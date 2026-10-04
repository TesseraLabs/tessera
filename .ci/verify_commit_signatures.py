#!/usr/bin/env python3
"""Require trusted developer signatures; admit proven SourceCraft server merges.

Use trust files from the protected base, never files supplied by a pull request.
SourceCraft CI reads authoritative merged-PR metadata with its built-in token.
GitHub CI uses a publication receipt committed by an approved publisher, so no
SourceCraft credentials or private signing keys are needed in GitHub Actions.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

SHA = re.compile(r"[0-9a-f]{40}\Z")
SLUG = re.compile(r"[a-zA-Z0-9_.-]+\Z")
API = "https://api.sourcecraft.tech"
MAX_RESPONSE = 8 * 1024 * 1024


class VerificationError(Exception):
    """An input, signature, or provenance check failed."""


def commit_sha(value: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise VerificationError("A full lowercase SHA-1 commit ID is required")
    return value


def git(repo: Path, *args: str, require_success: bool = True) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                                timeout=120, check=False)
    except subprocess.TimeoutExpired as error:
        raise VerificationError("Git verification timed out") from error
    if require_success and result.returncode:
        raise VerificationError("Git verification command failed: " + args[0])
    return result.stdout if result.returncode == 0 else b""


def signed(repo: Path, sha: str, signers: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "-c", "gpg.format=ssh", "-c",
         "gpg.ssh.allowedSignersFile=" + str(signers.resolve()), "verify-commit", sha],
        capture_output=True, timeout=120, check=False)
    return result.returncode == 0


def parent_ids(repo: Path, sha: str) -> list[str]:
    return git(repo, "show", "-s", "--format=%P", sha).decode().strip().split()


def introduced(repo: Path, base: str, head: str) -> list[str]:
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise VerificationError("Complete Git history is required")
    for sha in (base, head):
        git(repo, "cat-file", "-e", sha + "^{commit}")
    return git(repo, "rev-list", "--topo-order", base + ".." + head).decode().splitlines()


def server_merge_receipt(pr: dict, expected_repo: str) -> dict | None:
    """Only an authoritative main PR with a recognized non-rebase strategy qualifies."""
    if not isinstance(pr, dict) or pr.get("status") != "merged":
        return None
    repository = pr.get("repository", {})
    if not isinstance(repository, dict) or not isinstance(repository.get("organization"), dict):
        raise VerificationError("Invalid receipt repository metadata")
    org = repository["organization"]
    if not isinstance(org.get("slug"), str) or not isinstance(repository.get("slug"), str):
        raise VerificationError("Invalid receipt repository slug")
    if org["slug"] + "/" + repository["slug"] != expected_repo:
        raise VerificationError("Server merge receipt has a different repository")
    if pr.get("target_branch") != "main":
        return None
    info = pr.get("merge_info", {})
    parameters = info.get("merge_parameters", {})
    if parameters.get("rebase") is not False or parameters.get("squash") not in (False, True):
        return None
    receipt = {
        "commit": commit_sha(info.get("merge_commit_hash")),
        "target": commit_sha(info.get("target_commit_hash")),
        "source": commit_sha(pr.get("source", {}).get("sha")),
        "pr": str(pr.get("slug", "")),
    }
    if parameters["squash"]:
        receipt["strategy"] = "squash"
    return receipt


def prepare_squash_receipts(repo: Path, commits: list[str], signers: Path,
                            receipts: dict[str, dict], expected_repo: str, token: str) -> None:
    """Reverify original signed inputs, including after automatic branch deletion."""
    for sha in commits:
        receipt = receipts.get(sha, {})
        if receipt.get("strategy") != "squash":
            continue
        source, target = receipt["source"], receipt["target"]
        exists = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", source + "^{commit}"],
                                capture_output=True, timeout=120, check=False).returncode == 0
        if not exists:
            # Fetch only the API-recorded SHA from this fixed SourceCraft repository.
            # Token stays in child environment, never in argv, URLs or printed errors.
            env = dict(os.environ)
            env["GIT_CONFIG_COUNT"] = "3"
            env["GIT_CONFIG_KEY_0"] = "http.https://git.sourcecraft.dev/.extraHeader"
            basic = base64.b64encode(("git:" + token).encode()).decode()
            env["GIT_CONFIG_VALUE_0"] = "Authorization: Basic " + basic
            env["GIT_CONFIG_KEY_1"] = "http.followRedirects"
            env["GIT_CONFIG_VALUE_1"] = "false"
            env["GIT_CONFIG_KEY_2"] = "credential.helper"
            env["GIT_CONFIG_VALUE_2"] = ""
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_ASKPASS"] = "/usr/bin/false"
            env["SSH_ASKPASS"] = "/usr/bin/false"
            fetch = subprocess.run(["git", "-C", str(repo), "fetch", "--no-tags",
                                    "https://git.sourcecraft.dev/" + expected_repo + ".git", source],
                                   env=env, capture_output=True, timeout=120, check=False)
            if fetch.returncode:
                raise VerificationError("Cannot retrieve original squash input for audit")
        # Up-to-date source branches make the expected squash tree unambiguous.
        git(repo, "merge-base", "--is-ancestor", target, source)
        inputs = introduced(repo, target, source)
        if not inputs or any(not signed(repo, commit, signers) for commit in inputs):
            raise VerificationError("Squash inputs must contain only trusted signed developer commits")
        tree = commit_sha(git(repo, "show", "-s", "--format=%T", source).decode().strip())
        if git(repo, "show", "-s", "--format=%T", sha).decode().strip() != tree:
            raise VerificationError("Squash result differs from its verified source tree")
        receipt["tree"] = tree
        receipt["source_signatures_verified"] = True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise VerificationError("SourceCraft API redirects are not permitted")


def sourcecraft_json(path: str, token: str) -> dict:
    if not token:
        raise VerificationError("SourceCraft API token is required")
    request = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + token,
                                                          "Accept": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise VerificationError("SourceCraft response exceeds size limit")
        result = json.loads(payload)
    except (urllib.error.URLError, json.JSONDecodeError) as error:
        raise VerificationError("SourceCraft metadata request failed") from error
    if not isinstance(result, dict):
        raise VerificationError("Invalid SourceCraft metadata response")
    return result


def validate_pr_revision(expected_repo: str, token: str, slug: str, base: str, head: str) -> None:
    if not re.fullmatch(r"[1-9][0-9]*", slug or ""):
        raise VerificationError("A SourceCraft PR number is required")
    pr = sourcecraft_json("/repos/" + expected_repo + "/pulls/" + slug, token)
    repo = pr.get("repository", {})
    if repo.get("organization", {}).get("slug", "") + "/" + repo.get("slug", "") != expected_repo:
        raise VerificationError("SourceCraft PR repository mismatch")
    if pr.get("target_branch") != "main" or pr.get("status") not in ("open", "draft"):
        raise VerificationError("Signature CI must check an open PR into protected main")
    if pr.get("target", {}).get("sha") != base or pr.get("source", {}).get("sha") != head:
        raise VerificationError("Local CI revisions differ from authoritative PR revisions; rerun CI")


def validate_sourcecraft_main(expected_repo: str, token: str, head: str) -> None:
    """Publication export accepts only the current authoritative protected main."""
    pieces = expected_repo.split("/")
    if len(pieces) != 2 or any(not SLUG.fullmatch(p) or p in (".", "..") for p in pieces):
        raise VerificationError("Invalid SourceCraft repository")
    commit_sha(head)
    path = "/repos/" + expected_repo
    metadata = sourcecraft_json(path, token)
    org = metadata.get("organization", {})
    if (not isinstance(org, dict) or
            org.get("slug", "") + "/" + metadata.get("slug", "") != expected_repo or
            metadata.get("default_branch") != "main"):
        raise VerificationError("Publication requires the expected repository with default main")
    page_token, seen = "", set()
    for _ in range(1000):
        query = {"filter": "main", "page_size": "100"}
        if page_token:
            query["page_token"] = page_token
        data = sourcecraft_json(path + "/branches?" + urllib.parse.urlencode(query), token)
        if not isinstance(data.get("branches"), list):
            raise VerificationError("Invalid SourceCraft branch response")
        for branch in data["branches"]:
            if not isinstance(branch, dict):
                raise VerificationError("Invalid SourceCraft branch metadata")
            if branch.get("name") == "main":
                commit = branch.get("commit", {})
                if not isinstance(commit, dict) or commit_sha(commit.get("hash")) != head:
                    raise VerificationError("Publication head differs from current SourceCraft main")
                return
        page_token = data.get("next_page_token", "")
        if not page_token:
            break
        if not isinstance(page_token, str) or page_token in seen:
            raise VerificationError("Invalid SourceCraft pagination token")
        seen.add(page_token)
    raise VerificationError("Authoritative SourceCraft main was not found")


def sourcecraft_receipts(expected_repo: str, token: str) -> dict[str, dict]:
    if not token:
        raise VerificationError("SourceCraft API token is required for server provenance")
    pieces = expected_repo.split("/")
    if len(pieces) != 2 or any(not SLUG.fullmatch(p) or p in (".", "..") for p in pieces):
        raise VerificationError("Invalid SourceCraft repository")
    path = "/repos/" + "/".join(pieces) + "/pulls"
    opener = urllib.request.build_opener(NoRedirect())
    receipts = {}
    page_token = ""
    seen = set()
    for _ in range(1000):
        query = {"page_size": "100"}
        if page_token:
            query["page_token"] = page_token
        request = urllib.request.Request(API + path + "?" + urllib.parse.urlencode(query),
                                         headers={"Authorization": "Bearer " + token,
                                                  "Accept": "application/json"})
        try:
            with opener.open(request, timeout=30) as response:
                payload = response.read(MAX_RESPONSE + 1)
            if len(payload) > MAX_RESPONSE:
                raise VerificationError("SourceCraft response exceeds size limit")
            data = json.loads(payload)
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            # Response bodies/headers can contain credentials or sensitive metadata.
            raise VerificationError("SourceCraft provenance request failed") from error
        if not isinstance(data, dict) or not isinstance(data.get("pull_requests"), list):
            raise VerificationError("Unexpected SourceCraft PR-list response")
        for pr in data["pull_requests"]:
            receipt = server_merge_receipt(pr, expected_repo)
            if receipt:
                previous = receipts.get(receipt["commit"])
                if previous and previous != receipt:
                    raise VerificationError("Conflicting server merge receipts")
                receipts[receipt["commit"]] = receipt
        page_token = data.get("next_page_token", "")
        if not page_token:
            return receipts
        if not isinstance(page_token, str) or page_token in seen:
            raise VerificationError("Invalid SourceCraft pagination token")
        seen.add(page_token)
    raise VerificationError("SourceCraft provenance pagination limit exceeded")


def publication_receipts(repo: Path, base: str, head: str, path: str,
                         publisher_signers: Path, expected_repo: str) -> dict[str, dict]:
    if path.startswith("/") or ".." in Path(path).parts or "\0" in path:
        raise VerificationError("Invalid publication manifest path")
    commits = git(repo, "log", "--format=%H", base + ".." + head, "--", path).decode().splitlines()
    if not commits:
        raise VerificationError("A new signed publication manifest is required")
    owner = commits[0]
    if not signed(repo, owner, publisher_signers):
        raise VerificationError("Publication manifest is not signed by an approved publisher")
    payload = git(repo, "show", owner + ":" + path)
    if payload != git(repo, "show", head + ":" + path) or len(payload) > MAX_RESPONSE:
        raise VerificationError("Publication manifest changed after publisher attestation")
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as error:
        raise VerificationError("Invalid publication manifest JSON") from error
    if manifest.get("version") != 1 or manifest.get("repository") != expected_repo:
        raise VerificationError("Publication manifest repository/version mismatch")
    source_head = commit_sha(manifest.get("source_head"))
    git(repo, "merge-base", "--is-ancestor", source_head, head)
    records = manifest.get("server_merges")
    if not isinstance(records, list):
        raise VerificationError("Invalid server merge records")
    receipts = {}
    for receipt in records:
        if not isinstance(receipt, dict):
            raise VerificationError("Invalid server merge record")
        for field in ("commit", "source", "target"):
            commit_sha(receipt.get(field))
        strategy = receipt.get("strategy", "merge")
        if strategy == "squash":
            commit_sha(receipt.get("tree"))
            if receipt.get("source_signatures_verified") is not True:
                raise VerificationError("Publisher did not attest verified squash inputs")
        elif strategy != "merge":
            raise VerificationError("Unknown server merge strategy")
        git(repo, "merge-base", "--is-ancestor", receipt["commit"], source_head)
        if receipt["commit"] in receipts:
            raise VerificationError("Duplicate server merge record")
        receipts[receipt["commit"]] = receipt
    return receipts


def publication_owner(repo: Path, base: str, head: str, path: str,
                      developers: Path, publishers: Path) -> set[str]:
    """A separate publisher may sign only the exact source tree plus its receipt."""
    owners = git(repo, "log", "--format=%H", base + ".." + head, "--", path).decode().splitlines()
    if not owners:
        raise VerificationError("A publication owner is required")
    owner = commit_sha(owners[0])
    if not signed(repo, owner, publishers):
        raise VerificationError("Publication owner is not a trusted publisher")
    if signed(repo, owner, developers):
        return set()
    manifest = json.loads(git(repo, "show", owner + ":" + path))
    source = commit_sha(manifest.get("source_head"))
    if parent_ids(repo, owner) != [base, source]:
        raise VerificationError("Publisher-only commit must merge the exact source and GitHub base")
    changed = git(repo, "diff", "--name-only", source, owner).decode().splitlines()
    if changed != [path]:
        raise VerificationError("Publisher-only commit may change only its publication manifest")
    return {owner}


def verify(repo: Path, commits: list[str], signers: Path, receipts: dict[str, dict],
           publisher_commits: set[str] | None = None) -> dict:
    result = {"developer_signed": [], "sourcecraft_server_merges": [], "publisher_signed": []}
    for sha in commits:
        commit_sha(sha)
        if signed(repo, sha, signers):
            result["developer_signed"].append(sha)
            continue
        if sha in (publisher_commits or set()):
            result["publisher_signed"].append(sha)
            continue
        raw = git(repo, "cat-file", "commit", sha)
        # A bad/untrusted signature must not be treated as an unsigned server merge.
        headers = raw.split(b"\n\n", 1)[0]
        if any(line.startswith(b"gpgsig") for line in headers.splitlines()):
            raise VerificationError("Invalid or untrusted signature on " + sha)
        receipt = receipts.get(sha)
        if not receipt:
            raise VerificationError("Unsigned commit lacks matching SourceCraft server provenance: " + sha)
        strategy = receipt.get("strategy", "merge")
        if strategy == "squash":
            if (receipt.get("source_signatures_verified") is not True or
                    parent_ids(repo, sha) != [receipt["target"]] or
                    git(repo, "show", "-s", "--format=%T", sha).decode().strip() != receipt.get("tree")):
                raise VerificationError("Squash commit lacks exact parent/tree/input provenance: " + sha)
        elif strategy != "merge" or parent_ids(repo, sha) != [receipt["target"], receipt["source"]]:
            raise VerificationError("Unsigned commit lacks matching SourceCraft server provenance: " + sha)
        result["sourcecraft_server_merges"].append(sha)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-path", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--signers", type=Path, required=True)
    parser.add_argument("--sourcecraft-repo", required=True)
    parser.add_argument("--sourcecraft-pr")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sourcecraft-api", action="store_true")
    mode.add_argument("--sourcecraft-export-main", action="store_true")
    mode.add_argument("--publication-manifest")
    parser.add_argument("--publisher-signers", type=Path)
    parser.add_argument("--export-receipts", type=Path)
    args = parser.parse_args()
    try:
        if args.sourcecraft_export_main:
            if args.export_receipts is None or args.sourcecraft_pr is not None:
                raise VerificationError("Main export requires an output file and no PR parameter")
        elif args.export_receipts is not None:
            raise VerificationError("Receipt export requires the protected-main export mode")
        base, head = commit_sha(args.base), commit_sha(args.head)
        if not args.signers.is_file():
            raise VerificationError("Trusted signer file is missing")
        pieces = args.sourcecraft_repo.split("/")
        if len(pieces) != 2 or any(not SLUG.fullmatch(p) or p in (".", "..") for p in pieces):
            raise VerificationError("Invalid SourceCraft repository")
        commits = introduced(args.repo_path, base, head)
        publisher_commits = set()
        if args.sourcecraft_api:
            token = os.environ.get("SOURCECRAFT_TOKEN", "")
            validate_pr_revision(args.sourcecraft_repo, token, args.sourcecraft_pr, base, head)
            receipts = sourcecraft_receipts(args.sourcecraft_repo, token)
        elif args.sourcecraft_export_main:
            token = os.environ.get("SOURCECRAFT_TOKEN", "")
            validate_sourcecraft_main(args.sourcecraft_repo, token, head)
            receipts = sourcecraft_receipts(args.sourcecraft_repo, token)
        elif all(signed(args.repo_path, sha, args.signers) for sha in commits):
            receipts = {}
        else:
            if args.publisher_signers is None or not args.publisher_signers.is_file():
                raise VerificationError("Trusted publisher file is required")
            receipts = publication_receipts(args.repo_path, base, head, args.publication_manifest,
                                            args.publisher_signers, args.sourcecraft_repo)
            publisher_commits = publication_owner(args.repo_path, base, head, args.publication_manifest,
                                                  args.signers, args.publisher_signers)
        if args.sourcecraft_api or args.sourcecraft_export_main:
            prepare_squash_receipts(args.repo_path, commits, args.signers, receipts,
                                    args.sourcecraft_repo, token)
        result = verify(args.repo_path, commits, args.signers, receipts, publisher_commits)
        if args.export_receipts:
            # Do not attest an outdated selection if main changed during verification.
            validate_sourcecraft_main(args.sourcecraft_repo, token, head)
            manifest = {"version": 1, "repository": args.sourcecraft_repo, "source_head": head,
                        "server_merges": [receipts[sha] for sha in result["sourcecraft_server_merges"]]}
            with args.export_receipts.open("x") as output:
                output.write(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"verified": len(commits), "signed": len(result["developer_signed"]),
                          "sourcecraft_server_merges": len(result["sourcecraft_server_merges"])}))
        return 0
    except (VerificationError, subprocess.TimeoutExpired, OSError, TypeError, ValueError) as error:
        print("Signature check failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
