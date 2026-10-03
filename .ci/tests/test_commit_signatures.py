"""Security-focused tests; synthetic metadata only, no commits or credentials."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("signatures", Path(__file__).parents[1] / "verify_commit_signatures.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
COMMIT, TARGET, SOURCE = "a" * 40, "b" * 40, "c" * 40
REPO = "tessera-labs/example"


def pr():
    return {"status": "merged", "target_branch": "main", "slug": "1", "repository": {"slug": "example", "organization": {"slug": "tessera-labs"}},
            "source": {"sha": SOURCE}, "merge_info": {"merge_parameters": {"rebase": False, "squash": False},
            "merge_commit_hash": COMMIT, "target_commit_hash": TARGET}}


class SignaturesTests(unittest.TestCase):
    def test_signed_developer_commit_needs_no_exception(self):
        with patch.object(V, "signed", return_value=True):
            result = V.verify(Path("."), [COMMIT], Path("keys"), {})
        self.assertEqual(result["developer_signed"], [COMMIT])

    def test_unsigned_merge_name_and_shape_are_not_provenance(self):
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", return_value=b"committer SourceCraft\n\nmessage"):
            with self.assertRaisesRegex(V.VerificationError, "provenance"):
                V.verify(Path("."), [COMMIT], Path("keys"), {})

    def test_authoritative_ordinary_merge_is_accepted(self):
        receipt = V.server_merge_receipt(pr(), REPO)
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", return_value=b"tree x\n\nmessage"), patch.object(V, "parent_ids", return_value=[TARGET, SOURCE]):
            result = V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT: receipt})
        self.assertEqual(result["sourcecraft_server_merges"], [COMMIT])

    def test_parent_mismatch_rejects_receipt(self):
        receipt = V.server_merge_receipt(pr(), REPO)
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", return_value=b"tree x\n\nmessage"), patch.object(V, "parent_ids", return_value=[SOURCE, TARGET]):
            with self.assertRaises(V.VerificationError):
                V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT: receipt})

    def test_invalid_signature_cannot_use_merge_exception(self):
        receipt = V.server_merge_receipt(pr(), REPO)
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", return_value=b"tree x\ngpgsig bad-signature\n\nmessage"):
            with self.assertRaisesRegex(V.VerificationError, "untrusted signature"):
                V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT: receipt})

    def test_other_repository_is_rejected(self):
        with self.assertRaises(V.VerificationError):
            V.server_merge_receipt(pr(), "tessera-labs/other")

    def test_unmerged_pr_cannot_authorize_unsigned_commit(self):
        record = pr();record["status"] = "open"
        self.assertIsNone(V.server_merge_receipt(record, REPO))

    def test_rebase_is_not_a_server_exception(self):
        record = pr();record["merge_info"]["merge_parameters"]["rebase"] = True
        self.assertIsNone(V.server_merge_receipt(record, REPO))

    def test_squash_is_explicit_and_requires_verified_inputs(self):
        record = pr();record["merge_info"]["merge_parameters"]["squash"] = True
        receipt = V.server_merge_receipt(record, REPO)
        self.assertEqual(receipt["strategy"], "squash")
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", return_value=b"tree x\n\nmessage"):
            with self.assertRaisesRegex(V.VerificationError, "input provenance"):
                V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT: receipt})

    def test_verified_squash_requires_one_exact_parent_and_tree(self):
        receipt = {"commit": COMMIT, "source": SOURCE, "target": TARGET,
                   "strategy": "squash", "source_signatures_verified": True, "tree": "d"*40}
        def fake_git(repo, *args, **kwargs):
            return b"tree x\n\nmessage" if args[0] == "cat-file" else (receipt["tree"]+"\n").encode()
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", side_effect=fake_git), \
             patch.object(V, "parent_ids", return_value=[TARGET]):
            self.assertEqual(V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT:receipt})["sourcecraft_server_merges"], [COMMIT])
        with patch.object(V, "signed", return_value=False), patch.object(V, "git", side_effect=fake_git), \
             patch.object(V, "parent_ids", return_value=[TARGET, SOURCE]):
            with self.assertRaises(V.VerificationError):V.verify(Path("."), [COMMIT], Path("keys"), {COMMIT:receipt})

    def test_squash_tree_mismatch_is_rejected(self):
        receipt = {"commit":COMMIT,"source":SOURCE,"target":TARGET,"strategy":"squash", "source_signatures_verified":True,"tree":"d"*40}
        with patch.object(V,"signed",return_value=False), patch.object(V,"git",return_value=b"tree x\n\nmessage"), patch.object(V,"parent_ids",return_value=[TARGET]):
            with self.assertRaises(V.VerificationError):V.verify(Path("."),[COMMIT],Path("keys"),{COMMIT:receipt})

    def test_squash_audit_rejects_unsigned_original_inputs(self):
        import subprocess
        receipt={"commit":COMMIT,"source":SOURCE,"target":TARGET,"strategy":"squash"}
        with patch.object(V.subprocess,"run",return_value=subprocess.CompletedProcess([],0)), \
             patch.object(V,"git",return_value=b""), patch.object(V,"introduced",return_value=[SOURCE]), patch.object(V,"signed",return_value=False):
            with self.assertRaisesRegex(V.VerificationError,"trusted signed developer"):
                V.prepare_squash_receipts(Path("."),[COMMIT],Path("keys"),{COMMIT:receipt},REPO,"synthetic")

    def test_squash_audit_marks_only_matching_signed_source_tree(self):
        import subprocess
        receipt={"commit":COMMIT,"source":SOURCE,"target":TARGET,"strategy":"squash"}
        tree="d"*40
        def fake_git(repo,*args,**kwargs): return (tree+"\n").encode() if args[0]=='show' else b""
        with patch.object(V.subprocess,"run",return_value=subprocess.CompletedProcess([],0)), \
             patch.object(V,"git",side_effect=fake_git), patch.object(V,"introduced",return_value=[SOURCE]), patch.object(V,"signed",return_value=True):
            V.prepare_squash_receipts(Path("."),[COMMIT],Path("keys"),{COMMIT:receipt},REPO,"synthetic")
        self.assertTrue(receipt['source_signatures_verified']); self.assertEqual(receipt['tree'],tree)

    def test_non_main_server_merge_is_not_an_exception(self):
        record = pr();record["target_branch"] = "feature/unprotected"
        self.assertIsNone(V.server_merge_receipt(record, REPO))

    def test_shallow_git_history_is_rejected(self):
        with patch.object(V, "git", return_value=b"true\n"):
            with self.assertRaisesRegex(V.VerificationError, "Complete Git history"):
                V.introduced(Path("."), TARGET, COMMIT)

    def test_stale_pr_revisions_are_rejected(self):
        record = pr();record["status"] = "open";record["target"] = {"sha": TARGET}
        with patch.object(V, "sourcecraft_json", return_value=record):
            with self.assertRaisesRegex(V.VerificationError, "revisions differ"):
                V.validate_pr_revision(REPO, "synthetic", "1", "d" * 40, SOURCE)

    def test_authoritative_pr_revisions_are_accepted(self):
        record = pr();record["status"] = "open";record["target"] = {"sha": TARGET}
        with patch.object(V, "sourcecraft_json", return_value=record):
            V.validate_pr_revision(REPO, "synthetic", "1", TARGET, SOURCE)

    def test_publication_requires_exact_authoritative_main(self):
        repo = {"slug": "example", "organization": {"slug": "tessera-labs"}, "default_branch": "main"}
        page = {"branches": [{"name": "feature/main", "commit": {"hash": SOURCE}},
                             {"name": "main", "commit": {"hash": COMMIT}}]}
        with patch.object(V, "sourcecraft_json", side_effect=[repo, page]):
            V.validate_sourcecraft_main(REPO, "synthetic", COMMIT)
        with patch.object(V, "sourcecraft_json", side_effect=[repo, page]):
            with self.assertRaisesRegex(V.VerificationError, "differs"):
                V.validate_sourcecraft_main(REPO, "synthetic", SOURCE)

    def test_publication_rejects_wrong_repository_or_default_branch(self):
        for repo in [{"slug": "other", "organization": {"slug": "tessera-labs"}, "default_branch": "main"},
                     {"slug": "example", "organization": {"slug": "tessera-labs"}, "default_branch": "dev"}]:
            with patch.object(V, "sourcecraft_json", return_value=repo):
                with self.assertRaises(V.VerificationError):
                    V.validate_sourcecraft_main(REPO, "synthetic", COMMIT)

    def test_publication_does_not_accept_a_main_substring_branch(self):
        repo = {"slug": "example", "organization": {"slug": "tessera-labs"}, "default_branch": "main"}
        with patch.object(V, "sourcecraft_json", side_effect=[repo, {"branches": [{"name": "feature/main", "commit": {"hash": COMMIT}}]}]):
            with self.assertRaisesRegex(V.VerificationError, "not found"):
                V.validate_sourcecraft_main(REPO, "synthetic", COMMIT)

    def test_publication_follows_pages_and_rejects_repeated_page_tokens(self):
        repo = {"slug": "example", "organization": {"slug": "tessera-labs"}, "default_branch": "main"}
        first = {"branches": [], "next_page_token": "next"}
        last = {"branches": [{"name": "main", "commit": {"hash": COMMIT}}]}
        with patch.object(V, "sourcecraft_json", side_effect=[repo, first, last]):
            V.validate_sourcecraft_main(REPO, "synthetic", COMMIT)
        with patch.object(V, "sourcecraft_json", side_effect=[repo, first, first]):
            with self.assertRaisesRegex(V.VerificationError, "pagination"):
                V.validate_sourcecraft_main(REPO, "synthetic", COMMIT)

    def test_publication_export_rechecks_main_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); keys = root / "keys"; keys.touch(); output = root / "receipt.json"
            args = ["verify", "--base", TARGET, "--head", COMMIT, "--signers", str(keys),
                    "--sourcecraft-repo", REPO, "--sourcecraft-export-main", "--export-receipts", str(output)]
            result = {"developer_signed": [COMMIT], "sourcecraft_server_merges": []}
            with patch("sys.argv", args), patch.object(V, "introduced", return_value=[COMMIT]), \
                 patch.object(V, "validate_sourcecraft_main") as validate, \
                 patch.object(V, "sourcecraft_receipts", return_value={}), patch.object(V, "verify", return_value=result):
                self.assertEqual(V.main(), 0)
                self.assertEqual(validate.call_count, 2)
                self.assertEqual(json.loads(output.read_text())["source_head"], COMMIT)
                self.assertEqual(V.main(), 1)

    def test_main_change_during_publication_does_not_write_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); keys = root / "keys"; keys.touch(); output = root / "receipt.json"
            args = ["verify", "--base", TARGET, "--head", COMMIT, "--signers", str(keys),
                    "--sourcecraft-repo", REPO, "--sourcecraft-export-main", "--export-receipts", str(output)]
            with patch("sys.argv", args), patch.object(V, "introduced", return_value=[COMMIT]), \
                 patch.object(V, "validate_sourcecraft_main", side_effect=[None, V.VerificationError("main moved")]), \
                 patch.object(V, "sourcecraft_receipts", return_value={}), \
                 patch.object(V, "verify", return_value={"developer_signed": [COMMIT], "sourcecraft_server_merges": []}):
                self.assertEqual(V.main(), 1)
                self.assertFalse(output.exists())

    def test_pr_mode_cannot_bypass_revision_binding_by_requesting_export(self):
        args = ["verify", "--base", TARGET, "--head", COMMIT, "--signers", "keys", "--sourcecraft-repo", REPO,
                "--sourcecraft-api", "--export-receipts", "receipt.json"]
        with patch("sys.argv", args), patch.object(V, "validate_pr_revision") as validate:
            self.assertEqual(V.main(), 1)
            validate.assert_not_called()

    def test_short_sha_is_rejected(self):
        with self.assertRaises(V.VerificationError):V.commit_sha("abc123")

    def test_missing_api_token_fails_closed(self):
        with self.assertRaises(V.VerificationError):V.sourcecraft_receipts(REPO, "")

    def test_api_path_traversal_is_rejected(self):
        with self.assertRaises(V.VerificationError):V.sourcecraft_receipts("../example", "synthetic")

    def test_redirect_cannot_forward_authorization(self):
        with self.assertRaises(V.VerificationError):V.NoRedirect().redirect_request(None, None, 302, "", {}, "https://untrusted.invalid")

    def test_publication_manifest_traversal_is_rejected(self):
        with self.assertRaises(V.VerificationError):
            V.publication_receipts(Path("."), TARGET, COMMIT, "../receipt", Path("keys"), REPO)

    def test_signed_publication_is_bound_to_blob_and_ancestry(self):
        import json
        record = {"commit": COMMIT, "target": TARGET, "source": SOURCE, "pr": "1"}
        payload = json.dumps({"version": 1, "repository": REPO, "source_head": COMMIT, "server_merges": [record]}).encode()
        calls = []
        def fake_git(repo, *args, **kwargs):
            calls.append(args)
            if args[0] == "log":return (SOURCE + "\n").encode()
            if args[0] == "show":return payload
            return b""
        with patch.object(V, "git", side_effect=fake_git), patch.object(V, "signed", return_value=True):
            receipts = V.publication_receipts(Path("."), TARGET, SOURCE, "receipt.json", Path("keys"), REPO)
        self.assertEqual(receipts[COMMIT], record)
        self.assertIn(("merge-base", "--is-ancestor", COMMIT, SOURCE), calls)

    def test_changed_receipt_after_publisher_commit_is_rejected(self):
        def fake_git(repo, *args, **kwargs):
            if args[0] == "log":return (SOURCE + "\n").encode()
            if args[1].startswith(SOURCE):return b"trusted"
            return b"changed"
        with patch.object(V, "git", side_effect=fake_git), patch.object(V, "signed", return_value=True):
            with self.assertRaisesRegex(V.VerificationError, "changed after"):
                V.publication_receipts(Path("."), TARGET, COMMIT, "receipt.json", Path("keys"), REPO)

    def test_untrusted_publisher_is_rejected(self):
        with patch.object(V, "git", return_value=(COMMIT+"\n").encode()), patch.object(V, "signed", return_value=False):
            with self.assertRaisesRegex(V.VerificationError, "approved publisher"):
                V.publication_receipts(Path("."), TARGET, COMMIT, "receipt.json", Path("keys"), REPO)


if __name__ == "__main__":unittest.main()
