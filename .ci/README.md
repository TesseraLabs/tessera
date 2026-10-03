# Developer signatures and SourceCraft server merge provenance

Developer commits, including locally-created merge commits, require a trusted
SSH signature. The owner-approved exception covers authoritative ordinary server merges and
requested squash merges into protected SourceCraft `main`. Rebase results are not covered.

An unsigned ordinary merge requires authenticated SourceCraft PR metadata
reporting `merged`, the expected repository/main, the exact commit ID and both
exact ordered parents. A squash requires the explicit squash strategy, one exact
target parent and a tree identical to the original signed source. Its branch must
contain the target revision; the verifier rechecks every original input signature.
After source-branch deletion it fetches only the immutable API-recorded source SHA
from the fixed SourceCraft repository with redirects disabled. Unavailable inputs
fail closed. GitHub receives only publisher-signed attestations of these checks. A commit message, identity string or parent shape alone is insufficient. Bad/untrusted signatures fail.

Verification code and allowed keys must be extracted from the protected base,
not the PR checkout. The check rejects shallow history and compares local base
and head with current authoritative PR metadata. A stale check must be rerun.

SourceCraft CI uses its built-in `SOURCECRAFT_TOKEN` for GET metadata only.
PR-triggered workflows `signatures` and `pr-checks` are both merge checks; the
SourceCraft pilot confirmed that an ordinary merge is rejected when a configured
PR workflow fails. The new Control checks must pass live positive/negative tests
before the old GitHub `required_signatures` rule is replaced.

GitHub verification does not receive SourceCraft credentials. Publication must
include `.ci/sourcecraft-publication.json` added by a commit signed by a trusted
publisher. It attests the SourceCraft repository/head and validated server-merge
receipts. The checker binds receipts to this signature, Git ancestry and exact
parents. Normal PRs containing only signed developer commits need no receipt.
The publisher runs locally with the existing signing agent; no private signing
key is uploaded to either CI. Unsigned input is rejected before exporting receipts.

The manual `publication-proof` workflow exports receipts only for the current
authoritative SourceCraft `main`. Its `GITHUB_BASE` input is the full existing
GitHub base commit; PR verification keeps its separate strict base/head binding.
Export checks the repository, exact `main` ref and head both before and after
verification, follows bounded pagination, and refuses to overwrite an output.
It produces unsigned metadata, not publication authorization. Run this workflow
with both checkout and configuration fixed to the reviewed SourceCraft main SHA;
the local trusted publisher must validate and sign the receipt before GitHub use.
No images, tags, GitHub branches or releases are published by the proof workflow.

Signer and publisher key files are separate trust lists even when the initial
maintainer is the same. Change them only through protected reviewed PRs. Do not
mount deploy, registry, Kubernetes, production or private signing credentials in
the build/test workflows. The temporary PostgreSQL password is synthetic test data.

This is CI migration only. GitHub `origin` and deployment remain unchanged until
the separate cutover checks complete. Initial configuration installation is a
signed, independently-reviewed bootstrap PR; it cannot yet run a workflow whose
trusted base files do not exist until that PR is merged. Validate signatures and
configuration locally first, then test the installed checks in follow-up PRs.
