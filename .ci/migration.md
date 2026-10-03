# SourceCraft core CI

Main PRs require trusted signatures, public smoke/workflow/security tests and the
private Enterprise exact-SHA compatibility workflow. The private backend executes
only protected private main and exports a minimal source-bound result; private code,
logs, diagnostic artifacts and signing keys are never copied into the public job.
Normal trust/client code is extracted from the protected public base. The first
bootstrap uses reviewed frozen verifier/key/client/helper digests and all3 cloud
gates before installation. Compilation runs without the SourceCraft bearer token.

Main remains PR-only with independent review, no force-push and no deletion. Our
operator uses squash=true, rebase=false, delete_branch=true after exact green CI and
independent review. Full native/package/nightly/release workflows remain staged on
GitHub during development cutover. Selected public GitHub publication is separate
from the deferred external contributor PR bridge.

All three bootstrap gates passed, including protected Enterprise shared CI.
This ordinary PR verifies the installed automatic mandatory workflows.
