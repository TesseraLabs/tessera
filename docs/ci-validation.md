# CI validation

Pull requests run a bounded smoke gate. Complete platform, feature, SDK, package and release validation remains available through explicit manual workflows; release tag workflows remain explicit release operations. A smoke result is not a claim of full platform conformance.

The public minimal job runs on the standard GitHub-hosted `ubuntu-22.04` runner and requires no access to the private build runner group. Its existing preparation helper installs the native OpenSSL/udev development packages and pkg-config needed by the selected core targets. Fixture tests use `/usr/bin/python3` so the apt-installed `python3-yaml` is available even when the hosted toolcache Python precedes it on PATH. No deployment or private-repository credentials are passed to this job.

The full `release-issuer` Linux/macOS/Windows build runs only by manual dispatch or an explicit `v*` release tag. Its tag selection, build matrix and draft-release publication remain unchanged.

The public smoke checks formatting and executes five nonempty Rust targets with no ignored tests: Codes contract library, hash-chain integration, role catalogue, client-auth certificate TBS, and work-authorisation v2. CI also retains dependency policy/advisory checks. Run `bash scripts/check-pr-smoke.sh` locally. Script failure fixtures run with `python3 scripts/run-ci-tests.py scripts/tests test_pr_ci.py`.

The required `enterprise exact-SHA compatibility` job remains an actual private-consumer check. The hosted metadata-only bridge dispatches the full core SHA and resolved private-consumer SHA, then checks the exact request/source tuple and successful conclusion. It never checks out private source or reads private logs or artifacts. Private compilation and caches remain in the private repository. Fork requests do not run the secret-bearing bridge or produce the required named job; review and a successful result at the final full SHA remain necessary.

The private workflow must land before this bridge revision. The new bridge has no fallback to a legacy request-only run title. CLA and metadata notification workflows retain their existing behavior. Hosted capacity is not guaranteed by this configuration; a capacity failure is not a successful check.

Security tools are pinned official Linux x86_64 musl release binaries: cargo-deny 0.20.2 and cargo-audit 0.22.2. The installer verifies the committed SHA256 before extracting the single regular-file binary and checking its version. Download, digest or version failure blocks the job; no source-build/latest fallback is used. Existing deny/advisory policy is unchanged.
