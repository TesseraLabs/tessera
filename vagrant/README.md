# vagrant — E2E test rig

One box lives in `Vagrantfile`:

| Box       | Purpose                                                                           |
|-----------|-----------------------------------------------------------------------------------|
| `default` | Ubuntu 22.04 Astra-proxy with the full build toolchain. Used for stage-1 / stage-2 smoke fixtures and PKCS#12 flows. Provisioned by `provision.sh`. |

```sh
vagrant up default
vagrant ssh default
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/test-mac.sh`  | MAC-integrity runtime checks (parsec enforcement) — manual runbook. |
| `scripts/bench-mac.sh` | MAC label-application latency micro-bench. |

Real-hardware flows (USB media, PKCS#11 tokens, fly-dm) are not covered
here — see `tests/scripts/install-and-test.sh` for the manual runbook on
an Astra host.

## CI

These scripts are **manual** — `vagrant up` is too expensive to run on
every PR. There is no GitHub Actions workflow that spins up the box. If
you want to wire one, gate it behind `workflow_dispatch` or a
`schedule:` cron and provision a self-hosted runner with VirtualBox +
Vagrant.
