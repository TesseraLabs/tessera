# vagrant — E2E test rigs

Two boxes live in `Vagrantfile`:

| Box       | Purpose                                                                           |
|-----------|-----------------------------------------------------------------------------------|
| `default` | Ubuntu 22.04 Astra-proxy with the full build toolchain. Used for stage-1 / stage-2 smoke fixtures and PKCS#12 flows. Provisioned by `provision.sh`. |
| `mof-n`   | Phase 13 M-of-N E2E scenario. Runtime-only deps, installs the `.deb` from `/srv/source/target/release/`, and runs `scripts/setup-mof-n-scenario.sh`. |

## Prerequisites for `mof-n`

Build the `.deb` on the host first:

```sh
scripts/build-deb.sh
ls target/release/tessera_*.deb
```

Then boot the box:

```sh
vagrant up mof-n
vagrant ssh mof-n
```

Inside the VM:

```sh
sudo /vagrant/scripts/test-happy.sh      # Phase 13.2 — exit 0 expected
sudo /vagrant/scripts/test-negative.sh   # Phase 13.3 — five denial cases
sudo /vagrant/scripts/test-gost.sh       # Phase 13.4 — exit 0 or 77 (skip)
```

`test-gost.sh` exits 77 (autotools-style "skip") if `gost-engine` is not
installed or if openssl-rust cannot verify the GOST CMS bundle. The latter
is the documented openssl-rust gap; see
`docs/migration.md` for the tracking entry.

## CI

These scripts are **manual / nightly** for now — `vagrant up` is too
expensive to run on every PR. There is no GitHub Actions workflow that
spins up the box. If you want to wire one, gate it behind
`workflow_dispatch` or a `schedule:` cron and provision a self-hosted
runner with VirtualBox + Vagrant.
