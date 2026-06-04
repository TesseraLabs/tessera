#!/usr/bin/env bash
# Vagrant provisioning for the Ubuntu 22.04 proxy of Astra SE 1.7.
# Installs every runtime dependency declared in debian/control plus the
# build-host toolchain so `scripts/build-deb.sh` works inside the VM.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    libssl3 \
    libpam0g \
    libudev1 \
    libdbus-1-3 \
    libsystemd0 \
    gost-engine \
    pamtester \
    libpam0g-dev \
    build-essential

# Build-host toolchain so the VM can also act as a build host.
apt-get install -y \
    debhelper \
    dh-cargo \
    cargo \
    rustc \
    libssl-dev \
    libudev-dev \
    libdbus-1-dev \
    libsystemd-dev \
    pkg-config \
    lintian \
    devscripts \
    fakeroot \
    git

# Set up fixtures placeholder for the test operator.
sudo -u vagrant mkdir -p /home/vagrant/tessera-fixtures
cat > /home/vagrant/tessera-fixtures/README.txt <<'EOF'
Drop the following files here before running install-and-test.sh:
  ca.pem            (test CA bundle)
  config.toml       (filled-in tessera config; mountpoint /run/tessera/usb)
  host_acl.toml     (test host ACL)
  host_acl.toml.sig (detached signature for host_acl.toml)
  alice.p12         (test PKCS#12 for user alice; passphrase 'alice')
EOF
chown vagrant:vagrant /home/vagrant/tessera-fixtures/README.txt

echo "provisioning complete"
