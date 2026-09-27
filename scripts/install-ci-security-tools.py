#!/usr/bin/env python3
"""Install pinned official Linux tools after verifying each archive's reviewed SHA256."""
import hashlib
import io
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
from urllib.request import urlopen

# Official GitHub release asset digests checked 2026-09-28; no latest fallback.
TOOLS = {
    'cargo-deny': ('0.20.2', 'https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz',
                   '9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f', 'cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny'),
    'cargo-audit': ('0.22.2', 'https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-x86_64-unknown-linux-musl-v0.22.2.tgz',
                    '7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428', 'cargo-audit-x86_64-unknown-linux-musl-v0.22.2/cargo-audit'),
}
MAX_ARCHIVE = 64 * 1024 * 1024

def install(name, destination):
    version, url, digest, member_name = TOOLS[name]
    with urlopen(url, timeout=60) as response:
        archive = response.read(MAX_ARCHIVE + 1)
    if len(archive) > MAX_ARCHIVE or hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError('security-tool archive size or SHA256 mismatch')
    # Never extract arbitrary archive paths, links or other release contents.
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        matches = [member for member in bundle if member.name == member_name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > MAX_ARCHIVE:
            raise ValueError('unexpected security-tool archive member')
        source = bundle.extractfile(matches[0])
        if source is None:
            raise ValueError('missing security-tool binary')
        data = source.read(MAX_ARCHIVE + 1)
    destination.mkdir(parents=True, exist_ok=True)
    binary = destination / name
    # Remove a stale binary before writing; no PATH publication until verified.
    binary.unlink(missing_ok=True)
    binary.write_bytes(data)
    binary.chmod(0o700)
    try:
        actual = subprocess.check_output([str(binary), '--version'], text=True, timeout=10).strip()
        if actual != f'{name} {version}':
            raise ValueError('security-tool version mismatch')
    except Exception:
        binary.unlink(missing_ok=True)
        raise
    print(f'Installed {name} {version} (verified release SHA256).')

def main(names):
    if not names or any(name not in TOOLS for name in names) or len(set(names)) != len(names):
        raise ValueError('select cargo-deny and/or cargo-audit')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('pinned security tools require Linux x86_64')
    destination = Path(os.environ['RUNNER_TEMP']) / 'tessera-ci-security-tools'
    for name in names:
        install(name, destination)
    with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as output:
        output.write(str(destination) + '\n')

if __name__ == '__main__':
    main(sys.argv[1:])
