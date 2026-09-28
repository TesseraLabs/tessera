"""Exercise immutable installer refusal before any unverified binary execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/install-ci-security-tools.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)

class InstallerTests(unittest.TestCase):
    def archive(self, kind='file'):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            member = tarfile.TarInfo('release/cargo-audit'); data = b'fixture-binary'
            if kind == 'link': member.type = tarfile.SYMTYPE; member.linkname = '/wrong'
            else: member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        return stream.getvalue()

    def test_verified_archive_and_version_required(self):
        for mode in ['good', 'hash', 'link', 'version', 'network']:
            payload = self.archive('link' if mode == 'link' else 'file')
            entry = ('1.2.3', 'https://example.invalid/pinned', '0' * 64 if mode == 'hash' else hashlib.sha256(payload).hexdigest(), 'release/cargo-audit')
            with tempfile.TemporaryDirectory() as directory, patch.dict(installer.TOOLS, {'cargo-audit': entry}), \
                 patch.object(installer, 'urlopen', side_effect=OSError('unavailable') if mode == 'network' else None, return_value=io.BytesIO(payload)), \
                 patch.object(installer.subprocess, 'check_output', return_value='cargo-audit wrong' if mode == 'version' else 'cargo-audit 1.2.3') as execute:
                target = Path(directory)
                if mode == 'good':
                    installer.install('cargo-audit', target); self.assertTrue((target / 'cargo-audit').exists())
                else:
                    with self.assertRaises((ValueError, OSError)): installer.install('cargo-audit', target)
                    self.assertFalse((target / 'cargo-audit').exists())
                    if mode != 'version': execute.assert_not_called()

    def test_official_pins_and_workflow_context(self):
        import yaml
        self.assertEqual(installer.TOOLS['cargo-deny'][0], '0.20.2')
        self.assertEqual(installer.TOOLS['cargo-audit'][0], '0.22.2')
        for version, url, digest, member in installer.TOOLS.values():
            self.assertIn(version, url); self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertNotIn('/latest/', url)
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            for job in workflow.get('jobs', {}).values():
                self.assertNotIn('runner.', str(job.get('env', {})), path)
            if path.name in ['pr-checks.yml', 'open-core-compat.yml']:
                source = path.read_text()
                self.assertIn('install-ci-security-tools.py', source)
                self.assertNotIn('cargo install', source)
                self.assertIn('cargo audit', source)

if __name__ == '__main__': unittest.main()
