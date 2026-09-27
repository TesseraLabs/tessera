"""CI policy and executable failure guards; these tests never run Cargo or GitHub."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
class UniqueLoader(yaml.BaseLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f'duplicate YAML key: {key}')
            result[key] = self.construct_object(value_node, deep=deep)
        return result

def workflow(name):
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=UniqueLoader)

class PolicyTests(unittest.TestCase):
    def test_full_checks_are_manual_and_explicit_release_only(self):
        for name in ['lint.yml', 'issuer.yml', 'nightly.yml', 'build-builder-image.yml']:
            self.assertEqual(set(workflow(name)['on']), {'workflow_dispatch'}, name)
        self.assertEqual(set(workflow('build.yml')['on']), {'workflow_dispatch', 'push'})
        self.assertEqual(workflow('build.yml')['on']['push'], {'tags': ['v*']})
        self.assertEqual(workflow('windows.yml')['on']['push'], {'tags': ['v*']})
        self.assertIn('cargo clippy --workspace --all-targets --all-features', (ROOT / '.github/workflows/lint.yml').read_text())

    def test_bridge_is_metadata_only_and_never_occupies_private_worker(self):
        w = workflow('enterprise-compat.yml'); job = w['jobs']['exact-sha']
        same = 'github.event.pull_request.head.repo.full_name == github.repository'
        self.assertEqual(job['runs-on'], 'ubuntu-22.04')
        self.assertIn(same, job['if']); self.assertIn('draft == false', job['if'])
        self.assertEqual(job['name'], "${{ " + same + " && 'enterprise exact-SHA compatibility' || 'enterprise compatibility unavailable to forks' }}")
        self.assertNotIn('checkout', str(job)); self.assertNotIn('docker', str(job).lower())
        self.assertNotIn('packages', w['permissions'])
        self.assertEqual(job['steps'][0]['name'], 'Validate trusted PR source')
        token = job['steps'][1]
        self.assertEqual(token['with']['repositories'], 'tessera-enterprise')
        self.assertEqual(token['with']['permission-actions'], 'read')
        self.assertEqual(token['with']['permission-contents'], 'write')
        self.assertIn('ready_for_review', w['on']['pull_request']['types'])

    def test_foreign_origin_or_malformed_sha_refuses_before_token_action(self):
        guard = workflow('enterprise-compat.yml')['jobs']['exact-sha']['steps'][0]['run']
        for origin, sha, expected in [('TesseraLabs/tessera', 'a' * 40, 0), ('outsider/fork', 'a' * 40, 1),
                                      ('TesseraLabs/tessera', 'main', 1), ('TesseraLabs/tessera', 'A' * 40, 1)]:
            result = subprocess.run(['bash', '-c', guard], env={**os.environ, 'HEAD_REPOSITORY': origin,
                'OPEN_REPOSITORY': 'TesseraLabs/tessera', 'OPEN_CORE_SHA': sha}, capture_output=True)
            self.assertEqual(result.returncode, expected)
        # The exact YAML conditional above gives a skipped foreign job a different name:
        # no required context exists for it, rather than a skipped required-context success.

    def test_cla_remains_metadata_only_with_existing_contributor_action(self):
        w = workflow('cla.yml')
        self.assertEqual(set(w['on']), {'pull_request_target', 'issue_comment'})
        steps = w['jobs']['cla']['steps']; self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['uses'], 'contributor-assistant/github-action@ca4a40a7d1004f18d9960b404b97e5f30a505a08')
        self.assertEqual(steps[0]['with']['remote-repository-name'], 'cla-signatures')
        self.assertNotIn('checkout', str(w)); self.assertNotIn('cargo', str(w))

class SmokeTests(unittest.TestCase):
    def run_smoke(self, mode):
        with tempfile.TemporaryDirectory(prefix='core-smoke-fixture-') as directory:
            root = Path(directory); bin_dir = root / 'bin'; bin_dir.mkdir()
            fake = bin_dir / 'cargo'
            fake.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$FIXTURE_CALLS"
[ "$1" = fmt ] && exit 0
[ "$FIXTURE_MODE" = failure ] && exit 7
case "$FIXTURE_MODE" in
 zero) echo 'test result: ok. 0 passed; 0 failed; 0 ignored;' ;;
 ignored) echo 'test result: ok. 1 passed; 0 failed; 1 ignored;' ;;
 *) echo 'test result: ok. 1 passed; 0 failed; 0 ignored;' ;;
esac
'''); fake.chmod(0o700)
            result = subprocess.run(['bash', str(ROOT / 'scripts/check-pr-smoke.sh')], env={**os.environ,
                'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'], 'FIXTURE_CALLS': str(root / 'calls'),
                'FIXTURE_MODE': mode, 'TESSERA_SMOKE_REPORT': str(root / 'report')}, capture_output=True, text=True)
            return result.returncode, (root / 'calls').read_text(), result.stdout

    def test_actual_nonempty_targets_are_required(self):
        code, calls, output = self.run_smoke('ok')
        self.assertEqual(code, 0); self.assertEqual(calls.count('test --locked'), 5)
        self.assertIn('5/5 targets', output)

    def test_zero_ignored_and_failed_targets_cannot_pass(self):
        for mode in ['zero', 'ignored', 'failure']:
            code, calls, output = self.run_smoke(mode)
            self.assertNotEqual(code, 0, mode); self.assertEqual(calls.count('test --locked'), 1)
            self.assertNotIn('5/5 targets', output)


class BridgeResultTests(unittest.TestCase):
    def test_only_matching_successful_private_run_can_finish_gate(self):
        import json
        guard = workflow('enterprise-compat.yml')['jobs']['exact-sha']['steps'][-1]['run']
        for mode in ['success', 'failure', 'cancelled', 'timeout', 'wrong-head', 'wrong-request', 'wrong-core', 'duplicate']:
            with tempfile.TemporaryDirectory(prefix='bridge-fixture-') as directory:
                root = Path(directory); bin_dir = root / 'bin'; bin_dir.mkdir()
                run = {'id': 17, 'head_sha': 'b' * 40, 'display_title': 'open-core compatibility 8-1 ' + 'a' * 40 + ' ' + 'b' * 40,
                       'event': 'repository_dispatch', 'conclusion': 'success', 'status': 'completed', 'workflow_id': 23,
                       'annotations': [{'message': 'PRIVATE-COMPILER-DIAGNOSTIC'}]}
                if mode in ['failure', 'cancelled']: run['conclusion'] = mode
                if mode == 'timeout': run['status'] = 'in_progress'; run['conclusion'] = None
                if mode == 'wrong-head': run['head_sha'] = 'c' * 40
                if mode == 'wrong-core': run['display_title'] = 'open-core compatibility 8-1 ' + 'c' * 40 + ' ' + 'b' * 40
                if mode == 'wrong-request': run['display_title'] = 'open-core compatibility 7-1 ' + 'a' * 40 + ' ' + 'b' * 40
                (root / 'runs.json').write_text(json.dumps({'workflow_runs': [run, run] if mode == 'duplicate' else [run]}))
                (root / 'run.json').write_text(json.dumps(run))
                gh = bin_dir / 'gh'; gh.write_text('''#!/bin/sh
if [ "$1" = api ]; then
 case "$2" in */runs/17) /bin/cat "$FIXTURE_DIR/run.json" ;; *) /bin/cat "$FIXTURE_DIR/runs.json" ;; esac
else
 [ "$FIXTURE_MODE" = failure ] && exit 1
 [ "$FIXTURE_MODE" = cancelled ] && exit 1
 exit 0
fi
'''); gh.chmod(0o700)
                for name, body in [('seq', '#!/bin/sh\necho 1\n'), ('sleep', '#!/bin/sh\nexit 0\n')]:
                    path = bin_dir / name; path.write_text(body); path.chmod(0o700)
                result = subprocess.run(['bash', '-c', guard], env={**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
                    'REQUEST_ID': '8-1', 'OPEN_CORE_SHA': 'a' * 40, 'ENTERPRISE_SHA': 'b' * 40, 'FIXTURE_DIR': str(root), 'FIXTURE_MODE': mode}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mode == 'success', result.stderr)
                self.assertNotIn('PRIVATE-COMPILER-DIAGNOSTIC', result.stdout + result.stderr)


class PythonSelectionTests(unittest.TestCase):
    def test_empty_and_skipped_python_selections_fail(self):
        for body, good in [('pass\n', False),
                           ('import unittest\n@unittest.skip("fixture")\nclass T(unittest.TestCase):\n def test_case(self): pass\n', False),
                           ('import unittest\nclass T(unittest.TestCase):\n def test_case(self): self.assertTrue(True)\n', True)]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root / 'test_fixture.py').write_text(body)
                result = subprocess.run(['python3', str(ROOT / 'scripts/run-ci-tests.py'), str(root), 'test_fixture.py'], capture_output=True)
                self.assertEqual(result.returncode == 0, good)

if __name__ == '__main__': unittest.main()
