"""Mutation tests for unsafe CI changes, evidence and credential leakage."""
import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('security_check', ROOT / 'scripts/security_check.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.workflow = json.loads((ROOT / '.github/workflows/security-baseline.yml').read_text())

    def reject(self, change):
        workflow = copy.deepcopy(self.workflow)
        change(workflow)
        self.assertTrue(policy.workflow_errors(json.dumps(workflow).encode()))

    def test_reviewed_workflow(self):
        self.assertEqual([], policy.workflow_errors(json.dumps(self.workflow).encode()))

    def test_frontend_install_cannot_drop_hashes_or_allow_source_builds(self):
        command=self.workflow['jobs']['baseline']['steps'][2]['run']
        for flag in ('--require-hashes','--only-binary=:all:'):
            self.reject(lambda w:w['jobs']['baseline']['steps'][2].update(run=command.replace(flag,'')))
        self.assertEqual([],policy.dependency_errors((ROOT/'requirements-tui.txt').read_bytes()))
        for value in (b'textual>=8',b'-e attacker',b'--extra-index-url https://example.test',
                      b'textual==8.2.8 --hash=sha256:bad'):
            self.assertTrue(policy.dependency_errors(value))

    def test_platform_step_cannot_use_mutable_images_or_skip_required_targets(self):
        command=self.workflow['jobs']['baseline']['steps'][4]['run']
        for before,after in (('python@sha256:726d304906fa5eb468e5531e366548d1903286352f5adb54ef508ac01fbd80c6','python:latest'),
                             ('--target ubuntu-24.04','--target other'),('--container',''),('--frontend','')):
            self.reject(lambda w:w['jobs']['baseline']['steps'][4].update(run=command.replace(before,after)))
        install=self.workflow['jobs']['baseline']['steps'][2]['run']
        self.reject(lambda w:w['jobs']['baseline']['steps'][2].update(run=install.replace('--no-index','')))

    def test_package_matrix_and_read_only_hash_locked_inputs_are_required(self):
        self.reject(lambda w:w['jobs']['package']['strategy']['matrix']['target'].remove('debian-12'))
        self.reject(lambda w:w['jobs']['package'].update(permissions={'contents':'write'}))
        command=self.workflow['jobs']['package']['steps'][1]['run']
        for flag in ('--require-hashes','--only-binary=:all:'):
            self.reject(lambda w:w['jobs']['package']['steps'][1].update(run=command.replace(flag,'')))
        self.reject(lambda w:w['jobs']['package']['steps'][0].update(uses='actions/checkout@main'))

    def test_package_allowlist_contains_tracked_application_sources_only(self):
        tracked={'faultlens/cli.py','faultlens/__init__.py','README.md'}
        valid=b'faultlens/__init__.py\nfaultlens/cli.py\n'
        self.assertEqual([],policy.package_source_errors(valid,tracked))
        for data in (b'faultlens/cli.py\n', valid+b'faultlens/local_private.py\n',valid+b'../credentials.py\n',valid+valid):
            self.assertTrue(policy.package_source_errors(data,tracked))

    def test_unpinned_or_foreign_action(self):
        for action in ('actions/checkout@v7', 'actions/checkout@' + 'a' * 39,
                       'attacker/checkout@' + 'a' * 40):
            with self.subTest(action=action):
                self.reject(lambda w: w['jobs']['baseline']['steps'][0].update(uses=action))

    def test_privileged_triggers(self):
        for trigger in ('pull_request_target', 'workflow_run', 'issue_comment'):
            with self.subTest(trigger=trigger):
                self.reject(lambda w: w['on'].update({trigger: {}}))

    def test_write_permissions_and_credential_persistence(self):
        self.reject(lambda w: w.update(permissions={'contents': 'write'}))
        self.reject(lambda w: w['jobs']['baseline'].update(permissions={'id-token': 'write'}))
        self.reject(lambda w: w['jobs']['baseline']['steps'][0]['with'].update({'persist-credentials': True}))

    def test_hostile_execution_contexts(self):
        self.reject(lambda w: w['jobs']['baseline'].update({'runs-on': 'self-hosted'}))
        self.reject(lambda w: w['jobs']['baseline'].update(container='attacker/image'))
        self.reject(lambda w: w['jobs']['baseline'].update(env={'TOKEN': '${{ secrets.TOKEN }}'}))
        self.reject(lambda w: w['jobs']['baseline']['steps'][1].update(run='echo ${{ github.event.pull_request.title }}'))
        self.reject(lambda w: w['jobs']['baseline']['steps'].append({'run': 'curl https://example.test'}))

    def test_codeql_is_pinned_and_cannot_write_repository_content(self):
        workflow = json.loads((ROOT / '.github/workflows/codeql.yml').read_text())
        self.assertEqual([], policy.codeql_errors(json.dumps(workflow).encode()))
        mutations = [
            lambda w: w.update(permissions={'contents': 'write'}),
            lambda w: w['jobs']['analyze']['permissions'].update({'contents': 'write'}),
            lambda w: w['jobs']['analyze']['steps'][1].update(uses='github/codeql-action/init@v4'),
            lambda w: w['jobs']['analyze']['steps'][0]['with'].update({'persist-credentials': True}),
            lambda w: w['on'].update({'pull_request_target': {}}),
            lambda w: w['jobs']['analyze'].update(env={'TOKEN': '${{ secrets.TOKEN }}'}),
        ]
        for index, mutation in enumerate(mutations):
            candidate = copy.deepcopy(workflow)
            mutation(candidate)
            with self.subTest(mutation=index):
                self.assertTrue(policy.codeql_errors(json.dumps(candidate).encode()))

    def test_yaml_and_duplicate_keys_fail_closed(self):
        self.assertTrue(policy.workflow_errors(b'on: [pull_request_target]'))
        self.assertTrue(policy.workflow_errors(b'{"on": {}, "on": {}}'))

    def test_secret_signatures_without_disclosure(self):
        for credential in ('gh' + 'p_' + 'A' * 36,
                           'AK' + 'IA' + 'A' * 16,
                           '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
                           'password' + '=super-sensitive-value',
                           'https://user:' + 'secret@example.test'):
            with self.subTest(kind=credential[:4]):
                self.assertEqual(['possible credential material'], policy.secret_errors(credential.encode()))

    def test_sensitive_paths_and_binary_content(self):
        for path in ('.env', '.env.production', 'reports/result.json', 'tests/fixtures/live.log', '.ssh/id_rsa'):
            with self.subTest(path=path):
                self.assertTrue(policy.content_errors(path, b'example'))
        self.assertTrue(policy.content_errors('data.txt', b'\x00binary'))
        self.assertTrue(policy.content_errors('link', b'/etc/shadow', '120000'))
        self.assertTrue(policy.content_errors('large.txt', b'x' * (policy.MAX_BYTES + 1)))

    def test_unsafe_evidence(self):
        good = {'synthetic': True, 'description': 'Invented event',
                'events': [{'timestamp': '2026-01-01T00:00:00Z',
                            'message': '192.0.2.1 example.test'}]}
        path = 'tests/fixtures/event.json'
        self.assertEqual([], policy.fixture_errors(path, json.dumps(good)))
        for message in ('10.0.0.1', '8.8.8.8', 'fd00::1', 'admin@internal.corp',
                        '/home/alice/private', '\x1b]52;c;clipboard\x07'):
            value = copy.deepcopy(good)
            value['events'][0]['message'] = message
            with self.subTest(message=repr(message)):
                self.assertTrue(policy.fixture_errors(path, json.dumps(value)))
        good['synthetic'] = False
        self.assertTrue(policy.fixture_errors(path, json.dumps(good)))
        self.assertTrue(policy.fixture_errors(path, 'unstructured host capture'))

    def test_git_failures_are_actionable_without_logging_raw_stderr(self):
        for detail, expected in ((b'fatal: detected dubious ownership: synthetic-private-path', 'checkout owner'),
                                 (b'fatal: not a git repository: synthetic-private-path', 'checkout root'),
                                 (b'Permission denied: synthetic-private-path', 'read access'),
                                 (b'Other failure: synthetic-private-path', 'Git read operation failed')):
            failure = subprocess.CalledProcessError(128, ['git', 'ls-files'], stderr=detail)
            output = io.StringIO()
            with patch.object(policy, 'check_repository', side_effect=failure), contextlib.redirect_stderr(output):
                self.assertEqual(1, policy.main())
            self.assertIn(expected, output.getvalue())
            self.assertNotIn('synthetic-private-path', output.getvalue())
            self.assertNotIn('passed', output.getvalue())

    def test_deleted_secret_is_still_found_in_history(self):
        # Isolated repository: no real secrets, host diagnostics, or remote access.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            def git(*args):
                return subprocess.run(['git', '-C', directory, *args], check=True,
                                      capture_output=True)
            git('init', '-q')
            git('config', 'user.name', 'Synthetic Test')
            git('config', 'user.email', 'test@example.test')
            secret = repo / ('gh' + 'p_' + 'B' * 36 + '.txt')
            secret.write_text('gh' + 'p_' + 'A' * 36)
            git('add', '.')
            git('commit', '-qm', 'Add synthetic token for rejection test')
            git('rm', '-q', secret.name)
            git('commit', '-qm', 'Remove synthetic token')
            result = subprocess.run(['python3', str(ROOT / 'scripts/security_check.py')],
                                    cwd=repo, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Git object', result.stderr)
            self.assertIn('possible credential material', result.stderr)
            self.assertNotIn('A' * 36, result.stderr)
            self.assertNotIn('B' * 36, result.stderr)


if __name__ == '__main__':
    unittest.main()
