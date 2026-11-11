"""Mutation tests for unsafe CI changes, evidence and credential leakage."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

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
