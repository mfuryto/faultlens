"""Conservative repository checks, without dependencies or live host collection."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

MAX_BYTES = 1024 * 1024
SHA_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\Z")
# Assemble signatures so the scanner's own source does not resemble a live secret.
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN " + r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_" + r"[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)" + r"[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[baprs]-" + r"[A-Za-z0-9-]{20,}\b"),
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)"
               + r"\s*[:=]\s*[\"']?[^\s\"'<>]{8,}"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@"),
]
SENSITIVE_PARTS = {'.aws', '.ssh', '.gnupg', '.venv', 'venv', 'env', 'reports',
                   'evidence', 'collected', 'node_modules', '__pycache__'}
SENSITIVE_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.keystore', '.log', '.journal',
                      '.pcap', '.pcapng', '.dump', '.core', '.zip', '.tgz', '.tar', '.gz'}
DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in
                     ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))


def git(*args: str) -> bytes:
    return subprocess.check_output(['git', *args], stderr=subprocess.PIPE)


def secret_errors(data: bytes) -> list[str]:
    text = data.decode('utf-8', errors='replace')
    return ['possible credential material'] if any(p.search(text) for p in SECRET_PATTERNS) else []


def fixture_errors(path: str, text: str) -> list[str]:
    if not path.startswith('tests/fixtures/'):
        return []
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return ['fixtures must be synthetic JSON']
    if (not path.endswith('.json') or not isinstance(value, dict)
            or set(value) != {'synthetic', 'description', 'events'}
            or value['synthetic'] is not True
            or not isinstance(value['description'], str)
            or not value['description'].strip()
            or not isinstance(value['events'], list)):
        return ['fixture requires synthetic=true, description and events only']
    for event in value['events']:
        if (not isinstance(event, dict) or set(event) != {'timestamp', 'message'}
                or not all(isinstance(v, str) for v in event.values())):
            return ['fixture events require timestamp and message strings only']
    # Inspect both text and JSON-decoded values to catch escaped addresses/controls.
    decoded = value['description'] + '\n' + '\n'.join(
        e['timestamp'] + ' ' + e['message'] for e in value['events'])
    errors = []
    if any(ord(c) < 32 and c not in '\n\t' or ord(c) == 127 for c in decoded):
        errors.append('fixture contains terminal/control characters')
    for candidate in re.findall(r'(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|[0-9A-Fa-f]*:[0-9A-Fa-f:]+', decoded):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not any(address.version == n.version and address in n for n in DOC_NETWORKS):
            errors.append('fixture address must use a documentation network')
    # Only reserved .test/.example/.invalid names, including email domains, are allowed.
    for domain in re.findall(r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b', decoded):
        if not domain.endswith(('.test', '.example', '.invalid')):
            errors.append('fixture hostname must use a reserved example domain')
    if re.search(r'/(?:home|root|var/log|etc)/', decoded):
        errors.append('fixture contains a potentially identifying host path')
    return errors + secret_errors(decoded.encode())


def content_errors(path: str, data: bytes, mode: str = '100644') -> list[str]:
    errors = []
    parts = PurePosixPath(path).parts
    if (set(parts) & SENSITIVE_PARTS or PurePosixPath(path).suffix.lower() in SENSITIVE_SUFFIXES
            or any(p == '.env' or p.startswith('.env.') or p in {'.netrc', '.pypirc'}
                   or p.lower().startswith(('credentials', 'secrets', 'sosreport', 'atop_'))
                   for p in parts)):
        errors.append('sensitive or generated file path')
    if mode not in {'100644', '100755'}:
        errors.append('symlinks and submodules require a policy review')
    if len(data) > MAX_BYTES:
        errors.append('tracked file exceeds 1 MiB limit')
    try:
        text = data.decode('utf-8')
        if '\x00' in text:
            raise ValueError('binary')
    except (UnicodeError, ValueError):
        return errors + ['tracked content must be UTF-8 text']
    return errors + secret_errors(data) + fixture_errors(path, text)


def workflow_errors(data: bytes) -> list[str]:
    """Accept only the deliberately narrow baseline profile; fail closed on YAML."""
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError('duplicate key')
            obj[key] = value
        return obj

    try:
        workflow = json.loads(data, object_pairs_hook=unique_object)
        assert set(workflow) == {'name', 'on', 'permissions', 'concurrency', 'jobs'}
        assert workflow['name'] == 'Security baseline'
        assert workflow['on'] == {
            'push': {'branches': ['main', 'staging']},
            'pull_request': {'branches': ['main']}, 'workflow_dispatch': {}}
        assert workflow['permissions'] == {'contents': 'read'}
        assert workflow['concurrency'] == {
            'group': 'security-${{ github.workflow }}-${{ github.ref }}',
            'cancel-in-progress': True}
        assert set(workflow['jobs']) == {'baseline'}
        job = workflow['jobs']['baseline']
        assert set(job) == {'runs-on', 'timeout-minutes', 'steps'}
        assert job['runs-on'] == 'ubuntu-24.04'
        assert type(job['timeout-minutes']) is int and 1 <= job['timeout-minutes'] <= 10
        steps = job['steps']
        assert len(steps) == 3
        checkout = steps[0]
        assert set(checkout) == {'name', 'uses', 'with'}
        assert SHA_ACTION.fullmatch(checkout['uses'])
        assert checkout['uses'].split('@')[0] == 'actions/checkout'
        assert checkout['with'] == {'fetch-depth': 0, 'persist-credentials': False}
        for step, command in zip(steps[1:], (
                'python3 scripts/security_check.py',
                'python3 -m unittest discover -s tests -v')):
            assert set(step) == {'name', 'run'}
            assert step['run'] == command
        assert all(isinstance(step['name'], str) for step in steps)
    except (ValueError, TypeError, KeyError, AssertionError, AttributeError, RecursionError):
        return ['workflow violates the constrained JSON security profile']
    return []



def codeql_errors(data: bytes) -> list[str]:
    """Code scanning may write findings only, never repository content."""
    try:
        def unique_object(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError('duplicate key')
                obj[key] = value
            return obj
        workflow = json.loads(data, object_pairs_hook=unique_object)
        assert set(workflow) == {'name', 'on', 'permissions', 'jobs'}
        assert workflow['name'] == 'CodeQL'
        assert workflow['on'] == {
            'push': {'branches': ['main', 'staging']},
            'pull_request': {'branches': ['main']},
            'schedule': [{'cron': '23 6 * * 1'}]}
        assert workflow['permissions'] == {'contents': 'read'}
        assert set(workflow['jobs']) == {'analyze'}
        job = workflow['jobs']['analyze']
        assert set(job) == {'runs-on', 'timeout-minutes', 'permissions', 'steps'}
        assert job['runs-on'] == 'ubuntu-24.04'
        assert type(job['timeout-minutes']) is int and 1 <= job['timeout-minutes'] <= 20
        assert job['permissions'] == {'contents': 'read', 'security-events': 'write'}
        steps = job['steps']
        assert len(steps) == 3
        expected = [
            ('actions/checkout', {'persist-credentials': False}),
            ('github/codeql-action/init', {'languages': 'python', 'build-mode': 'none',
                                          'queries': 'security-extended'}),
            ('github/codeql-action/analyze', {'category': '/language:python'})]
        for step, (action, options) in zip(steps, expected):
            assert set(step) == {'name', 'uses', 'with'}
            assert isinstance(step['name'], str)
            assert SHA_ACTION.fullmatch(step['uses'])
            assert step['uses'].split('@')[0] == action
            assert step['with'] == options
    except (ValueError, TypeError, KeyError, AssertionError, AttributeError, RecursionError):
        return ['CodeQL workflow violates the constrained JSON security profile']
    return []


def check_repository() -> list[str]:
    errors = []
    tracked = git('ls-files', '--stage', '-z').split(b'\0')
    workflows = set()
    for record in filter(None, tracked):
        metadata, raw_path = record.split(b'\t', 1)
        mode, _, stage = metadata.decode().split()
        path = raw_path.decode('utf-8')
        if stage != '0':
            errors.append(f'{path}: unresolved index entry')
            continue
        file = Path(path)
        # Never follow a tracked symlink during a scan.
        if mode == '120000' or file.is_symlink():
            errors.append(f'{path}: symlink rejected')
            continue
        if mode == '160000':
            errors.append(f'{path}: submodule rejected')
            continue
        data = file.read_bytes()
        errors.extend(f'{path}: {e}' for e in content_errors(path, data, mode))
        if path.startswith('.github/workflows/'):
            workflows.add(path)
            checks = {'.github/workflows/security-baseline.yml': workflow_errors,
                      '.github/workflows/codeql.yml': codeql_errors}
            if path not in checks:
                errors.append(f'{path}: additional workflows require a policy review')
            else:
                errors.extend(f'{path}: {e}' for e in checks[path](data))
        if path.endswith(('/action.yml', '/action.yaml')) or path in {'action.yml', 'action.yaml'}:
            errors.append(f'{path}: local actions require a policy review')
    if workflows != {'.github/workflows/security-baseline.yml', '.github/workflows/codeql.yml'}:
        errors.append('exactly the baseline and CodeQL workflows are required')

    # Scan every reachable blob, not just the working tree or latest commit. Do not
    # print matched content: the check must not copy suspected secrets to CI logs.
    objects = git('rev-list', '--objects', '--all').splitlines()
    for entry in objects:
        oid, _, _ = entry.partition(b' ')
        object_id = oid.decode('ascii')
        kind = git('cat-file', '-t', object_id).strip()
        if kind not in {b'blob', b'commit', b'tag'}:
            continue
        size = int(git('cat-file', '-s', object_id))
        if size > MAX_BYTES:
            errors.append(f'Git object {object_id[:12]}: exceeds scan size limit; manual review required')
            continue
        data = git('cat-file', '-p', object_id)
        errors.extend(f'Git object {object_id[:12]}: {e}' for e in secret_errors(data))
    return errors


def main() -> int:
    if not __debug__:
        print('Security policy requires Python without optimization.', file=sys.stderr)
        return 1
    try:
        errors = check_repository()
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f'Security scan could not complete ({type(exc).__name__}).', file=sys.stderr)
        return 1
    for error in errors:
        # Never propagate file names, object metadata or scanner-derived text to CI.
        # These may themselves contain sensitive material. Log fixed categories only.
        if 'possible credential material' in error:
            print('Security policy: possible credential material in tracked content or a Git object.',
                  file=sys.stderr)
        else:
            print('Repository policy violation; inspect tracked files and workflow configuration locally.',
                  file=sys.stderr)
    if errors:
        print(f'Security baseline failed: {len(errors)} finding(s).', file=sys.stderr)
        return 1
    print('Security baseline passed: tracked files, workflow policy and reachable Git objects.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
