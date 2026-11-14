"""Read-only preservation assessment; configuration snapshots are not runtime proof."""
import re
import shlex

from .commands import Command, CommandRunner
from .linux import LinuxSources
from .models import Observation, unavailable

JOURNAL_KEYS = {
    'Storage': ('storage', 'mode'),
    'SystemMaxUse': ('system_max_use', 'bytes'),
    'SystemKeepFree': ('system_keep_free', 'bytes'),
    'RuntimeMaxUse': ('runtime_max_use', 'bytes'),
    'RuntimeKeepFree': ('runtime_keep_free', 'bytes'),
    'MaxRetentionSec': ('max_retention', 'seconds'),
}
CONFIG_SOURCE = 'systemd-analyze cat-config --tldr systemd/journald.conf'
CONFIG_LIMITS = ('Default namespace configuration snapshot only; loaded daemon state and flush state are not verified.',
                 'Missing explicit settings do not imply missing defaults or unbounded storage.',
                 'Configured budgets and time limits do not guarantee actual retained history.')


def capacity(text):
    match = re.fullmatch(r'([0-9]{1,18})([KMGTPE]?)', text)
    if not match:
        raise ValueError('Unsupported size')
    value = int(match[1]) * (1024 ** ('KMGTPE'.index(match[2]) + 1) if match[2] else 1)
    if value > 2**63 - 1:
        raise ValueError('Size exceeds supported range')
    return value


def seconds(text):
    units = {'s': 1, 'sec': 1, 'second': 1, 'seconds': 1, 'm': 60, 'min': 60,
             'minute': 60, 'minutes': 60, 'h': 3600, 'hour': 3600, 'hours': 3600,
             'd': 86400, 'day': 86400, 'days': 86400, 'w': 604800,
             'week': 604800, 'weeks': 604800}
    if not text or len(text) > 128:
        raise ValueError('Unsupported duration')
    position, value = 0, 0
    while position < len(text):
        match = re.match(r'\s*([0-9]{1,12})\s*([A-Za-z]*)\s*', text[position:])
        if (not match or (match[2] and match[2] not in units)
                or (not match[2] and position + match.end() != len(text))):
            raise ValueError('Unsupported duration unit')
        value += int(match[1]) * units.get(match[2], 1)
        position += match.end()
    if value > 2**63 - 1:
        raise ValueError('Duration exceeds supported range')
    return value


def journal_config(text):
    if len(text.encode('utf-8')) > 262144:
        raise ValueError('Configuration exceeds limit')
    values = {key: None for key in JOURNAL_KEYS}
    states = {key: 'unspecified' for key in JOURNAL_KEYS}
    section, pending = None, ''
    for index, raw in enumerate(text.splitlines()):
        if index >= 4096 or len(raw) > 4096:
            raise ValueError('Configuration structure exceeds limit')
        line = raw.strip()
        if line.startswith('# /'):
            if pending or not re.fullmatch(r'# /(?:etc|run|usr/local/lib|usr/lib|lib)/systemd/journald\.conf(?:\.d/[^/\x00-\x1f]+\.conf)?', line):
                raise ValueError('Ambiguous configuration boundary')
            section = None
            continue
        if not line or line.startswith(('#', ';')):
            continue
        if line.endswith('\\'):
            pending += line[:-1] + ' '
            if len(pending) > 4096:
                raise ValueError('Continuation exceeds limit')
            continue
        line, pending = pending + line, ''
        if line.startswith('['):
            if not re.fullmatch(r'\[[A-Za-z0-9_.-]+\]', line):
                raise ValueError('Invalid section')
            section = line[1:-1]
            continue
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if key not in JOURNAL_KEYS:
            continue
        if not separator or section is None:
            raise ValueError('Ambiguous setting scope')
        if section != 'Journal':
            continue
        try:
            if key == 'Storage':
                if value not in {'auto', 'persistent', 'volatile', 'none'}:
                    raise ValueError('Unsupported storage mode')
                parsed = value
            else:
                parsed = seconds(value) if key == 'MaxRetentionSec' else capacity(value)
            values[key], states[key] = parsed, 'explicit'
        except ValueError:
            values[key], states[key] = None, 'unsupported'
    if pending:
        raise ValueError('Incomplete configuration continuation')
    return values, states


def atop_defaults(text):
    if len(text.encode('utf-8')) > 16384:
        raise ValueError('Defaults exceed limit')
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)', line)
        if not match:
            raise ValueError('Defaults require shell evaluation')
        tokens = shlex.split(match[2], comments=True, posix=True)
        if len(tokens) > 1:
            raise ValueError('Non-literal defaults statement')
        value = tokens[0] if tokens else ''
        if any(char in value for char in '$`;|&<>\\'):
            raise ValueError('Defaults require shell evaluation')
        if match[1] in {'LOGINTERVAL', 'LOGGENERATIONS'}:
            if not re.fullmatch(r'[0-9]{1,8}', value):
                raise ValueError('Unsupported numeric default')
            values[match[1]] = int(value)
        elif match[1] == 'LOGPATH':
            values['standard_path'] = value == '/var/log/atop'
    return values


def assess(sources=None, runner=None):
    sources = sources or LinuxSources()
    runner = runner or CommandRunner()
    observations = []
    result = runner.run(Command.JOURNAL_CONFIG)
    try:
        if result.state != 'completed' or result.returncode != 0:
            raise ValueError('Configuration command unavailable')
        values, states = journal_config(result.stdout)
        for key, (label, unit) in JOURNAL_KEYS.items():
            value, origin = values[key], states[key]
            state = 'warning' if key == 'Storage' and value in {'volatile', 'none'} else 'unknown'
            observations.append(Observation('journal.config.' + label, value, unit, CONFIG_SOURCE,
                state, 'Confirmed' if origin == 'explicit' else 'Unknown',
                'Explicit configuration value observed; running state remains unverified.' if origin == 'explicit'
                else 'Setting is unspecified or uses an unsupported expression; no default value is assumed.',
                CONFIG_LIMITS, recommendations=(
                    'Verify accessible previous boots and loaded journald settings before planning any change.',
                    'Review storage budgets and retention together; defaults may already provide limits.')))
    except (ValueError, UnicodeError):
        observations.append(unavailable('journal.config', CONFIG_SOURCE,
            'Merged configuration could not be read or interpreted safely; no persistence mode is inferred.'))
    try:
        values = atop_defaults(sources.read('/etc/default/atop', limit=16384))
        for name, label, unit in (('LOGINTERVAL', 'interval', 'seconds'), ('LOGGENERATIONS', 'generations', 'days')):
            observations.append(Observation('atop.config.' + label, values.get(name), unit, '/etc/default/atop',
                'unknown', 'Confirmed' if name in values else 'Unknown',
                'Literal defaults-file hint only; effective unit overrides and running recorder state are not resolved.',
                ('The service may use unit defaults, other environment files or different paths.',),
                recommendations=('Compare with observed sample intervals and verify rotation; measure overhead before changing sampling.',)))
        observations.append(Observation('atop.config.standard_path', values.get('standard_path'), '', '/etc/default/atop',
            'warning' if values.get('standard_path') is False else 'unknown', 'Unknown',
            'Only the standard recording path is supported by the current replay adapter; an unset path may come from unit defaults.'))
    except (OSError, ValueError, KeyError, UnicodeError):
        observations.append(unavailable('atop.config', '/etc/default/atop',
            'Defaults are missing, inaccessible or need unsupported shell semantics; the file was not executed.'))
    for kind in ('journal', 'atop'):
        try:
            fs = sources.log_filesystem(kind)
            if fs.f_frsize <= 0 or not 0 <= fs.f_bavail <= fs.f_bfree <= fs.f_blocks:
                raise ValueError('Inconsistent log filesystem')
            total, available = fs.f_blocks * fs.f_frsize, fs.f_bavail * fs.f_frsize
            observations.append(Observation(kind + '.storage.total', total, 'bytes', 'fstatvfs(protected log directory)',
                'unknown', explanation='Filesystem capacity at the protected default log directory; this is not a retention guarantee.'))
            observations.append(Observation(kind + '.storage.available', available, 'bytes', 'fstatvfs(protected log directory)',
                'unknown', explanation='Available space on the inspected log filesystem at collection time; retention duration is unknown.',
                limitations=('Default log directory only; no file contents, runtime journal mount or namespace overrides inspected.',),
                recommendations=('Choose retention using measured growth and available capacity; no setting is changed automatically.',)))
        except (OSError, ValueError, KeyError, AttributeError):
            observations.append(unavailable(kind + '.storage.available', 'protected default log directory',
                                            'Log filesystem is absent, inaccessible or unsafe to inspect.'))
    try:
        inventory = sources.recording_inventory()
        observations.append(Observation('atop.recording_inventory', inventory, 'metadata', '/var/log/atop (metadata only)',
            'warning' if inventory['unsafe_entries'] or inventory['oversized_files'] else 'unknown',
            explanation='Bounded snapshot of protected date-named files; dates and sizes do not prove recorded coverage.',
            limitations=('No binary content read. Logical byte sizes differ from allocated disk blocks.',
                         'Files can change during inspection. Compressed/custom names are excluded.',
                         'At most 512 directory entries are inspected; no recursive traversal.'),
            recommendations=('Verify replay on the desired date; check retention/rotation and gaps before relying on history.',)))
    except (OSError, ValueError, KeyError, AttributeError):
        observations.append(unavailable('atop.recording_inventory', '/var/log/atop (metadata only)',
                                        'Inventory could not complete within safe access and enumeration limits.'))
    return observations
