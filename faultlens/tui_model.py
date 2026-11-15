"""Terminal-independent, single-snapshot administrator navigation and collection."""
from dataclasses import asdict, dataclass
import json

from .collectors import check, status
from .incidents import diagnose
from .models import report
from .network import collect as network
from .overview import incidents

PAGES = ('System Overview', 'System Health', 'Network Status', 'Security Analysis',
         'Incident History', 'Diagnostics', 'Evidence Explorer', 'Settings')
SETTING_KEYS = ('boot_selector', 'system_journal', 'sample_seconds', 'boot_count',
                'include_current', 'preservation', 'sockets', 'search_events',
                'search_ssh', 'search_firewall', 'atop_date', 'atop_extended',
                'pstore', 'pstore_archive', 'since_us', 'until_us')


def escaped(value):
    """Lossless ASCII JSON; never interpret data as terminal markup or escapes."""
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def brief(value):
    if isinstance(value, dict):
        if isinstance(value.get('key'), str) and 'value' in value and isinstance(value.get('unit'), str):
            return brief(value['value']) + ' ' + escaped(value['unit'][:32])
        identity = value.get('title', value.get('key', value.get('boot_id', value.get('interface', value.get('device', '')))))
        return f"object ({len(value)} fields) " + escaped(str(identity)[:80])
    if isinstance(value, list):
        return f"list ({len(value)} items)"
    if isinstance(value, str) and len(value) > 80:
        return escaped(value[:80]) + f' ... ({len(value)} characters; Enter to inspect all)'
    return escaped(value)


@dataclass
class Settings:
    boot_selector: str = '-1'
    system_journal: bool = False
    sample_seconds: float = 0.1
    boot_count: int = 3
    include_current: bool = False
    preservation: bool = False
    sockets: bool = False
    search_events: bool = False
    search_ssh: bool = False
    search_firewall: bool = False
    atop_date: str = ''
    atop_extended: bool = False
    pstore: bool = False
    pstore_archive: bool = False
    since_us: str = ''
    until_us: str = ''


@dataclass(frozen=True)
class Row:
    label: str
    value: object
    action: str = 'inspect'


def children(value):
    if isinstance(value, dict):
        return [Row(escaped(key), child) for key, child in value.items()]
    if isinstance(value, list):
        return [Row(str(index), child) for index, child in enumerate(value)]
    return []


class Session:
    def __init__(self, *, sources=None, runner=None, pstore_collector=None,
                 pstore_archive_collector=None, sample_seconds=0.1):
        self.sources, self.runner = sources, runner
        self.pstore_collector = pstore_collector
        self.pstore_archive_collector = pstore_archive_collector
        self.settings = Settings(sample_seconds=sample_seconds)
        self.page, self.selected, self.scroll = 0, 0, 0
        self.data, self.snapshot_settings = None, None
        self.stack = []
        self.notice = 'Read-only. Press r to collect; 1-8 choose a page. No automatic polling.'

    def choose_page(self, page):
        if type(page) is not int or not 0 <= page < len(PAGES):
            raise ValueError('Unknown page')
        self.page, self.selected, self.scroll = page, 0, 0
        self.stack.clear()

    def update_setting(self, key, text=None):
        from .cli import atop_date, boot_identity, boot_index, interval, overview_count, receipt_boundary
        from .journal import validate_window
        if key not in SETTING_KEYS:
            raise ValueError('Unknown setting')
        proposed = asdict(self.settings)
        current = proposed[key]
        if type(current) is bool:
            proposed[key] = not current
        elif key == 'boot_selector':
            proposed[key] = boot_identity(text) if len(text) == 32 else str(boot_index(text))
        elif key == 'sample_seconds':
            proposed[key] = interval(text)
        elif key == 'boot_count':
            proposed[key] = overview_count(text)
        elif key == 'atop_date':
            proposed[key] = atop_date(text) if text else ''
            if not text:
                proposed['atop_extended'] = False
        elif key in {'since_us', 'until_us'}:
            proposed[key] = str(receipt_boundary(text)) if text else ''
        validate_window(int(proposed['since_us']) if proposed['since_us'] else None,
                        int(proposed['until_us']) if proposed['until_us'] else None)
        if proposed['atop_extended'] and not proposed['atop_date']:
            raise ValueError('Set an existing recording date before enabling extended Atop')
        self.settings = Settings(**proposed)
        self.notice = 'Session setting updated. Existing snapshots keep their original scope; r collects again.'

    def refresh(self):
        if self.page in {6, 7}:
            self.notice = 'This page does not collect. Choose a source page and press r.'
            return
        # Drop browser references before collecting a replacement; do not retain two reports.
        self.data, self.snapshot_settings = None, None
        self.stack.clear()
        self.selected, self.scroll = 0, 0
        options = asdict(self.settings)
        if self.page in {0, 1}:
            kind = 'status' if self.page == 0 else 'check'
            observations = (status(self.sources, self.runner, self.settings.sample_seconds)
                            if self.page == 0 else check(self.sources, self.runner))
            if self.page == 1 and self.settings.preservation:
                from .preservation import assess
                observations.extend(assess(self.sources, self.runner))
            data = report(kind, observations)
        elif self.page in {2, 3}:
            data = network(self.sources, command='network' if self.page == 2 else 'security',
                           sample_seconds=self.settings.sample_seconds)
            if self.settings.sockets:
                from .sockets import attach
                attach(data, self.runner)
        elif self.page == 4:
            data = incidents(self.runner, boot_count=self.settings.boot_count,
                system_journal=self.settings.system_journal, include_current=self.settings.include_current)
        else:
            selector = self.settings.boot_selector
            data = diagnose(self.runner, None if len(selector) == 32 else int(selector),
                self.settings.atop_date or None, boot_id=selector if len(selector) == 32 else None,
                system_journal=self.settings.system_journal, search_events=self.settings.search_events,
                search_ssh=self.settings.search_ssh, search_firewall=self.settings.search_firewall,
                atop_extended=self.settings.atop_extended, show_evidence=True,
                since_us=int(self.settings.since_us) if self.settings.since_us else None,
                until_us=int(self.settings.until_us) if self.settings.until_us else None)
            if self.settings.pstore:
                from .pstore import analyze
                data['pstore'] = analyze(self.pstore_collector)
            if self.settings.pstore_archive:
                from .pstore_archive import analyze
                data['pstore_archive'] = analyze(self.pstore_archive_collector)
        self.data, self.snapshot_settings = data, options
        self.notice = 'Snapshot collected. Availability is not proof of system health; Enter inspects evidence.'

    @property
    def stale(self):
        return self.data is not None and self.snapshot_settings != asdict(self.settings)

    @property
    def value(self):
        return self.stack[-1][0] if self.stack else None

    def rows(self):
        if self.stack:
            return children(self.value)
        if self.page == 7:
            return [Row(key, getattr(self.settings, key), 'setting') for key in SETTING_KEYS]
        if self.data is None:
            return []
        command = self.data['command']
        if self.page == 6:
            return [Row('Snapshot settings', self.snapshot_settings), Row('Full original report', self.data)]
        expected = ('status', 'check', 'network', 'security', 'incidents', 'diagnose')[self.page]
        if command != expected and not (self.page == 3 and command == 'diagnose'):
            return []
        if self.page == 4:
            return ([Row('Boot ' + str(boot['index']) + ': ' + boot['boot_id'], boot, 'boot')
                    for boot in self.data['boots']] + [Row('Boot summaries', self.data['summaries']),
                    Row('Full report', self.data)])
        if self.page in {0, 1, 2, 3} and command != 'diagnose':
            return [Row('[' + item['state'].upper() + '] ' + item['key'], item)
                    for item in self.data['observations']] + [Row('Full report', self.data)]
        keys = ('security_analysis', 'ssh_analysis', 'firewall_analysis') if self.page == 3 else (
            'findings', 'timeline', 'reconstruction', 'journal_records', 'security_analysis',
            'ssh_analysis', 'firewall_analysis', 'atop', 'pstore', 'pstore_archive')
        return [Row(key, self.data[key]) for key in keys if key in self.data] + [Row('Full report', self.data)]

    def open_row(self, *, inspect_only=False):
        rows = self.rows()
        if not rows:
            return
        row = rows[min(self.selected, len(rows)-1)]
        if row.action == 'boot' and not inspect_only:
            self.update_setting('boot_selector', row.value['boot_id'])
            self.choose_page(5)
            self.notice = 'Immutable boot ID selected. Press r to diagnose it with current session options.'
        elif row.action != 'setting' or inspect_only:
            if len(self.stack) >= 64:
                self.notice = 'Navigation depth limit reached; use Left to return.'
                return
            self.stack.append((row.value, row.label, self.selected, self.scroll))
            self.selected, self.scroll = 0, 0

    def back(self):
        if self.stack:
            _, _, self.selected, self.scroll = self.stack.pop()

    def help(self):
        if len(self.stack) >= 64:
            self.notice = 'Navigation depth limit reached; use Left to return.'
            return
        guide = {
            'Navigation': '1-8 or Tab choose pages; Up/Down, j/k, PageUp/PageDown, Home/End move. Enter opens, Left returns. q quits.',
            'Collection': 'r replaces the current snapshot on source pages only. No automatic polling. Ctrl-C interrupts collection and restores the terminal.',
            'Evidence': 'Enter drills into every object/list/scalar. Long values are paged in lossless ASCII JSON form. e inspects boot metadata; t opens the retained timeline.',
            'Settings': 'Session only; no system configuration or report writes. Enter toggles booleans or edits values. Esc cancels an edit; Ctrl-U clears it.',
            'boot_selector': 'An index from -128 to 0 or a visible 32-character lowercase hexadecimal boot ID. History selection pins the ID.',
            'sample_seconds': '0.05 to 1 second. Actual elapsed time controls counter rates.',
            'boot_count': '1 to 7 visible previous boots; include_current opts in to current boot.',
            'atop_date': 'Empty disables replay; otherwise an existing YYYYMMDD recording. atop_extended requires a date. Source host/boot identity stays unverified.',
            'since_us/until_us': 'Empty or nonnegative Unix microseconds through year 9999; start must not exceed end. Collection caps still apply.',
            'Scope': 'system_journal selects accessible system journals without elevation. Other source toggles request their existing read-only adapters.',
            'Privacy': 'No masking of collected administrator evidence. Controls are escaped; no clipboard, shell, report export or upload is provided.',
            'Confidence': 'No matches is not an all-clear. Confirmed reports are not confirmed attacks or root causes.',
        }
        self.stack.append((guide, 'Help and scope', self.selected, self.scroll))
        self.selected, self.scroll = 0, 0

    def timeline(self):
        if self.data and self.data.get('command') == 'diagnose':
            self.stack = [(self.data['timeline'], 'Retained boot-local timeline', self.selected, self.scroll)]
            self.selected, self.scroll = 0, 0
            self.notice = 'Main retained timeline only; filtered timelines remain inside their source views.'
