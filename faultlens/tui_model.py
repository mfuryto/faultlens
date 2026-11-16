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


SETTING_NAMES = dict(zip(SETTING_KEYS, ('Selected boot (index or ID)', 'Use accessible system journals',
    'Sample duration (seconds)', 'Previous boots to summarize', 'Include current boot',
    'Check recording/retention setup', 'Include socket endpoints', 'Search kernel/service events',
    'Search SSH events', 'Search firewall events', 'Atop recording date (YYYYMMDD)',
    'Extended recorded measurements', 'Read live crash evidence', 'Read archived crash evidence',
    'Earliest journal receipt (Unix us)', 'Latest journal receipt (Unix us)')))
VIEW_NAMES = {'findings':'Explained findings', 'timeline':'Recorded event timeline',
    'reconstruction':'What the retained chronology shows', 'journal_records':'Original journal records',
    'security_analysis':'Security indicators and their limits', 'ssh_analysis':'SSH authentication evidence',
    'firewall_analysis':'Firewall log evidence', 'event_search':'Broader journal event search', 'atop':'Recorded resource measurements',
    'pstore':'Live crash evidence', 'pstore_archive':'Archived crash evidence'}


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

    @classmethod
    def administrator_defaults(cls, *, sample_seconds=0.1):
        """Enable read-only coverage; journal scope and dated replay remain explicit."""
        return cls(sample_seconds=sample_seconds,include_current=True,preservation=True,
                   sockets=True,search_events=True,search_ssh=True,search_firewall=True,
                   pstore=True,pstore_archive=True)


@dataclass(frozen=True)
class Row:
    label: str
    value: object
    action: str = 'inspect'
    key: str | None = None


def children(value):
    if isinstance(value, dict):
        return [Row(escaped(key), child) for key, child in value.items()]
    if isinstance(value, list):
        return [Row(str(index), child) for index, child in enumerate(value)]
    return []


def row_preview(row):
    """Shared bounded row representation for display and literal search."""
    if row.action=='observation':
        from .presentation import reading
        preview=escaped(reading(row.value))[1:-1]
    elif row.action=='guide':
        preview=escaped(row.value['Summary'])[1:-1]
    elif row.action=='finding':
        preview=escaped(row.value['confidence']+' report; cause '+row.value.get('cause_confidence','Unknown'))[1:-1]
    elif row.action=='timeline_entry':
        preview='Enter explains the referenced finding; e inspects timeline metadata'
    elif row.action=='boot_summary':
        preview=escaped(row.value['boot']['boot_id'])
    elif row.action=='socket_snapshot':
        preview='Local socket states and endpoints; external access unverified'
    elif row.action=='recording':
        preview='Recorded resource samples and coverage; host/boot identity unverified'
    elif row.action=='recording_sample':
        preview='Enter explains interval CPU and memory snapshots; e opens original measurements'
    elif row.action=='crash_source':
        preview='Retained crash fragments; boot/time/cause unverified'
    elif row.action=='crash_record':
        preview='Enter explains signature/encoding limits; e opens original fragment'
    elif row.action=='interface_sample':
        preview='Interface rates and comparison limits; e opens original counters'
    elif row.action=='socket_row':
        from .socket_presentation import state_meaning,binding_meaning
        preview=state_meaning(row.value)[0]+' | '+binding_meaning(row.value)[0]
    elif row.action=='explanation':
        text=(row.value[0] if row.value else 'No additional items') if isinstance(row.value,list) else row.value
        preview=escaped(str(text))[1:-1]+(' (Enter for all '+str(len(row.value))+')' if isinstance(row.value,list) and len(row.value)>1 else '')
    elif row.action=='setting' and type(row.value) is bool:
        preview='On' if row.value else 'Off'
    elif row.action=='setting' and row.value=='':
        preview='Not selected'
    else:
        preview=brief(row.value)
    return preview


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
        self.search_text = ''
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
        if self.page==0:
            data=report('status',status(self.sources,self.runner,self.settings.sample_seconds))
        elif self.page==1:
            from .health import collect
            data=collect(self.sources,self.runner,sample_seconds=self.settings.sample_seconds,
                         preservation=self.settings.preservation)
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
            context=self.stack[-1][4] if len(self.stack[-1])>4 else 'raw'
            if context=='boot_summaries':
                from .presentation import boot_summary_label
                return [Row(escaped(boot_summary_label(item))[1:-1],item,'boot_summary') for item in self.value]
            if context=='socket_rows':
                from .socket_presentation import row_label
                return [Row(escaped(row_label(item))[1:-1],item,'socket_row') for item in self.value]
            if context=='recording_samples':
                from .recording_presentation import sample_label
                return [Row(escaped(sample_label(item))[1:-1],item,'recording_sample') for item in self.value]
            if context=='crash_records':
                from .crash_presentation import record_label
                return [Row(escaped(record_label(item))[1:-1],item,'crash_record') for item in self.value]
            if context=='interface_samples':
                return [Row(escaped(item['interface'])[1:-1]+' | '+item['state'],item,'interface_sample') for item in self.value]
            if context=='interface_sample':
                return [Row(escaped(key)[1:-1],value,'inspect' if key in {'Technical details','Sample timing'} else 'explanation') for key,value in self.value.items()]
            if context in {'crash_source','crash_record'}:
                return [Row(escaped(key)[1:-1],value,'crash_records' if key=='Retained fragments' else 'inspect'
                            if key in {'Technical details','Original content','Signature line references'} else 'explanation') for key,value in self.value.items()]
            if context in {'recording','recording_sample'}:
                return [Row(escaped(key)[1:-1],value,'recording_samples' if key=='Retained samples' else 'inspect'
                            if key in {'Technical details','Reported coverage'} else 'explanation') for key,value in self.value.items()]
            if context in {'socket_snapshot','socket_row'}:
                return [Row(escaped(key)[1:-1],value,'socket_rows' if key=='Socket rows' else 'inspect'
                            if key=='Technical details' else 'explanation') for key,value in self.value.items()]
            if context in {'observation','finding','guide','boot_summary'}:
                if context=='observation':
                    return [Row(escaped(key)[1:-1],value,'interface_samples' if key=='Interface samples' else 'inspect'
                                if key=='Technical details' else 'explanation') for key,value in self.value.items()]
                if context=='boot_summary':
                    return [Row(escaped(key)[1:-1],value,'boot' if key=='Diagnose this boot' else 'inspect'
                                if key=='Technical details' else 'explanation') for key,value in self.value.items()]
                return [Row(escaped(key)[1:-1],value,'inspect' if key in {'Technical details','Referenced source evidence','Timeline position'} else 'explanation') for key,value in self.value.items()]
            if context=='explanation' and isinstance(self.value,list):
                return [Row(str(index+1),value,'explanation') for index,value in enumerate(self.value)]
            if context=='findings':
                return [Row(escaped(item['title'])[1:-1],item,'finding') for item in self.value]
            if context=='analysis':
                return [Row(escaped(key),value,'findings' if key=='findings' else 'timeline' if key=='timeline' else 'inspect') for key,value in self.value.items()]
            if context=='event_search':
                return [Row(escaped(key),value,'queries' if key=='queries' else 'inspect') for key,value in self.value.items()]
            if context=='queries':
                return [Row(escaped(value['query'].replace('_',' '))[1:-1],value,'analysis') for value in self.value]
            if context=='timeline':
                from .presentation import timeline_label
                return [Row(escaped(timeline_label(item))[1:-1],item,'timeline_entry') for item in self.value]
            return children(self.value)
        if self.page == 7:
            return [Row(SETTING_NAMES[key], getattr(self.settings, key), 'setting', key) for key in SETTING_KEYS]
        if self.data is None:
            return []
        command = self.data['command']
        if self.page == 6:
            return [Row('Snapshot settings', self.snapshot_settings), Row('Full original report', self.data)]
        expected = ('status', 'health', 'network', 'security', 'incidents', 'diagnose')[self.page]
        if command != expected and not (self.page == 3 and command == 'diagnose'):
            return []
        from .presentation import guide, name
        summary=Row('Summary and next steps',guide(self.data),'guide')
        if self.page == 4:
            return ([summary]+[Row('Boot ' + str(boot['index']) + ': ' + boot['boot_id'], boot, 'boot')
                    for boot in self.data['boots']] + [Row('Boot summaries', self.data['summaries'],'boot_summaries'),
                    Row('Full report', self.data)])
        if self.page in {0, 1, 2, 3} and command != 'diagnose':
            return [summary]+[Row('[' + item['state'].upper() + '] ' + escaped(name(item))[1:-1], item, 'observation')
                    for item in self.data['observations']] + ([Row('Explained findings',self.data['findings'],'findings')]
                    if self.data.get('findings') else []) + ([Row('Socket snapshot',self.data['sockets'],'socket_snapshot')]
                    if 'sockets' in self.data else []) + [Row('Full report', self.data)]
        keys = ('security_analysis', 'ssh_analysis', 'firewall_analysis') if self.page == 3 else (
            'findings', 'timeline', 'reconstruction', 'journal_records', 'security_analysis',
            'ssh_analysis', 'firewall_analysis', 'event_search', 'atop', 'pstore', 'pstore_archive')
        return [summary]+[Row(VIEW_NAMES.get(key,key), self.data[key],
            'findings' if key=='findings' else 'timeline' if key=='timeline' else 'crash_source' if key in {'pstore','pstore_archive'} else 'recording' if key=='atop' else 'event_search' if key=='event_search' else 'analysis'
            if key in {'ssh_analysis','firewall_analysis','security_analysis'} else 'inspect') for key in keys if key in self.data] + [Row('Full report', self.data)]

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
            value=row.value
            context=row.action
            if row.action=='timeline_entry':
                from .evidence_links import timeline_finding
                context='inspect'
                finding=None if inspect_only else timeline_finding(self.data,self.value,row.value)
                if finding is not None:
                    value,context=finding,'finding'
                    self.notice='Timeline finding opened within its original source. Temporal order does not establish cause.'
                elif not inspect_only:
                    self.notice='Timeline reference could not be resolved uniquely in this source. Original metadata is shown; no finding was guessed.'
            if row.action=='observation':
                from .presentation import observation_view
                value=observation_view(value)
                if row.value['key']=='network.interfaces' and isinstance(row.value['value'],list):
                    value['Interface samples']=row.value['value']
            elif row.action=='interface_sample':
                if inspect_only:
                    context='inspect'
                else:
                    from .interface_presentation import interface_view
                    value=interface_view(value,self.data['sample'])
            elif row.action=='boot_summary':
                if inspect_only:
                    context='inspect'
                else:
                    from .presentation import boot_summary_view
                    value=boot_summary_view(value)
                    value['Diagnose this boot']=row.value['boot']
            elif row.action in {'socket_snapshot','socket_row'}:
                if inspect_only:
                    context='inspect'
                else:
                    from .socket_presentation import snapshot_view,row_view
                    value=(snapshot_view if row.action=='socket_snapshot' else row_view)(value)
                    if row.action=='socket_snapshot': value['Socket rows']=row.value['rows']
            elif row.action in {'recording','recording_sample'}:
                if inspect_only:
                    context='inspect'
                else:
                    from .recording_presentation import recording_view,sample_view
                    value=(recording_view if row.action=='recording' else sample_view)(value)
                    if row.action=='recording':
                        value['Retained samples']=row.value['samples']
                        value['Reported coverage']=row.value.get('coverage')
            elif row.action in {'crash_source','crash_record'}:
                if inspect_only:
                    context='inspect'
                else:
                    from .crash_presentation import source_view,record_view
                    value=(source_view if row.action=='crash_source' else record_view)(value)
                    if row.action=='crash_source': value['Retained fragments']=row.value['records']
            elif context=='finding':
                from .presentation import finding_view
                from .evidence_links import resolve
                finding=value
                value=finding_view(value)
                value['Referenced source evidence']=resolve(self.data,finding)
                if row.action=='timeline_entry': value['Timeline position']=row.value
            self.stack.append((value, row.label, self.selected, self.scroll, context))
            self.selected, self.scroll = 0, 0

    def back(self):
        if self.stack:
            frame=self.stack.pop()
            self.selected,self.scroll=frame[2:4]

    def find(self, text=None, *, reverse=False, width=80):
        """Find literal displayed text in this view, without filtering or walking evidence trees."""
        fresh = text is not None
        if fresh:
            if not isinstance(text,str) or len(text)>64 or any(not 32<=ord(c)<=126 for c in text):
                raise ValueError('Search requires at most 64 printable ASCII characters')
            self.search_text = text
        if not self.search_text:
            self.notice = 'Search cleared. Press / to find literal text in the current view.'
            return
        query = self.search_text.lower()
        direction = -1 if reverse else 1
        if self.stack and not isinstance(self.value,(dict,list)):
            width = max(1,min(240,width))
            value = escaped(self.value).lower()
            boundary = min(len(value),self.scroll*width)
            if fresh:
                match = value.find(query)
            elif reverse:
                match = value.rfind(query,0,boundary+len(query)-1)
                if match<0: match = value.rfind(query)
            else:
                match = value.find(query,boundary+width)
                if match<0: match = value.find(query)
            if match>=0: self.scroll = match//width
        else:
            rows = self.rows()
            match = -1
            start = 0 if fresh else self.selected+direction
            for offset in range(len(rows)):
                index = (start+direction*offset)%len(rows)
                row = rows[index]
                value = row_preview(row) if isinstance(row.value,(dict,list)) else row_preview(row)+' '+escaped(row.value)
                if query in (row.label+' '+value).lower():
                    match = index
                    self.selected = index
                    break
        self.notice = ('Match in current view; n/N moves between matching rows or scalar lines (wraps).'
                       if match>=0 else 'No match in this view. Open an object or original value to search inside it.')

    def help(self):
        if len(self.stack) >= 64:
            self.notice = 'Navigation depth limit reached; use Left to return.'
            return
        guide = {
            'Navigation': '1-8 or Tab choose pages; Up/Down, j/k, PageUp/PageDown, Home/End move. Enter opens, Left returns. q quits.',
            'Collection': 'r replaces the current snapshot on source pages only. No automatic polling. Ctrl-C interrupts collection and restores the terminal.',
            'Evidence': 'Enter drills into every object/list/scalar. On a timeline entry it opens the referenced explained finding; e keeps the original timeline metadata. Long values are paged in lossless ASCII JSON form. e also inspects boot metadata; t opens only the main retained timeline. Filtered timelines remain separate inside their source views.',
            'Search': '/ enters up to 64 printable ASCII characters; Enter finds, Esc cancels, Ctrl-U clears. n/N finds the next/previous matching row or scalar line, wrapping at the ends. Literal case-insensitive search covers current row labels/previews and full direct scalar values, or the open escaped scalar. It does not filter rows, search unopened trees, collect data or interpret regular expressions.',
            'Settings': 'Session only; no system configuration or report writes. Enter toggles booleans or edits values. Esc cancels an edit; Ctrl-U clears it.',
            'Explained views': 'Enter opens readable measurements, findings, boot summaries, interface samples, sockets, recording samples and crash fragments. Technical details retains original data. Known source views offer raw metadata through e; Full report and Evidence Explorer remain raw trees.',
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
            self.stack = [(self.data['timeline'], 'Retained boot-local timeline', self.selected, self.scroll, 'timeline')]
            self.selected, self.scroll = 0, 0
            self.notice = 'Main retained timeline only; filtered timelines remain inside their source views.'
