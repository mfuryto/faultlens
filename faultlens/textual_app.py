"""UserDock-style tabs, domain tables and dialogs for read-only diagnostics."""
import asyncio
import argparse
from dataclasses import asdict,replace
import json
import os

# Environment-driven developer endpoints and logs are outside this local-only UI.
for _key in list(os.environ):
    if _key.startswith('TEXTUAL'): os.environ.pop(_key,None)

from rich.text import Text
from textual.app import App,ComposeResult
from textual.binding import Binding
from textual.containers import Vertical,VerticalScroll,Horizontal,Grid
from textual.screen import ModalScreen
from textual.widgets import Header,Footer,Static,DataTable,TabbedContent,TabPane,Button,Input
from textual import constants

constants.LOG_FILE=None
constants.DRIVER=None

from . import __version__
from .tui_model import Session,Settings,escaped,brief
from .workspace import TABS,page_table,source_table,detail_text,collection_entry,Entry
from .presentation import guide
from .evidence_links import resolve
from . import ui_collection


def literal(value):
    styles={'critical':'bold red','warning':'yellow','unavailable':'dim','partial':'yellow',
            'Allowed':'green','Blocked':'bold red','Source dependent':'yellow','Address/interface dependent':'yellow','Unresolved':'yellow','No INPUT chains':'cyan',
            'Interface dependent':'yellow','Source/interface dependent':'yellow',
            'available':'green','normal':'green','Critical':'bold red','Review':'yellow','Gap':'yellow','Partial':'yellow','Measured':'cyan','Confirmed':'cyan','Possible':'yellow','Unknown':'dim'}
    return Text(json.dumps(str(value),ensure_ascii=True)[1:-1],style=styles.get(str(value),''))


class WorkspaceTabs(TabbedContent):
    """Keep explicit tab selection ahead of stale focus and activation messages."""
    def on_tabs_tab_activated(self,event):
        if event.tabs.parent is self and event.tab.id!=event.tabs.active:
            event.prevent_default()
            event.stop()

    def on_tab_pane_focused(self,event):
        if event.tab_pane.id!=self.active:
            event.prevent_default()
            event.stop()


class ActionBar(Grid):
    """Aligned buttons in one row when space permits, wrapping in narrow terminals."""
    def on_mount(self):self.fit_buttons()
    def on_resize(self,event):self.fit_buttons()
    def fit_buttons(self):
        buttons=list(self.query(Button))
        if not buttons:return
        width=max(8,max(len(str(button.label))+2 for button in buttons))
        columns=max(1,min(len(buttons),(self.size.width+1)//(width+1)))
        self.styles.grid_size_columns=columns
        self.styles.height=(len(buttons)+columns-1)//columns


class RawDialog(ModalScreen):
    """Secondary raw evidence browser; source values remain referenced, not copied."""
    BINDINGS=[Binding('escape','back','Back'),Binding('q','dismiss','Close')]

    def __init__(self,value,title='Original evidence'):
        super().__init__(); self.value=value; self.title_text=title; self.history=[]; self.children_values=[]

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(literal(self.title_text),classes='dialog-title')
            yield DataTable(id='raw-table',cursor_type='row',zebra_stripes=True)
            with VerticalScroll(id='raw-scalar'):
                yield Static('',id='scalar-value',markup=False)
            yield Static('Enter opens | Esc returns | q closes | Original values use lossless JSON escaping',classes='hint')

    def on_mount(self): self.populate()

    def populate(self):
        table=self.query_one('#raw-table',DataTable); table.clear(columns=True)
        container=self.query_one('#raw-scalar'); structured=isinstance(self.value,(dict,list))
        table.display=bool(structured); container.display=not structured
        if structured:
            table.add_columns('Field / index','Retained value')
            items=list(self.value.items()) if isinstance(self.value,dict) else list(enumerate(self.value))
            self.children_values=[value for key,value in items]
            for index,(key,value) in enumerate(items):
                table.add_row(literal(key),Text(brief(value)),key=str(index))
            table.focus()
        else:
            self.query_one('#scalar-value',Static).update(Text(escaped(self.value)))
            container.focus()

    def on_data_table_row_selected(self,event):
        event.stop()
        if len(self.history)>=64: return
        index=int(event.row_key.value)
        self.history.append(self.value); self.value=self.children_values[index]; self.populate()

    def action_back(self):
        if self.history: self.value=self.history.pop(); self.populate()
        else: self.dismiss()


class DetailDialog(ModalScreen):
    BINDINGS=[Binding('escape','dismiss','Close'),Binding('e','original','Original evidence'),Binding('v','evidence','Evidence'),
              Binding('p','position','Timeline position')]

    def __init__(self,entry,data):
        super().__init__(); self.entry=entry; self.data=data

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(literal(self.entry.cells[0]),classes='dialog-title')
            with VerticalScroll(): yield Static(Text(detail_text(self.entry.detail or {})),markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Original',id='original')
                if self.entry.kind=='finding': yield Button('Records',id='references')
                if self.entry.kind=='service_message': yield Button('Context',id='service-context',variant='primary')
                if self.entry.kind=='socket':yield Button('Reported owners',id='socket-owners')
                if self.entry.kind=='network_issue':
                    yield Button('Investigate logs',id='network-logs')
                    if self.entry.original.get('candidate_indices'):yield Button('Referenced records',id='network-records')
                    if self.entry.original.get('socket_indices'):yield Button('Socket rows',id='network-sockets')
                if self.entry.kind=='process' and self.entry.original.get('service'):
                    yield Button('Reported service',id='process-service')
                if 'Timeline position' in (self.entry.detail or {}): yield Button('Position',id='position')
                if self.entry.kind=='boot': yield Button('Investigate this boot',id='select-boot',variant='primary')
                yield Button('Close',id='close')
            with ActionBar(classes='buttons'):
                yield Button('Evidence',id='pin-evidence')
                if self.entry.kind=='history_event':
                    yield Button('Investigate period',id='history-period')
                    if self.entry.navigation.get('record') is not None:yield Button('Recorded message',id='history-record')
            if self.entry.kind in {'port','port_translation'}:
                with ActionBar(classes='buttons'):
                    yield Button('Policy',id='port-policy');yield Button('Addresses',id='port-addresses');yield Button('Routes',id='port-routes')
                with ActionBar(classes='buttons'):
                    yield Button('External check',id='port-external')
                    if self.entry.kind=='port' and any(owner.get('service') for owner in self.entry.original['owners']):yield Button('Reported service',id='port-service')
                    if self.entry.kind=='port_translation':yield Button('Target sockets',id='port-targets')
            if self.entry.kind in {'firewall_ban','firewall_chain','firewall_jail'}:
                with ActionBar(classes='buttons'):
                    if self.entry.kind in {'firewall_ban','firewall_chain'}:yield Button('Matching rules' if self.entry.kind=='firewall_ban' else 'Chain rules',id='firewall-matches')
                    if self.entry.kind in {'firewall_ban','firewall_jail'}:yield Button('Related logs',id='firewall-logs')
                    if self.entry.kind=='firewall_jail':yield Button('Reported bans',id='firewall-bans')
            if self.entry.kind=='service_message':
                with ActionBar(classes='buttons'):
                    yield Button('Investigate period',id='service-period')
                    yield Button('Current Network' if self.entry.navigation['current_page']==2 else 'Current System',id='service-current')

    def action_evidence(self):self.app.show_evidence(self.entry,self.data)
    def action_original(self): self.app.push_screen(RawDialog(self.entry.original))
    def action_position(self):
        if 'Timeline position' in (self.entry.detail or {}):
            self.app.push_screen(RawDialog(self.entry.detail['Timeline position'],'Original timeline position'))

    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='pin-evidence':self.action_evidence()
        elif event.button.id in {'port-policy','port-addresses','port-routes','port-targets'}:
            from .port_presentation import view
            kind='ports_listeners' if event.button.id=='port-targets' else 'ports_'+event.button.id.removeprefix('port-')
            self.app.push_screen(SourceDialog(Entry(('Related port evidence',),self.data,view(self.data),kind,navigation=self.entry.navigation),self.data))
        elif event.button.id=='port-external':
            from .port_presentation import external_check
            self.app.push_screen(DetailDialog(Entry(('External verification',),self.entry.original,external_check(self.entry.original if self.entry.kind=='port' else None)),self.data))
        elif event.button.id=='port-service':
            units=sorted({owner['service'] for owner in self.entry.original['owners'] if owner.get('service')})
            self.app.push_screen(SourceDialog(Entry(('Reported services',),{'state':'reported','rows':units},kind='port_services'),self.data))
        elif event.button.id in {'firewall-matches','firewall-bans'}:
            from .firewall_presentation import view
            kind='firewall_rules' if event.button.id=='firewall-matches' else 'firewall_bans'
            self.app.push_screen(SourceDialog(Entry(('Related firewall evidence',),self.data,view(self.data),kind,navigation=self.entry.navigation),self.data))
        elif event.button.id=='firewall-logs':
            from .firewall_rules import network
            subject=self.entry.navigation;records=[]
            for record in self.data['records']:
                event_data=record.get('observation')
                if not event_data or event_data['jail']!=subject['jail']:continue
                if subject.get('address') and event_data['address'] is not None and network(event_data['address'])!=network(subject['address']):continue
                records.append(record)
            self.app.push_screen(RecordsDialog(self.data,records=records))
        elif event.button.id=='history-record':
            self.app.push_screen(RecordsDialog(self.data,record=self.entry.navigation['record']))
        elif event.button.id=='history-period':
            from .investigation_flow import period
            window=period(self.entry.navigation['reference'])
            if window is None:self.app.notice='No usable receipt time was retained; no period was guessed.';self.app.update_status();return
            self.app.set_inquiry_anchor(self.entry,self.data)
            while len(self.app.screen_stack)>1:self.app.pop_screen()
            self.app.start_investigation('period',start=window[0],end=window[1],preserve_anchor=True)
        elif event.button.id=='original': self.action_original()
        elif event.button.id=='position': self.action_position()
        elif event.button.id=='references': self.app.push_screen(RecordsDialog(self.data,self.entry.original))
        elif event.button.id=='socket-owners':
            self.app.push_screen(SourceDialog(Entry(('Reported owners',),{'state':self.entry.original.get('owner_state','not_established'),'rows':self.entry.original.get('owners',[])},kind='socket_owners'),self.data))
        elif event.button.id=='network-records':
            source=self.data.get(self.entry.original.get('source_key'),{})
            records=source.get('records',[])
            self.app.push_screen(RecordsDialog(self.data,records=[records[index] for index in self.entry.original['candidate_indices'] if type(index) is int and 0<=index<len(records)]))
        elif event.button.id=='network-sockets':
            indices=set(self.entry.original['socket_indices']);source=self.data.get('sockets',{})
            subset=dict(source,rows=[row for row in source.get('rows',[]) if row['row_index'] in indices])
            self.app.push_screen(SourceDialog(Entry(('Referenced socket rows',),subset,kind='sockets'),self.data))
        elif event.button.id=='network-logs':
            self.app.open_network_logs(self.entry.original,data=self.data)
        elif event.button.id=='process-service' and self.entry.kind=='process':
            unit=self.entry.original['service']
            self.app.push_screen(ServiceDialog(Entry((unit,),{'unit':unit},None,'service'),self.data))
        elif event.button.id=='service-context' and self.entry.kind=='service_message':
            index=self.entry.navigation['record_index']
            self.app.push_screen(RecordsDialog(self.data,records=self.data['journal_records'][max(0,index-3):index+4]))
        elif event.button.id in {'service-period','service-current'} and self.entry.kind=='service_message':
            from .service_diagnostics import followup_window
            start,end=followup_window(self.entry.original)
            app=self.app;target=self.entry.navigation['current_page']
            while len(app.screen_stack)>1:app.pop_screen()
            if event.button.id=='service-period':
                app.set_inquiry_anchor(self.entry,self.data)
                app.start_investigation('period',start=start,end=end,preserve_anchor=True)
                app.notice='Selected two minutes around a service journal receipt time. Journal scope uses Settings; temporal proximity is not causality.'
                app.update_status()
            else:
                app.set_inquiry_anchor(self.entry,self.data)
                for cache in (app.snapshots,app.snapshot_options,app.collection_attempts):cache.pop(target,None)
                app.select_page(target)
                app.notice='Collect current readings for comparison; they do not establish conditions at the earlier service error.'
                app.update_status();app.call_later(app.ensure_snapshot)
        elif event.button.id=='select-boot':
            self.app.set_inquiry_anchor(self.entry,self.data)
            source=self.entry.original; boot=source.get('boot',source)
            self.app.session.update_setting('boot_selector',boot['boot_id'])
            if self.app.session.settings.investigation_mode:
                self.app.session.update_setting('investigation_mode','now' if boot.get('index')==0 else 'before-restart')
            self.app.snapshots.pop(5,None)
            self.app.snapshot_options.pop(5,None)
            self.app.collection_attempts.pop(5,None)
            self.dismiss(); self.app.select_page(5)
            self.app.persist_settings()
            self.app.notice='Optional boot filter selected. Investigate loads the explicitly selected context.'; self.app.update_status()
        else: self.dismiss()


class ServiceDialog(ModalScreen):
    """Load one selected unit on entry; cancellation reaps its isolated CLI worker."""
    BINDINGS=[Binding('escape','back','Back'),Binding('r','retry','Refresh'),Binding('p','problems','Messages'),
              Binding('e','original','Original fields')]

    def __init__(self,entry,data):
        super().__init__(); self.entry=entry; self.data=data
        self.report=None; self.collection_task=None

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(literal(self.entry.original['unit']),classes='dialog-title')
            with VerticalScroll():
                yield Static('Loading service status and current-boot unit logs...',id='service-explanation',markup=False)
            yield Static('Read-only system service query; existing access only. r refreshes; Esc returns.',classes='hint',markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Messages',id='service-messages',disabled=True,variant='primary')
                yield Button('Logs',id='service-logs',disabled=True)
                yield Button('Original fields',id='service-original',disabled=True)
                yield Button('Back',id='service-back')
            with ActionBar(classes='buttons'):yield Button('Evidence',id='service-evidence',disabled=True)

    def on_mount(self): self.action_retry()

    def action_retry(self):
        if self.collection_task is not None: return
        self.report=None
        self.query_one('#service-explanation',Static).update('Loading service status and current-boot unit logs...')
        for name in ('service-messages','service-logs','service-original','service-evidence'): self.query_one('#'+name,Button).disabled=True
        self.collection_task=asyncio.create_task(self.load_service())

    async def load_service(self):
        try:
            from .service import view
            value=await self.app.service_collector(self.entry.original['unit'])
            explanation=Text(detail_text(view(value)))
            self.query_one('#service-explanation',Static).update(explanation)
            self.report=value
            self.query_one('#service-messages',Button).disabled=not value['journal_records']
            self.query_one('#service-logs',Button).disabled=not value['journal_records']
            self.query_one('#service-original',Button).disabled=False
            self.query_one('#service-evidence',Button).disabled=False
            self.query_one('#service-messages' if value['journal_records'] else '#service-original',Button).focus()
        except asyncio.CancelledError: raise
        except (OSError,ValueError,TimeoutError):
            self.query_one('#service-explanation',Static).update('Service investigation unavailable within collection limits. No fault or absence of faults was established. r retries; Esc returns.')
        except Exception:
            self.query_one('#service-explanation',Static).update('Service investigation failed unexpectedly. No replacement evidence was retained. Use the explicit service CLI command to check the source.')
        finally: self.collection_task=None

    async def on_unmount(self):
        if self.collection_task is not None:
            task=self.collection_task;task.cancel()
            await asyncio.gather(task,return_exceptions=True)

    def action_back(self): self.dismiss()
    def action_original(self):
        if self.report is not None: self.app.push_screen(RawDialog(self.report,'Original service status and unit logs'))
    def action_problems(self):
        if self.report is not None:
            from .workspace import Entry
            self.app.push_screen(SourceDialog(Entry(('Service messages',),self.report,None,'service_messages'),self.report))
    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='service-messages':self.action_problems()
        elif event.button.id=='service-logs' and self.report is not None:
            self.app.push_screen(RecordsDialog(self.report,records=self.report['journal_records']))
        elif event.button.id=='service-original': self.action_original()
        elif event.button.id=='service-evidence' and self.report is not None:
            from .service import view
            entry=Entry((self.report['unit']+' — retained service messages',),self.report,view(self.report),'service_messages')
            self.app.show_evidence(entry,self.report)
        else: self.dismiss()


class SshStatisticsDialog(ModalScreen):
    """One cancellable SSH query with retained source/time context."""
    time_windows=True
    domain='ssh';report_heading='SSH authentication history';default_window='boot'
    snapshot_key='ssh_snapshot';collector_key='ssh_collector';report_kind='ssh_report'
    groups=((('Usernames','users'),('Peers','peers'),('Times','timeline')),(('Records','records'),('Original','original'),('Evidence','evidence')))
    BINDINGS=[Binding('escape','dismiss','Back'),Binding('r','refresh','Refresh'),Binding('e','original','Original')]

    def __init__(self):
        super().__init__();self.report=None;self.collection_task=None;self.active_read=None;self.pending=None;self.generation=0
        self.options={'window':self.default_window,'since_us':None,'until_us':None}

    def report_view(self):
        from .ssh_presentation import view
        return view(self.report)

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(self.report_heading+' — read-only',classes='dialog-title',markup=False)
            windows=((('Since boot','boot'),('Last hour','hour')),(('Last day','day'),('Period','period'))) if self.time_windows else ()
            if windows:
                with ActionBar(classes='buttons'):
                    for options in windows:
                        for label,key in options:yield Button(label,id=self.domain+'-'+key)
            with VerticalScroll():yield Static('Reading '+self.report_heading+' within source bounds; Esc cancels and returns.',id=self.domain+'-explanation',markup=False)
            with ActionBar(classes='buttons'):
                for options in self.groups:
                    for label,key in options:yield Button(label,id=self.domain+'-'+key,disabled=True)
            with ActionBar(classes='buttons'):
                yield Button('Refresh',id=self.domain+'-refresh');yield Button('Back',id=self.domain+'-back')

    def on_mount(self):
        if getattr(self.app,self.snapshot_key) is not None:
            self.report=getattr(self.app,self.snapshot_key)
            if self.time_windows:
                self.options={key:self.report[key] if key=='window' else self.report['requested_window'][key.replace('_us','_realtime_us')] for key in self.options}
                if self.options['window']!='period':self.options.update(since_us=None,until_us=None)
            self.present()
        else:self.action_refresh()

    def present(self):
        self.query_one('#'+self.domain+'-explanation',Static).update(Text(detail_text(self.report_view())))
        for key in (key for group in self.groups for _,key in group):self.query_one('#'+self.domain+'-'+key,Button).disabled=False
        if self.time_windows:
            for key in ('boot','hour','day','period'):self.query_one('#'+self.domain+'-'+key,Button).variant='primary' if self.options['window']==key else 'default'

    def action_refresh(self):
        self.generation+=1;self.report=None;setattr(self.app,self.snapshot_key,None)
        for key in (key for group in self.groups for _,key in group):self.query_one('#'+self.domain+'-'+key,Button).disabled=True
        self.query_one('#'+self.domain+'-explanation',Static).update('Reading '+self.report_heading+' within source bounds; Esc cancels and returns. No previous result is substituted on failure.')
        self.pending=(dict(self.options,system_journal=self.app.session.settings.system_journal) if self.time_windows else {},self.generation)
        if self.active_read is not None and not self.active_read.done() and not self.active_read.cancelling():self.active_read.cancel()
        if self.collection_task is None or self.collection_task.done():self.collection_task=asyncio.create_task(self.load())

    async def load(self):
        while self.pending is not None:
            options,generation=self.pending;self.pending=None
            self.active_read=asyncio.create_task(getattr(self.app,self.collector_key)(**options))
            try:
                value=await asyncio.shield(self.active_read)
                if generation!=self.generation:continue
                self.report=value;setattr(self.app,self.snapshot_key,value);self.present()
            except asyncio.CancelledError:
                if not self.active_read.done() and not self.active_read.cancelling():self.active_read.cancel()
                await asyncio.gather(self.active_read,return_exceptions=True)
                if self.pending is None:raise
            except Exception:
                if generation==self.generation and self.is_mounted:
                    self.query_one('#'+self.domain+'-explanation',Static).update(self.report_heading+' unavailable. No assessment could be established. r retries; Esc returns. The explicit '+self.domain+' CLI command can explain source availability.')
            finally:self.active_read=None

    async def on_unmount(self):
        self.pending=None
        if self.collection_task is not None:
            self.collection_task.cancel();await asyncio.gather(self.collection_task,return_exceptions=True)

    def action_original(self):
        if self.report is not None:self.app.push_screen(RawDialog(self.report,'Original '+self.report_heading+' report'))

    def on_button_pressed(self,event):
        event.stop();key=event.button.id.removeprefix(self.domain+'-')
        if key in {'boot','hour','day'}:
            self.options={'window':key,'since_us':None,'until_us':None};self.action_refresh()
        elif key=='period':
            def select(start,end):
                self.options={'window':'period','since_us':start,'until_us':end};self.action_refresh()
            self.app.push_screen(PeriodDialog(self.options['since_us'],self.options['until_us'],select))
        elif key=='refresh':self.action_refresh()
        elif key=='back':self.dismiss()
        elif key=='original':self.action_original()
        elif self.report is not None:
            if key=='external':
                from .port_presentation import external_check
                self.app.push_screen(DetailDialog(Entry(('External verification',),None,external_check()),self.report))
            elif key=='records':self.app.push_screen(RecordsDialog(self.report,records=self.report['records']))
            elif key=='evidence':self.app.show_evidence(Entry((self.report_heading,),self.report,self.report_view(),self.report_kind),self.report)
            else:self.app.push_screen(SourceDialog(Entry((self.report_heading+' / '+key,),self.report,self.report_view(),self.domain+'_'+key),self.report))


class FirewallDialog(SshStatisticsDialog):
    """Firewall snapshots and Fail2ban evidence share bounded serial collection."""
    domain='firewall';report_heading='Firewall and Fail2ban';default_window='day'
    snapshot_key='firewall_snapshot';collector_key='firewall_collector';report_kind='firewall_report'
    groups=((('Rules','rules'),('Chains','chains'),('Sets','sets')),
            (('Jails','jails'),('Bans','bans'),('Sources','sources')),
            (('Records','records'),('Original','original'),('Evidence','evidence')))

    def report_view(self):
        from .firewall_presentation import view
        return view(self.report)


class PortsDialog(SshStatisticsDialog):
    """Explicit current binding/policy inquiry; no history selectors or remote probes."""
    time_windows=False;domain='ports';report_heading='Port accessibility'
    snapshot_key='ports_snapshot';collector_key='ports_collector';report_kind='ports_report'
    groups=((('Ports','listeners'),('Forwarding','translations'),('Sources','sources')),
            (('External check','external'),('Original','original'),('Evidence','evidence')))

    def report_view(self):
        from .port_presentation import view
        return view(self.report)


class RecordsDialog(ModalScreen):
    """Readable, scrollable source messages; exact retained objects remain available."""
    BINDINGS=[Binding('escape','dismiss','Back'),Binding('e','original','Original fields'),Binding('v','evidence','Evidence'),
              Binding('ctrl+right','next_records','Next records'),Binding('ctrl+left','previous_records','Previous records')]

    def __init__(self,data,finding=None,*,record=None,records=None):
        super().__init__()
        from .investigation import linked_records
        self.records=records if records is not None else [record] if record is not None else linked_records(data,finding)
        self.data=data
        self.record_offset=0
        self.linkage=records if records is not None else resolve(data,finding) if finding is not None else record

    def messages(self):
        from .investigation import utc
        if not self.records:
            yield Static('No original record resolved. Original fields retain reference details; no source message is guessed.',markup=False)
        for record in self.records[self.record_offset:self.record_offset+16]:
            if 'message' in record:
                metadata=record.get('metadata',{})
                text=utc(record['reference'].get('realtime_us'))+' | '+str(metadata.get('comm',''))+' | PID '+str(metadata.get('pid',''))
                if record.get('reported_local_time'):text='Reported local '+record['reported_local_time']+' | timezone / boot unverified'
                yield Static(literal(text),markup=False)
                yield Static(literal(record['message']),markup=False)
                if record.get('observation'):yield Static(literal(record['observation']['meaning']),markup=False)
            else:
                from .recording_presentation import sample_view
                yield Static(Text(detail_text(sample_view(record))),markup=False)

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static('Recorded source evidence',classes='dialog-title',markup=False)
            with VerticalScroll(id='readable-records'): yield from self.messages()
            yield Static('',id='record-position',classes='hint',markup=False)
            yield Static('Receipt time may differ from event time. e opens complete original fields; Esc returns.',classes='hint',markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Previous',id='record-previous'); yield Button('Next',id='record-next')
                yield Button('Original fields',id='original'); yield Button('Back',id='back')
            with ActionBar(classes='buttons'):yield Button('Evidence',id='pin-evidence')

    def on_mount(self): self.position()
    def position(self):
        self.query_one('#record-position',Static).update('Retained records '+str(self.record_offset+1 if self.records else 0)+'–'+str(min(self.record_offset+16,len(self.records)))+' of '+str(len(self.records))+'. Reports can overlap; no independent corroboration is inferred.')
        self.query_one('#record-previous',Button).disabled=self.record_offset==0
        self.query_one('#record-next',Button).disabled=self.record_offset+16>=len(self.records)
    def action_evidence(self):
        entry=Entry(('Referenced records',),self.records,{'What it means':'These exact retained records keep their original source context.'},'retained_records')
        self.app.show_evidence(entry,self.data)
    def action_original(self): self.app.push_screen(RawDialog(self.linkage,'Complete source references and originals'))
    async def change_records(self,step):
        self.record_offset=max(0,min(max(0,(len(self.records)-1)//16*16),self.record_offset+step))
        container=self.query_one('#readable-records',VerticalScroll)
        await container.remove_children(); await container.mount(*self.messages()); container.scroll_home(animate=False); self.position()
    async def action_next_records(self): await self.change_records(16)
    async def action_previous_records(self): await self.change_records(-16)
    async def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='pin-evidence':self.action_evidence()
        elif event.button.id=='original': self.action_original()
        elif event.button.id=='record-next': await self.action_next_records()
        elif event.button.id=='record-previous': await self.action_previous_records()
        else: self.dismiss()


class SourceDialog(ModalScreen):
    BINDINGS=[Binding('escape','dismiss','Back'),Binding('e','original','Original source'),
              Binding('v','evidence','Evidence'),Binding('ctrl+right','next_page','Next records'),Binding('ctrl+left','previous_page','Previous records'),
              Binding('s','summary','Source summary')]
    PAGE_SIZE=64

    def __init__(self,entry,data):
        super().__init__(); self.entry=entry; self.data=data
        self.heading,self.columns,self.entries=source_table(entry,data)
        self.page_offset=0

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(literal(self.heading),classes='dialog-title')
            state=self.entry.original.get('state','retained') if isinstance(self.entry.original,dict) else 'retained report group'
            hint='Source state: '+str(state)+' | Bounded evidence; no complete-health verdict'
            if self.entry.kind=='ports_listeners':hint='Collected INPUT policy for new TCP/UDP flows; open a port for conditions and source coverage. Internet reachability has not been tested.'
            yield Static(literal(hint),classes='hint')
            yield DataTable(id='source-table',cursor_type='row',zebra_stripes=True)
            empty='No session rows reported; this does not establish that nobody is logged in. s explains coverage.' if self.entry.kind=='login_sessions' else 'No rows in this view. Events may still exist; s explains coverage, e opens originals.'
            if (self.entry.navigation or {}).get('network_context_source'):
                detail=self.entry.detail or {}
                empty=detail.get('What it means',empty)+'\n'+' '.join(detail.get('What you can do',[]))
            yield Static(literal(empty),id='source-empty',classes='hint',markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Previous',id='previous'); yield Button('Next',id='next'); yield Button('Back',id='back')
            with ActionBar(classes='buttons'):yield Button('Evidence',id='pin-evidence')

    def on_mount(self):
        self.rebuild_table()
        self.query_one(DataTable).focus()

    def on_resize(self,event):
        if self.is_mounted and self.entry.kind in {'port_services','ports_report','ports_listeners','ports_translations','ports_policy','ports_addresses','ports_routes','ports_sources','firewall_report','firewall_rules','firewall_chains','firewall_sets','firewall_jails','firewall_bans','firewall_sources','ssh_report','ssh_users','ssh_peers','ssh_timeline','network_issues','network_context','network_addresses','network_routes','network_samples','socket_owners','observations','interfaces','failed_services','scope_details','login_sessions','service_messages','processes','filesystems'}:
            self.call_after_refresh(self.rebuild_table)

    def rebuild_table(self):
        table=self.query_one(DataTable); selected=table.cursor_row; table.clear(columns=True)
        if self.entry.kind in {'port_services','ports_report','ports_listeners','ports_translations','ports_policy','ports_addresses','ports_routes','ports_sources','firewall_report','firewall_rules','firewall_chains','firewall_sets','firewall_jails','firewall_bans','firewall_sources','ssh_report','ssh_users','ssh_peers','ssh_timeline','network_issues','network_context','network_addresses','network_routes','network_samples','socket_owners','observations','interfaces','failed_services','scope_details','login_sessions','service_messages','processes','filesystems'}:
            weights=([.20,.13,.30,.37] if self.entry.kind=='login_sessions' else
                    [.20,.12,.20,.48] if self.entry.kind in {'firewall_sources','ports_sources'} else
                    [0.40,0.12,0.48] if len(self.columns)==3 else [0.28,0.26,0.14,0.32])
            usable=max(12,self.app.size.width-8-2*len(self.columns))
            for column,weight in zip(self.columns,weights): table.add_column(column,width=max(3,int(usable*weight)))
        else: table.add_columns(*self.columns)
        self.populate()
        if table.row_count: table.move_cursor(row=min(selected,table.row_count-1))

    def populate(self):
        table=self.query_one(DataTable); table.clear()
        self.query_one('#source-empty',Static).display=not self.entries
        for index in range(self.page_offset,min(len(self.entries),self.page_offset+self.PAGE_SIZE)):
            table.add_row(*(literal(c) for c in self.entries[index].cells),key=str(index))
        title=self.heading+' | '+str(self.page_offset+1 if self.entries else 0)+'-'+str(min(len(self.entries),self.page_offset+self.PAGE_SIZE))+'/'+str(len(self.entries))
        self.query_one('.dialog-title',Static).update(literal(title))
        self.query_one('#previous',Button).disabled=self.page_offset==0
        self.query_one('#next',Button).disabled=self.page_offset+self.PAGE_SIZE>=len(self.entries)

    def action_next_page(self):
        if self.page_offset+self.PAGE_SIZE<len(self.entries): self.page_offset+=self.PAGE_SIZE; self.populate()
    def action_previous_page(self):
        if self.page_offset: self.page_offset=max(0,self.page_offset-self.PAGE_SIZE); self.populate()
    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='pin-evidence':self.action_evidence()
        elif event.button.id=='next': self.action_next_page()
        elif event.button.id=='previous': self.action_previous_page()
        else: self.dismiss()

    def on_data_table_row_selected(self,event):
        event.stop(); self.app.open_entry(self.entries[int(event.row_key.value)],self.data)

    def action_evidence(self):self.app.show_evidence(self.entry,self.data)
    def action_original(self): self.app.push_screen(RawDialog(self.entry.original))

    def action_summary(self):
        from .workspace import Entry
        from .socket_presentation import snapshot_view
        from .recording_presentation import recording_view
        from .crash_presentation import source_view
        source=self.entry.original
        explain={'sockets':snapshot_view,'atop':recording_view,'pstore':source_view,'pstore_archive':source_view}
        if (self.entry.navigation or {}).get('network_context_source'):detail=self.entry.detail
        elif self.entry.kind in {'port_services','ports_report','ports_listeners','ports_translations','ports_policy','ports_addresses','ports_routes','ports_sources','firewall_report','firewall_rules','firewall_chains','firewall_sets','firewall_jails','firewall_bans','firewall_sources','ssh_report','ssh_users','ssh_peers','ssh_timeline','network_issues','network_context','network_addresses','network_routes','network_samples','socket_owners','observations','interfaces','failed_services','scope_details','login_sessions','service_messages','processes','filesystems'}: detail=self.entry.detail or {'What it means':'Retained source rows only; open an individual row for context.'}
        elif self.entry.kind in explain: detail=explain[self.entry.kind](source)
        else:
            detail={'Source':self.entry.cells[0],'State':source.get('state','retained') if isinstance(source,dict) else 'retained reports',
                'Meaning':'Only retained candidates and supported signatures are shown. No matches is not an all-clear; use original evidence for unclassified records.',
                'Coverage limits':source.get('limitations',[]) if isinstance(source,dict) else ['Counts are reports, not separate incidents.']}
        self.app.push_screen(DetailDialog(Entry((self.heading,),source,detail),self.data))


class PeriodDialog(ModalScreen):
    """Apply both explicit time boundaries atomically; invalid edits save nothing."""
    BINDINGS=[Binding('escape','cancel','Cancel')]

    def __init__(self,start,end,callback):
        super().__init__();self.start,self.end,self.callback=start,end,callback

    def compose(self):
        from .time_window import display,HELP
        with Vertical(classes='edit-dialog'):
            yield Static('Investigate a selected period — boot filter optional',classes='dialog-title',markup=False)
            yield Static(HELP,markup=False)
            yield Input(value=display(self.start) if self.start else '',placeholder='Start with timezone',id='period-start',max_length=64)
            yield Input(value=display(self.end) if self.end else '',placeholder='End with timezone',id='period-end',max_length=64)
            yield Static('Both boundaries are required. Enter applies the complete range.',id='period-validation',markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Investigate period',id='period-apply',variant='primary')
                yield Button('Cancel',id='period-cancel')

    def on_mount(self):self.query_one('#period-start',Input).focus()
    def action_cancel(self):self.dismiss()
    def apply(self):
        from .time_window import parse
        from .journal import validate_window
        try:
            start=parse(self.query_one('#period-start',Input).value)
            end=parse(self.query_one('#period-end',Input).value)
            validate_window(start,end)
        except (ValueError,argparse.ArgumentTypeError):
            self.query_one('#period-validation',Static).update('Use valid start/end with explicit timezone; start must not exceed end. Nothing was saved.')
            return
        self.dismiss();self.callback(start,end)
    def on_input_submitted(self,event):
        event.stop()
        if event.input.id=='period-start':self.query_one('#period-end',Input).focus()
        else:self.apply()
    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='period-apply':self.apply()
        else:self.dismiss()


class ValueDialog(ModalScreen):
    BINDINGS=[Binding('escape','cancel','Cancel')]

    def __init__(self,label,value,callback,*,persistent=False):
        super().__init__(); self.label_text=label; self.value=str(value); self.callback=callback; self.persistent=persistent

    def compose(self):
        with Vertical(classes='edit-dialog'):
            yield Static(literal(self.label_text),classes='dialog-title')
            yield Input(value=self.value,max_length=64,id='value')
            if self.label_text in {'Incident start (date/time)','Incident end (date/time)'}:
                from .time_window import HELP
                yield Static(HELP,markup=False)
            yield Static('Enter applies and saves preferences; Esc cancels.' if self.persistent else 'Session only. Enter applies; Esc cancels.',id='validation',markup=False)
            with ActionBar(classes='buttons'):
                yield Button('Apply',id='apply',variant='primary'); yield Button('Cancel',id='cancel')

    def on_mount(self): self.query_one(Input).focus()
    def action_cancel(self): self.dismiss()
    def on_input_submitted(self,event): event.stop(); self.apply()
    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='apply': self.apply()
        else: self.dismiss()

    def apply(self):
        value=self.query_one(Input).value
        if any(not 32<=ord(c)<=126 for c in value):
            self.query_one('#validation',Static).update('Use printable ASCII; original evidence is never changed.'); return
        try: self.callback(value)
        except (ValueError,argparse.ArgumentTypeError):
            self.query_one('#validation',Static).update('Invalid value; previous setting retained.'); return
        self.dismiss()


class FaultlensApp(App):
    TITLE='Faultlens'
    SUB_TITLE='Local diagnostics | Read-only'
    ENABLE_COMMAND_PALETTE=False
    CSS='''
    Screen { background: $surface; }
    #status-line { height: 1; padding: 0 1; background: $boost; }
    TabPane { padding: 0 1; }
    .summary { height: auto; max-height: 4; color: $text-muted; }
    .current-summary { max-height: 6; }
    .incident-summary { max-height: 8; }
    .selected-evidence { height: 7; max-height: 9; background: $boost; padding: 0 1; }
    DataTable { height: 1fr; }
    .dialog-title { height: auto; max-height: 3; text-style: bold; }
    .hint { height: auto; max-height: 3; color: $text-muted; }
    ModalScreen { align: center middle; background: $background; }
    .dialog { width: 96%; height: 94%; padding: 0 1; border: round $primary; background: $surface; }
    .edit-dialog { width: 90%; max-width: 72; height: auto; max-height: 100%; padding: 0 1; border: round $primary; background: $surface; }
    .edit-dialog #validation { height: 1; }
    .buttons { height: 1; min-height: 1; }
    .buttons Button { height: 1; min-height: 1; border: none; min-width: 6; padding: 0 1; margin-right: 1; }
    .buttons Button { background: $primary-darken-2; color: $text; }
    .buttons Button:hover, .buttons Button:focus { background: $primary; text-style: bold; }
    .buttons Button.-primary { background: $primary; text-style: bold; }
    .buttons Button:disabled { background: $panel; color: $text-disabled; }
    ActionBar.buttons { grid-columns: 1fr; grid-rows: 1; grid-gutter: 0 1; }
    ActionBar.buttons Button { width: 100%; min-width: 0; margin: 0; }
    #raw-scalar { height: 1fr; }
    '''
    BINDINGS=[Binding('q','quit','Quit'),Binding('r','refresh','Refresh'),Binding('enter','open','Open'),
              Binding('e','original','Original'),Binding('v','evidence','Evidence'),Binding('/','search','Search'),Binding('n','next_match','Next match'),
              Binding('N','previous_match','Previous match'),Binding('?','help','Help'),Binding('s','summary','Summary'),
              Binding('left','previous_tab','Previous section',priority=True),
              Binding('right','next_tab','Next section',priority=True),
              Binding('escape','cancel','Cancel collection'),Binding('ctrl+c','interrupt','Interrupt',priority=True)]

    def __init__(self,session=None,collector=None,initial_collect=True,settings_store=None,settings_status='',service_collector=None,ssh_collector=None,firewall_collector=None,ports_collector=None):
        super().__init__(); self.session=session or Session(); self.collector=collector or ui_collection.collect
        if session is None: self.session.settings=Settings.administrator_defaults()
        self.page=0; self.snapshots={}; self.snapshot_options={}; self.entries={}; self.notice=''; self.job=None
        self.table_models={}; self.rendered_tables={}
        self.evidence_selection=None;self.inquiry_anchor=None;self.active_source_page=0;self.keep_inquiry_once=False
        self.initial_collect=initial_collect; self.search_query=''
        self.collection_attempts={}; self.collection_states={}; self.closing=False; self.workspace_ready=False
        self.settings_store=settings_store; self.settings_status=settings_status
        self.service_collector=service_collector or ui_collection.collect_service
        self.ssh_collector=ssh_collector or ui_collection.collect_ssh;self.ssh_snapshot=None
        self.firewall_collector=firewall_collector or ui_collection.collect_firewall;self.firewall_snapshot=None
        self.ports_collector=ports_collector or ui_collection.collect_ports;self.ports_snapshot=None

    def _handle_exception(self,error):
        # Pinned Textual hook: never render exception locals containing admin evidence.
        self._return_code=1
        if self._exception is None:
            self._exception=error; self._exception_event.set()
        self.exit(1)

    def compose(self):
        yield Header(show_clock=False)
        yield Static('Read-only diagnostics; no elevation. User preferences may be saved.',id='status-line',markup=False)
        with WorkspaceTabs(initial='page-0',id='sections'):
            for page,title in enumerate(TABS):
                with TabPane(title,id='page-'+str(page)):
                    if page==0: yield from self.section_widgets(page)
        yield Footer()

    def section_widgets(self,page):
        yield Static('Opening a source section loads its data; r refreshes or retries.',id='summary-'+str(page),classes='summary'+(' current-summary' if page<3 or page in {4,5,6} else '')+(' incident-summary' if page in {5,6} else ''),markup=False)
        yield DataTable(id='grid-'+str(page),cursor_type='row',zebra_stripes=True)
        if page in {3,4,5,6,7}: yield Static('',id='selected-evidence-'+str(page),classes='selected-evidence',markup=False)

    def on_mount(self):
        self.populate(self.page)
        self.query_one('#grid-0',DataTable).focus()
        self.call_after_refresh(self.start_workspace)

    def start_workspace(self):
        self.workspace_ready=True
        self.ensure_snapshot()

    def on_resize(self,event):
        for widget in self.query('.summary'): widget.display=event.size.height>=16
        for widget in self.query('.selected-evidence'): widget.display=event.size.height>=20
        self.call_after_refresh(self.relayout)

    def relayout(self):
        if self.is_running:
            if self.query('#grid-'+str(self.page)): self.populate(self.page)

    def check_action(self,action,parameters):
        if action in {'previous_tab','next_tab','open','refresh','original','evidence','search','next_match','previous_match','help','summary'}:
            return len(self.screen_stack)==1
        return True

    def data(self,page=None):
        page=self.page if page is None else page
        if page==6:return self.evidence_selection.report if self.evidence_selection else self.snapshots.get(5) or self.snapshots.get(self.active_source_page)
        if page==3:return self.snapshots.get(5)
        return self.snapshots.get(page)

    def last_source(self):return 5 if self.snapshots.get(5) is not None else self.active_source_page

    def populate(self,page):
        table=self.query_one('#grid-'+str(page),DataTable); selected=table.cursor_row
        data=self.data(page); options=tuple(asdict(self.session.settings).values())
        cached=self.table_models.get(page)
        if cached is not None and cached[0] is data and cached[1]==options:
            model=cached[2]
        else:
            if page==6 and self.evidence_selection:
                from .investigation_flow import evidence
                model=(('Evidence / finding','State','Retained context','Next step'),evidence(self.evidence_selection,data))
            else:model=page_table(page,data,self.session.settings)
            if page in {3,5,6} and self.inquiry_anchor:
                from .investigation_flow import context,subject
                anchor=self.inquiry_anchor
                anchor_row=Entry(('Inquiry origin',subject(anchor.entry,anchor.report),context(anchor.report),'Open original selection; filters shown in inquiry scope'),anchor.entry.original,
                    {'What it means':'Selected subject retained as navigation context; actual journal filters are shown separately. A service/peer subject alone does not narrow the query.','Scope':context(anchor.report)},'inquiry_origin')
                model=(model[0],[anchor_row,*model[1]])
            self.table_models[page]=(data,options,model)
        columns,entries=model
        if data is None and page<7 and page!=3 and not (page==5 and self.session.settings.investigation_mode): entries=[collection_entry(page,self.collection_states.get(page,'not_collected'))]
        elif data is None and page==5 and self.session.settings.investigation_mode:
            status=collection_entry(page,self.collection_states.get(page,'not_collected'))
            entries=entries[:-1]+[replace(status,cells=(status.cells[0],status.cells[1],status.cells[2],'Choose an inquiry or refresh/retry'))]
        if page==7:
            from .investigation_flow import availability
            entries=[replace(entry,cells=(*entry.cells[:2],entry.cells[2]+' '+availability(entry.original,self.snapshots)),
                detail={**(entry.detail or {}),'Last retained availability':availability(entry.original,self.snapshots)}) for entry in entries]
        if page==3 and data is None and self.collection_states.get(5) in {'loading','failed','cancelled'}:
            state=collection_entry(3,self.collection_states[5])
            entries=[replace(state,cells=(*state.cells,'Inquiry evidence not assessed')),*entries]
        self.entries[page]=entries
        view=(self.size.width,self.collection_states.get(page),self.settings_store is not None)
        rendered=self.rendered_tables.get(page)
        if rendered is None or rendered[0] is not model or rendered[1]!=view:
            table.clear(columns=True)
            visible=list(range(len(columns)))
            if self.size.width<70 and len(columns)>2:
                visible=[0,1,2] if page in {0,1,2,4} else [0,1]
            usable=max(12,self.size.width-6-2*len(visible))
            if len(visible)==3:
                widths=[max(4,int((usable-9)*0.55)),max(4,usable-9-int((usable-9)*0.55)),9]
            else:
                weights=({2:[0.45,0.55],4:[0.25,0.23,0.15,0.37] if page<3 else [0.27,0.19,0.39,0.15] if page in {5,6} else [0.34,0.18,0.18,0.30],5:[0.08,0.18,0.16,0.17,0.41]})[len(visible)]
                widths=[max(4,int(usable*weight)) for weight in weights]
            for index,width in zip(visible,widths): table.add_column(columns[index],width=width)
            for index,entry in enumerate(entries): table.add_row(*(literal(entry.cells[c]) for c in visible),key=str(index))
            if entries: table.move_cursor(row=min(selected,len(entries)-1))
            self.rendered_tables[page]=(model,view)
        if page==7:
            summary=literal('Collection options apply on source entry or refresh; server settings are unchanged.')
            if self.settings_status: summary.append('\n').append(literal(self.settings_status))
            if self.settings_store is not None:
                summary.append('\nPreferences file: ').append(literal(str(self.settings_store.path)))
        elif page==3:
            from .investigation_flow import context
            summary=literal('Signals reuse the selected inquiry: review observations and coverage gaps; no independent collection or attack verdict.')
            if data:summary.append('\n').append(literal(context(data)))
        elif page==6 and self.evidence_selection:
            from .investigation_flow import selected_scope
            summary=literal('Pinned selection: '+self.evidence_selection.entry.cells[0]+' | '+selected_scope(self.evidence_selection))
            summary.append('\nOther tab visits and refreshes do not replace this retained evidence. Use current inquiry explicitly to release it.')
        elif page<3 and data:
            from .current_views import build
            view=build(data,('status','health','network')[page])
            summary=literal(view['summary']); summary.append('\nNext: ').append(literal(view['next_step']))
        elif page in {5,6} and data and data['command'] in {'diagnose','investigate'}:
            from .investigation import story
            view=story(data)
            summary=literal(view['answer']); summary.append('\nScope: ').append(literal(view['scope'])); summary.append('\nNext: ').append(literal(view['next']))
        elif page==4 and data:
            summary=literal('Retained report examples and optional boot sources. Open a report for its original message and receipt-time period; boot identity is not required for a period inquiry. Coverage remains bounded.')
        else:
            summary=literal(guide(data)['Summary'] if data else
                'No retained snapshot. Opening this source section loads data; r refreshes or retries.')
        self.query_one('#summary-'+str(page),Static).update(summary)

    def update_status(self):
        data=self.data(); state='No snapshot' if data is None else data.get('state','observations; no health verdict')
        source_page=(self.evidence_selection.page if self.evidence_selection else self.last_source()) if self.page==6 else 5 if self.page==3 else self.page
        stale=(source_page in self.snapshot_options and self.snapshot_options[source_page]!=asdict(self.session.settings))
        text=TABS[self.page]+' | '+(data['command']+' | ' if data else '')+state+(' | SETTINGS CHANGED: refresh explicitly' if stale else '')
        if data: text+=' | '+str(data.get('collected_at',''))
        self.query_one('#status-line',Static).update(literal(text+' | '+self.notice+(' | '+self.settings_status if self.settings_status else '')))

    def select_page(self,page): self.query_one('#sections',TabbedContent).active='page-'+str(page)
    def action_previous_tab(self): self.select_page((self.page-1)%8)
    def action_next_tab(self): self.select_page((self.page+1)%8)
    async def on_tabbed_content_tab_activated(self,event):
        sections=self.query_one('#sections',TabbedContent)
        if event.tabbed_content is not sections or event.pane.id!=sections.active: return
        page=int(event.pane.id.removeprefix('page-'))
        if not self.query('#grid-'+str(page)):
            await event.pane.mount(*self.section_widgets(page))
        if event.pane.id!=sections.active: return
        if page in {0,1,2,4,5}:self.active_source_page=page
        if page!=self.page: self.page=page; self.populate(self.page)
        self.update_status()
        self.query_one('#grid-'+str(self.page),DataTable).focus()
        self.ensure_snapshot()

    def ensure_snapshot(self):
        if self.query_one('#sections',TabbedContent).active!='page-'+str(self.page): return
        if not self.workspace_ready or not self.initial_collect or self.closing or self.page>=6 or self.job is not None:return
        if self.page==3:
            if self.snapshots.get(5) is None and self.collection_attempts.get(5)!=asdict(self.session.settings):self.action_refresh()
            return
        if self.page==5 and self.keep_inquiry_once and self.snapshots.get(5) is not None:
            self.keep_inquiry_once=False;return
        options=asdict(self.session.settings)
        if self.page in self.snapshots and self.snapshot_options.get(self.page)==options: return
        # Failed/cancelled reads need r to retry; tab events must never create a loop.
        if self.collection_attempts.get(self.page)!=options: self.action_refresh()

    def action_refresh(self):
        if self.job is not None: self.notice='Collection already running. Esc cancels.'; self.update_status(); return
        if self.page>=6: self.notice='This section does not collect. Choose a source section.'; self.update_status(); return
        page=5 if self.page==3 else self.page; options=replace(self.session.settings)
        self.collection_attempts[page]=asdict(options)
        self.collection_states[page]='loading'
        self.snapshots.pop(page,None); self.populate(self.page)
        self.notice='Collecting '+TABS[page]+'... Esc cancels; q exits.'; self.update_status()
        self.job=asyncio.create_task(self.load(page,options))

    async def load(self,page,options):
        cancelled=False
        try:
            value=await self.collector(page,options)
            self.snapshots[page]=value; self.snapshot_options[page]=asdict(options)
            self.table_models.clear()
            self.collection_states[page]='completed'
            self.notice='Snapshot collected. Open a row for meaning and original evidence.'
        except asyncio.CancelledError:
            self.collection_states[page]='cancelled'
            cancelled=True; self.notice='Collection cancelled. Press r to retry; no replacement snapshot retained.'
        except (OSError,ValueError,TimeoutError):
            self.collection_states[page]='failed'
            self.notice='Collection unavailable within source limits; no evidence was guessed.'
        except Exception:
            self.collection_states[page]='failed'
            self.notice='Collection failed unexpectedly. Try the explicit CLI command; no replacement evidence retained.'
        finally:
            self.job=None
            if self.is_running:
                self.populate(self.page); self.update_status()
                if not cancelled: self.call_later(self.ensure_snapshot)

    async def action_cancel(self):
        if self.job is not None:
            self.job.cancel(); await self.job
    async def action_quit(self): self.closing=True; await self.action_cancel(); self.exit(0)
    async def action_interrupt(self): self.closing=True; await self.action_cancel(); self.exit(130)
    async def on_unmount(self): self.closing=True; await self.action_cancel()

    def selected(self):
        entries=self.entries.get(self.page,[]); table=self.query_one('#grid-'+str(self.page),DataTable)
        return entries[table.cursor_row] if entries else None

    def on_data_table_row_highlighted(self,event):
        if len(self.screen_stack)!=1 or self.page not in {3,4,5,6,7} or event.data_table.id!='grid-'+str(self.page): return
        rows=self.entries.get(self.page,[])
        if not rows or not 0<=event.cursor_row<len(rows): return
        entry=rows[event.cursor_row];detail=entry.detail or {}
        text=Text()
        if self.page==7:
            text.append(literal(entry.cells[2]))
        elif self.page==4 and entry.kind=='history_event':
            text.append(literal('Recorded: '+entry.original['time']+' | '+entry.original['message_excerpt']))
            text.append('\nEnter opens the retained message and period actions; a report is not an independent incident.')
        elif self.page==4:
            text.append(literal('Retained UTC: '+str(detail.get('Retained UTC range','Not examined'))))
            for example in detail.get('Recorded examples',[])[:1]: text.append('\nRecorded: ').append(literal(example))
            text.append('\nEnter opens context and Investigate this boot.')
        else:
            lines=detail.get('Recorded evidence',detail.get('Recorded message',[]))
            if isinstance(lines,str):lines=[lines]
            if not lines and entry.kind=='journal_record':
                from .investigation import utc,excerpt
                lines=[utc(entry.original['reference'].get('realtime_us'))+' | '+excerpt(entry.original['message'],2048)]
            for line in lines[:1]: text.append(literal(line))
            meaning=detail.get('What it means','Enter opens full context; original source fields remain available.')
            if isinstance(meaning,str): text.append('\nMeaning: ').append(literal(meaning.split('. ',1)[0]+('.' if '. ' in meaning else '')))
            steps=detail.get('What you can do',[])
            if steps: text.append('\nNext: ').append(literal(steps[0]))
        self.query_one('#selected-evidence-'+str(self.page),Static).update(text)

    def set_inquiry_anchor(self,entry,data):
        from .investigation_flow import Selection
        if entry.context is not None:data=entry.context
        self.inquiry_anchor=Selection(entry,data,self.page)
        self.table_models.clear();self.rendered_tables.clear()

    def show_evidence(self,entry,data):
        from .investigation_flow import Selection
        if entry.context is not None:data=entry.context
        if entry.kind=='investigation_focus':entry=replace(entry,original=data,kind='retained_report')
        table=self.query_one('#grid-'+str(self.page),DataTable)
        origin=(self.evidence_selection.page if self.evidence_selection else self.last_source()) if self.page==6 else self.page
        self.evidence_selection=Selection(entry,data,origin,table.cursor_row)
        while len(self.screen_stack)>1:self.pop_screen()
        self.table_models.pop(6,None);self.rendered_tables.pop(6,None)
        self.select_page(6)
        if self.page==6:self.populate(6)
        self.notice='Evidence selection fixed to its original retained snapshot; no collection started.'
        self.update_status()

    def action_evidence(self):
        entry=self.selected()
        if entry and self.data() is not None and entry.kind!='setting':self.show_evidence(entry,self.data())

    def open_network_logs(self,issue=None,*,data=None):
        issue=issue or {};window=issue.get('window')
        if issue:
            entry=Entry((issue.get('title','Network observation'),),issue)
            self.set_inquiry_anchor(entry,data if data is not None else self.data() or {})
        while len(self.screen_stack)>1:self.pop_screen()
        self.session.settings=replace(self.session.settings,search_ssh=True,search_firewall=True)
        if window:
            self.start_investigation('period',start=max(0,window['since_us']-60000000),end=window['until_us']+60000000,preserve_anchor=bool(issue))
        else:self.start_investigation('now',preserve_anchor=bool(issue))
        self.notice='Network follow-up: journal scope uses Settings; optional boot filter cleared. Inspect original peers/ports and service logs; the query is not peer-filtered.'
        self.update_status()

    def start_investigation(self,mode,*,start=None,end=None,preserve_anchor=False):
        if not preserve_anchor:self.inquiry_anchor=None
        self.table_models.clear()
        self.rendered_tables.clear()
        self.session.settings=replace(self.session.settings,investigation_mode=mode,boot_selector='',
            since_us=str(start) if start is not None else self.session.settings.since_us,
            until_us=str(end) if end is not None else self.session.settings.until_us)
        self.persist_settings()
        self.snapshots.pop(5,None);self.snapshot_options.pop(5,None);self.collection_attempts.pop(5,None)
        if self.page!=5:self.select_page(5)
        elif self.job is None:self.action_refresh()
        else:self.notice='New inquiry selected; waiting for the active read to finish.';self.update_status()

    def setting_changed(self):
        self.persist_settings()
        if self.page==5 and self.session.settings.investigation_mode:
            self.collection_attempts.pop(5,None)
            if self.job is None:self.action_refresh()
            else:self.notice='Filter changed; waiting for the active read to finish.';self.update_status()
        else:self.populate(self.page);self.update_status()

    def action_open(self):
        entry=self.selected()
        if entry: self.open_entry(entry,self.data())
    def on_data_table_row_selected(self,event):
        if len(self.screen_stack)==1: event.stop(); self.action_open()

    def open_entry(self,entry,data):
        if entry.context is not None: data=entry.context
        if entry.kind=='port_accessibility':self.push_screen(PortsDialog());return
        if entry.kind=='firewall_state':self.push_screen(FirewallDialog());return
        if entry.kind in {'port_services','ports_report','ports_listeners','ports_translations','ports_policy','ports_addresses','ports_routes','ports_sources','firewall_report','firewall_rules','firewall_chains','firewall_sets','firewall_jails','firewall_bans','firewall_sources'}:self.push_screen(SourceDialog(entry,data));return
        if entry.kind=='ssh_statistics':self.push_screen(SshStatisticsDialog());return
        if entry.kind in {'ssh_report','ssh_users','ssh_peers','ssh_timeline'}:self.push_screen(SourceDialog(entry,data));return
        if entry.kind=='return_source':
            selection=self.evidence_selection
            if selection:self.select_page(selection.page)
            self.notice='Returned to the source section. Pinned evidence retains its original snapshot even if this section has been refreshed.';self.update_status();return
        if entry.kind=='current_evidence':
            self.evidence_selection=None;self.table_models.pop(6,None);self.rendered_tables.pop(6,None);self.populate(6);self.update_status();return
        if entry.kind=='inquiry_origin':
            if self.inquiry_anchor:self.show_evidence(self.inquiry_anchor.entry,self.inquiry_anchor.report)
            return
        if entry.kind=='investigation_focus':
            self.keep_inquiry_once=self.page!=5 and self.snapshots.get(5) is not None
            self.select_page(5);return
        if entry.kind=='retained_records':self.push_screen(RecordsDialog(data,records=entry.original));return
        if entry.kind=='network_logs':
            self.open_network_logs();return
        if entry.kind=='investigation_start':
            if entry.original=='period':
                self.push_screen(PeriodDialog(self.session.settings.since_us,self.session.settings.until_us,
                    lambda start,end:self.start_investigation('period',start=start,end=end)))
            else: self.start_investigation(entry.original)
            return
        if len(self.screen_stack)>=32: return
        if entry.kind=='finding' and entry.detail is None:
            from .investigation import finding_detail
            entry=replace(entry,detail=finding_detail(data,entry.original))
        if entry.kind=='setting':
            key=entry.original; value=getattr(self.session.settings,key)
            if type(value) is bool:
                self.session.update_setting(key); self.setting_changed()
            else:
                if key in {'since_us','until_us'}:
                    from .time_window import display
                    value=display(value) if value else ''
                def save(text):
                    self.session.update_setting(key,text); self.setting_changed()
                self.push_screen(ValueDialog(entry.cells[0],value,save,persistent=self.settings_store is not None))
        elif entry.kind=='diagnostics_link':
            self.select_page(5)
            self.notice='Investigate uses the selected question/time and optional boot filter.'; self.update_status()
        elif entry.kind=='journal_record': self.push_screen(RecordsDialog(data,record=entry.original))
        elif entry.kind=='service': self.push_screen(ServiceDialog(entry,data))
        elif entry.kind=='raw': self.push_screen(RawDialog(entry.original))
        elif entry.kind in {'port_services','ports_report','ports_listeners','ports_translations','ports_policy','ports_addresses','ports_routes','ports_sources','firewall_report','firewall_rules','firewall_chains','firewall_sets','firewall_jails','firewall_bans','firewall_sources','ssh_report','ssh_users','ssh_peers','ssh_timeline','network_issues','network_context','network_addresses','network_routes','network_samples','socket_owners','retained_report','service_messages','finding_group','sockets','atop','pstore','pstore_archive','ssh_analysis','firewall_analysis','event_search','analysis','timeline','observations','interfaces','failed_services','scope_details','login_sessions','processes','filesystems'}:
            self.push_screen(SourceDialog(entry,data))
        else: self.push_screen(DetailDialog(entry,data))

    def persist_settings(self):
        if self.settings_store is None: return
        try:
            self.settings_store.save(self.session.settings)
            self.settings_status='Preferences saved for this user.'
        except (OSError,ValueError,argparse.ArgumentTypeError):
            self.settings_status='PREFERENCE SAVE NOT CONFIRMED: current session remains active; check configuration access.'

    def action_original(self):
        entry=self.selected()
        if entry and entry.kind!='setting': self.push_screen(RawDialog(entry.original))

    def action_search(self):
        def save(text): self.search_query=text; self.find_match(fresh=True)
        self.push_screen(ValueDialog('Find literal text; rows are not filtered',self.search_query,save))
    def action_next_match(self): self.find_match()
    def action_previous_match(self): self.find_match(reverse=True)
    def find_match(self,fresh=False,reverse=False):
        entries=self.entries.get(self.page,[]); table=self.query_one('#grid-'+str(self.page),DataTable)
        if not self.search_query or not entries: return
        direction=-1 if reverse else 1; start=0 if fresh else table.cursor_row+direction
        for offset in range(len(entries)):
            index=(start+offset*direction)%len(entries)
            if self.search_query.casefold() in ' '.join(entries[index].cells).casefold():
                table.move_cursor(row=index); self.notice='Match in this table; rows remain visible.'; self.update_status(); return
        self.notice='No match in this table.'; self.update_status()

    def action_help(self):
        from .workspace import Entry
        detail={'Navigation':['Left/Right changes main sections; Up/Down selects rows; Enter opens a record or source.',
            'Esc closes a dialog or cancels collection; e opens unchanged original evidence; r explicitly refreshes.',
            'Search moves the table cursor without filtering. q quits; Ctrl-C interrupts and restores the terminal.'],
            'Questions':['Investigate offers Problems now, A selected period, and Before restart. Boot is an optional filter.',
            'Period queries may cross restarts. Current readings cannot establish past conditions.'],
            'Collection':['Source sections load when opened and reuse their snapshot; r refreshes. Changed options load on the next visit.',
            'Read-only coverage defaults on. System-only journal scope and dated Atop replay remain explicit. Preferences save per user; diagnostic evidence is never saved.',
            'Tables retain the latest bounded snapshot for each source section; timestamps and changed options remain visible.'],
            'Confidence':'A reported event is not a confirmed cause. Missing evidence is not an all-clear.'}
        self.push_screen(DetailDialog(Entry(('Keyboard and evidence help',),detail,detail),None))

    def action_summary(self):
        from .workspace import Entry
        data=self.data()
        if data:
            if self.page<3:
                from .current_views import build
                detail=build(data,('status','health','network')[self.page])['detail']
            else: detail=guide(data)
            self.push_screen(DetailDialog(Entry(('Snapshot meaning and coverage',),data,detail),data))
