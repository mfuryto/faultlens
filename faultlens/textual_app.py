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
from textual.containers import Vertical,VerticalScroll,Horizontal
from textual.screen import ModalScreen
from textual.widgets import Header,Footer,Static,DataTable,TabbedContent,TabPane,Button,Input
from textual import constants

constants.LOG_FILE=None
constants.DRIVER=None

from . import __version__
from .tui_model import Session,Settings,escaped,brief
from .workspace import TABS,page_table,source_table,detail_text,collection_entry
from .presentation import guide
from .evidence_links import resolve
from . import ui_collection


def literal(value):
    styles={'critical':'bold red','warning':'yellow','unavailable':'dim','partial':'yellow',
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
    BINDINGS=[Binding('escape','dismiss','Close'),Binding('e','original','Original evidence'),
              Binding('p','position','Timeline position')]

    def __init__(self,entry,data):
        super().__init__(); self.entry=entry; self.data=data

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static(literal(self.entry.cells[0]),classes='dialog-title')
            with VerticalScroll(): yield Static(Text(detail_text(self.entry.detail or {})),markup=False)
            with Horizontal(classes='buttons'):
                yield Button('Original',id='original')
                if self.entry.kind=='finding': yield Button('Records',id='references')
                if 'Timeline position' in (self.entry.detail or {}): yield Button('Position',id='position')
                if self.entry.kind=='boot': yield Button('Investigate this boot',id='select-boot',variant='primary')
                yield Button('Close',id='close')

    def action_original(self): self.app.push_screen(RawDialog(self.entry.original))
    def action_position(self):
        if 'Timeline position' in (self.entry.detail or {}):
            self.app.push_screen(RawDialog(self.entry.detail['Timeline position'],'Original timeline position'))

    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='original': self.action_original()
        elif event.button.id=='position': self.action_position()
        elif event.button.id=='references': self.app.push_screen(RecordsDialog(self.data,self.entry.original))
        elif event.button.id=='select-boot':
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


class RecordsDialog(ModalScreen):
    """Readable, scrollable source messages; exact retained objects remain available."""
    BINDINGS=[Binding('escape','dismiss','Back'),Binding('e','original','Original fields'),
              Binding('ctrl+right','next_records','Next records'),Binding('ctrl+left','previous_records','Previous records')]

    def __init__(self,data,finding=None,*,record=None):
        super().__init__()
        from .investigation import linked_records
        self.records=[record] if record is not None else linked_records(data,finding)
        self.record_offset=0
        self.linkage=resolve(data,finding) if finding is not None else record

    def messages(self):
        from .investigation import utc
        if not self.records:
            yield Static('No original record resolved. Original fields retain reference details; no source message is guessed.',markup=False)
        for record in self.records[self.record_offset:self.record_offset+16]:
            if 'message' in record:
                metadata=record.get('metadata',{})
                text=utc(record['reference'].get('realtime_us'))+' | '+str(metadata.get('comm',''))+' | PID '+str(metadata.get('pid',''))
                yield Static(literal(text),markup=False)
                yield Static(literal(record['message']),markup=False)
            else:
                from .recording_presentation import sample_view
                yield Static(Text(detail_text(sample_view(record))),markup=False)

    def compose(self):
        with Vertical(classes='dialog'):
            yield Static('Recorded source evidence',classes='dialog-title',markup=False)
            with VerticalScroll(id='readable-records'): yield from self.messages()
            yield Static('',id='record-position',classes='hint',markup=False)
            yield Static('Receipt time may differ from event time. e opens complete original fields; Esc returns.',classes='hint',markup=False)
            with Horizontal(classes='buttons'):
                yield Button('Previous',id='record-previous'); yield Button('Next',id='record-next')
                yield Button('Original fields',id='original'); yield Button('Back',id='back')

    def on_mount(self): self.position()
    def position(self):
        self.query_one('#record-position',Static).update('Retained records '+str(self.record_offset+1 if self.records else 0)+'–'+str(min(self.record_offset+16,len(self.records)))+' of '+str(len(self.records))+'. Reports can overlap; no independent corroboration is inferred.')
        self.query_one('#record-previous',Button).disabled=self.record_offset==0
        self.query_one('#record-next',Button).disabled=self.record_offset+16>=len(self.records)
    def action_original(self): self.app.push_screen(RawDialog(self.linkage,'Complete source references and originals'))
    async def change_records(self,step):
        self.record_offset=max(0,min(max(0,(len(self.records)-1)//16*16),self.record_offset+step))
        container=self.query_one('#readable-records',VerticalScroll)
        await container.remove_children(); await container.mount(*self.messages()); container.scroll_home(animate=False); self.position()
    async def action_next_records(self): await self.change_records(16)
    async def action_previous_records(self): await self.change_records(-16)
    async def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='original': self.action_original()
        elif event.button.id=='record-next': await self.action_next_records()
        elif event.button.id=='record-previous': await self.action_previous_records()
        else: self.dismiss()


class SourceDialog(ModalScreen):
    BINDINGS=[Binding('escape','dismiss','Back'),Binding('e','original','Original source'),
              Binding('ctrl+right','next_page','Next records'),Binding('ctrl+left','previous_page','Previous records'),
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
            yield Static(literal('Source state: '+str(state)+' | Bounded evidence; no complete-health verdict'),classes='hint')
            yield DataTable(id='source-table',cursor_type='row',zebra_stripes=True)
            yield Static('No session rows reported; this does not establish that nobody is logged in. s explains coverage.' if self.entry.kind=='login_sessions' else 'No rows in this view. Events may still exist; s explains coverage, e opens originals.',id='source-empty',classes='hint',markup=False)
            with Horizontal(classes='buttons'):
                yield Button('Previous',id='previous'); yield Button('Next',id='next'); yield Button('Back',id='back')

    def on_mount(self):
        self.rebuild_table()
        self.query_one(DataTable).focus()

    def on_resize(self,event):
        if self.is_mounted and self.entry.kind in {'observations','interfaces','failed_services','scope_details','login_sessions'}:
            self.call_after_refresh(self.rebuild_table)

    def rebuild_table(self):
        table=self.query_one(DataTable); selected=table.cursor_row; table.clear(columns=True)
        if self.entry.kind in {'observations','interfaces','failed_services','scope_details','login_sessions'}:
            weights=([.20,.13,.30,.37] if self.entry.kind=='login_sessions' else
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
        if event.button.id=='next': self.action_next_page()
        elif event.button.id=='previous': self.action_previous_page()
        else: self.dismiss()

    def on_data_table_row_selected(self,event):
        event.stop(); self.app.open_entry(self.entries[int(event.row_key.value)],self.data)

    def action_original(self): self.app.push_screen(RawDialog(self.entry.original))

    def action_summary(self):
        from .workspace import Entry
        from .socket_presentation import snapshot_view
        from .recording_presentation import recording_view
        from .crash_presentation import source_view
        source=self.entry.original
        explain={'sockets':snapshot_view,'atop':recording_view,'pstore':source_view,'pstore_archive':source_view}
        if self.entry.kind in {'observations','interfaces','failed_services','scope_details','login_sessions'}: detail=self.entry.detail or {'What it means':'Retained source rows only; open an individual row for context.'}
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
            with Horizontal(classes='buttons'):
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
            with Horizontal(classes='buttons'):
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
    ModalScreen { align: center middle; background: $background 60%; }
    .dialog { width: 96%; height: 94%; padding: 0 1; border: round $primary; background: $surface; }
    .edit-dialog { width: 90%; max-width: 72; height: auto; max-height: 100%; padding: 0 1; border: round $primary; background: $surface; }
    .edit-dialog #validation { height: 1; }
    .buttons { height: 1; min-height: 1; }
    .buttons Button { height: 1; min-height: 1; border: none; min-width: 6; padding: 0 1; margin-right: 1; }
    #raw-scalar { height: 1fr; }
    '''
    BINDINGS=[Binding('q','quit','Quit'),Binding('r','refresh','Refresh'),Binding('enter','open','Open'),
              Binding('e','original','Original'),Binding('/','search','Search'),Binding('n','next_match','Next match'),
              Binding('N','previous_match','Previous match'),Binding('?','help','Help'),Binding('s','summary','Summary'),
              Binding('left','previous_tab','Previous section',priority=True),
              Binding('right','next_tab','Next section',priority=True),
              Binding('escape','cancel','Cancel collection'),Binding('ctrl+c','interrupt','Interrupt',priority=True)]

    def __init__(self,session=None,collector=None,initial_collect=True,settings_store=None,settings_status=''):
        super().__init__(); self.session=session or Session(); self.collector=collector or ui_collection.collect
        if session is None: self.session.settings=Settings.administrator_defaults()
        self.page=0; self.snapshots={}; self.snapshot_options={}; self.entries={}; self.notice=''; self.job=None
        self.table_models={}; self.rendered_tables={}
        self.initial_collect=initial_collect; self.search_query=''
        self.collection_attempts={}; self.collection_states={}; self.closing=False; self.workspace_ready=False
        self.settings_store=settings_store; self.settings_status=settings_status

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
        if page in {4,5,6}: yield Static('',id='selected-evidence-'+str(page),classes='selected-evidence',markup=False)

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
        if action in {'previous_tab','next_tab','open','refresh','original','search','next_match','previous_match','help','summary'}:
            return len(self.screen_stack)==1
        return True

    def data(self,page=None):
        page=self.page if page is None else page
        if page==6: return self.snapshots.get(self.last_source())
        return self.snapshots.get(page)

    def last_source(self): return next(reversed(self.snapshots),0)

    def populate(self,page):
        table=self.query_one('#grid-'+str(page),DataTable); selected=table.cursor_row
        data=self.data(page); options=tuple(asdict(self.session.settings).values())
        cached=self.table_models.get(page)
        if cached is not None and cached[0] is data and cached[1]==options:
            model=cached[2]
        else:
            model=page_table(page,data,self.session.settings)
            self.table_models[page]=(data,options,model)
        columns,entries=model
        if data is None and page<7 and not (page==5 and self.session.settings.investigation_mode): entries=[collection_entry(page,self.collection_states.get(page,'not_collected'))]
        elif data is None and page==5 and self.session.settings.investigation_mode:
            status=collection_entry(page,self.collection_states.get(page,'not_collected'))
            entries=entries[:-1]+[replace(status,cells=(status.cells[0],status.cells[1],status.cells[2],'Choose an inquiry or refresh/retry'))]
        if page==7 and self.settings_store is not None:
            entries=[replace(entry,cells=(*entry.cells[:2],'User preference')) for entry in entries]
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
        elif page<3 and data:
            from .current_views import build
            view=build(data,('status','health','network')[page])
            summary=literal(view['summary']); summary.append('\nNext: ').append(literal(view['next_step']))
        elif page in {5,6} and data and data['command'] in {'diagnose','investigate'}:
            from .investigation import story
            view=story(data)
            summary=literal(view['answer']); summary.append('\nScope: ').append(literal(view['scope'])); summary.append('\nNext: ').append(literal(view['next']))
        elif page==4 and data:
            summary=literal('Optional boot history browser. For a problem now or a time range, open Investigate directly. Retained record times are not boot/crash boundaries.')
        else:
            summary=literal(guide(data)['Summary'] if data else
                'No retained snapshot. Opening this source section loads data; r refreshes or retries.')
        self.query_one('#summary-'+str(page),Static).update(summary)

    def update_status(self):
        data=self.data(); state='No snapshot' if data is None else data.get('state','observations; no health verdict')
        source_page=self.last_source() if self.page==6 else self.page
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
        if page!=self.page: self.page=page; self.populate(self.page)
        self.update_status()
        self.query_one('#grid-'+str(self.page),DataTable).focus()
        self.ensure_snapshot()

    def ensure_snapshot(self):
        if self.query_one('#sections',TabbedContent).active!='page-'+str(self.page): return
        if not self.workspace_ready or not self.initial_collect or self.closing or self.page>=6 or self.job is not None: return
        options=asdict(self.session.settings)
        if self.page in self.snapshots and self.snapshot_options.get(self.page)==options: return
        # Failed/cancelled reads need r to retry; tab events must never create a loop.
        if self.collection_attempts.get(self.page)!=options: self.action_refresh()

    def action_refresh(self):
        if self.job is not None: self.notice='Collection already running. Esc cancels.'; self.update_status(); return
        if self.page>=6: self.notice='This section does not collect. Choose a source section.'; self.update_status(); return
        page=self.page; options=replace(self.session.settings)
        self.collection_attempts[page]=asdict(options)
        self.collection_states[page]='loading'
        self.snapshots.pop(page,None); self.populate(page)
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
        if len(self.screen_stack)!=1 or self.page not in {4,5,6} or event.data_table.id!='grid-'+str(self.page): return
        rows=self.entries.get(self.page,[])
        if not rows or not 0<=event.cursor_row<len(rows): return
        entry=rows[event.cursor_row];detail=entry.detail or {}
        text=Text()
        if self.page==4:
            text.append(literal('Retained UTC: '+str(detail.get('Retained UTC range','Not examined'))))
            for example in detail.get('Recorded examples',[])[:1]: text.append('\nRecorded: ').append(literal(example))
            text.append('\nEnter opens context and Investigate this boot.')
        else:
            lines=detail.get('Recorded evidence',detail.get('Recorded message',[]))
            if not lines and entry.kind=='journal_record':
                from .investigation import utc,excerpt
                lines=[utc(entry.original['reference'].get('realtime_us'))+' | '+excerpt(entry.original['message'],2048)]
            for line in lines[:1]: text.append(literal(line))
            meaning=detail.get('What it means','Enter opens full context; original source fields remain available.')
            if isinstance(meaning,str): text.append('\nMeaning: ').append(literal(meaning.split('. ',1)[0]+('.' if '. ' in meaning else '')))
            steps=detail.get('What you can do',[])
            if steps: text.append('\nNext: ').append(literal(steps[0]))
        self.query_one('#selected-evidence-'+str(self.page),Static).update(text)

    def start_investigation(self,mode,*,start=None,end=None):
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
        elif entry.kind=='raw': self.push_screen(RawDialog(entry.original))
        elif entry.kind in {'finding_group','sockets','atop','pstore','pstore_archive','ssh_analysis','firewall_analysis','event_search','analysis','timeline','observations','interfaces','failed_services','scope_details','login_sessions'}:
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
