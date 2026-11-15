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
from .tui_model import Session,escaped,brief
from .workspace import TABS,page_table,source_table,detail_text
from .presentation import guide
from .evidence_links import resolve
from . import ui_collection


def literal(value):
    styles={'critical':'bold red','warning':'yellow','unavailable':'dim','partial':'yellow',
            'available':'green','normal':'green','Confirmed':'cyan','Possible':'yellow','Unknown':'dim'}
    return Text(json.dumps(str(value),ensure_ascii=True)[1:-1],style=styles.get(str(value),''))


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
                if self.entry.kind=='boot': yield Button('Select boot',id='select-boot',variant='primary')
                yield Button('Close',id='close')

    def action_original(self): self.app.push_screen(RawDialog(self.entry.original))
    def action_position(self):
        if 'Timeline position' in (self.entry.detail or {}):
            self.app.push_screen(RawDialog(self.entry.detail['Timeline position'],'Original timeline position'))

    def on_button_pressed(self,event):
        event.stop()
        if event.button.id=='original': self.action_original()
        elif event.button.id=='position': self.action_position()
        elif event.button.id=='references': self.app.push_screen(RawDialog(resolve(self.data,self.entry.original),'Referenced source evidence'))
        elif event.button.id=='select-boot':
            source=self.entry.original; boot=source.get('boot',source)
            self.app.session.update_setting('boot_selector',boot['boot_id'])
            self.dismiss(); self.app.select_page(5)
            self.app.notice='Boot ID selected. Press r to diagnose with the current collection options.'; self.app.update_status()
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
            with Horizontal(classes='buttons'):
                yield Button('Previous',id='previous'); yield Button('Next',id='next'); yield Button('Back',id='back')

    def on_mount(self):
        table=self.query_one(DataTable); table.add_columns(*self.columns); self.populate()
        table.focus()

    def populate(self):
        table=self.query_one(DataTable); table.clear()
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
        if self.entry.kind in explain: detail=explain[self.entry.kind](source)
        else:
            detail={'Source':self.entry.cells[0],'State':source.get('state','retained') if isinstance(source,dict) else 'retained reports',
                'Meaning':'Only retained candidates and supported signatures are shown. No matches is not an all-clear; use original evidence for unclassified records.',
                'Coverage limits':source.get('limitations',[]) if isinstance(source,dict) else ['Counts are reports, not separate incidents.']}
        self.app.push_screen(DetailDialog(Entry((self.heading,),source,detail),self.data))


class ValueDialog(ModalScreen):
    BINDINGS=[Binding('escape','cancel','Cancel')]

    def __init__(self,label,value,callback):
        super().__init__(); self.label_text=label; self.value=str(value); self.callback=callback

    def compose(self):
        with Vertical(classes='edit-dialog'):
            yield Static(literal(self.label_text),classes='dialog-title')
            yield Input(value=self.value,max_length=64,id='value')
            yield Static('Session only. Enter applies; Esc cancels.',id='validation',markup=False)
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

    def __init__(self,session=None,collector=None,initial_collect=True):
        super().__init__(); self.session=session or Session(); self.collector=collector or ui_collection.collect
        self.page=0; self.snapshots={}; self.snapshot_options={}; self.entries={}; self.notice=''; self.job=None
        self.initial_collect=initial_collect; self.search_query=''

    def _handle_exception(self,error):
        # Pinned Textual hook: never render exception locals containing admin evidence.
        self._return_code=1
        if self._exception is None:
            self._exception=error; self._exception_event.set()
        self.exit(1)

    def compose(self):
        yield Header(show_clock=False)
        yield Static('Read-only; no elevation or configuration changes.',id='status-line',markup=False)
        with TabbedContent(initial='page-0',id='sections'):
            for page,title in enumerate(TABS):
                with TabPane(title,id='page-'+str(page)):
                    yield Static('Press r to collect this section with current access.',id='summary-'+str(page),classes='summary',markup=False)
                    yield DataTable(id='grid-'+str(page),cursor_type='row',zebra_stripes=True)
        yield Footer()

    def on_mount(self):
        for page in range(8): self.populate(page)
        self.query_one('#grid-0',DataTable).focus()
        if self.initial_collect: self.action_refresh()

    def on_resize(self,event):
        for widget in self.query('.summary'): widget.display=event.size.height>=16
        self.call_after_refresh(self.relayout)

    def relayout(self):
        if self.is_running:
            for page in range(8):
                if self.query('#grid-'+str(page)): self.populate(page)

    def check_action(self,action,parameters):
        if action in {'previous_tab','next_tab','open','refresh','original','search','next_match','previous_match','help','summary'}:
            return len(self.screen_stack)==1
        return True

    def data(self,page=None):
        page=self.page if page is None else page
        if page==6: return self.snapshots.get(self.last_source())
        if page==3 and 3 not in self.snapshots: return self.snapshots.get(5)
        return self.snapshots.get(page)

    def last_source(self): return next(reversed(self.snapshots),0)

    def populate(self,page):
        table=self.query_one('#grid-'+str(page),DataTable); selected=table.cursor_row; table.clear(columns=True)
        data=self.data(page); columns,entries=page_table(page,data,self.session.settings)
        self.entries[page]=entries
        visible=list(range(len(columns)))
        if self.size.width<70 and len(columns)>2:
            visible=[0,1,2] if page in {0,1,2,4} else [0,1]
        if page==2: visible=[index for index in visible if index<3]
        usable=max(12,self.size.width-6-2*len(visible))
        if len(visible)==3:
            widths=[max(4,int((usable-9)*0.55)),max(4,usable-9-int((usable-9)*0.55)),9]
        else:
            weights=({2:[0.45,0.55],4:[0.34,0.18,0.18,0.30],5:[0.08,0.18,0.16,0.17,0.41]})[len(visible)]
            widths=[max(4,int(usable*weight)) for weight in weights]
        for index,width in zip(visible,widths): table.add_column(columns[index],width=width)
        for index,entry in enumerate(entries): table.add_row(*(literal(entry.cells[c]) for c in visible),key=str(index))
        if entries: table.move_cursor(row=min(selected,len(entries)-1))
        summary=('Collection options affect the next explicit refresh; no server settings are changed.' if page==7 else
                 guide(data)['Summary'] if data else 'No retained snapshot. Press r to collect this section using existing access.')
        self.query_one('#summary-'+str(page),Static).update(literal(summary))

    def update_status(self):
        data=self.data(); state='No snapshot' if data is None else data.get('state','observations; no health verdict')
        source_page=5 if self.page==3 and 3 not in self.snapshots else self.last_source() if self.page==6 else self.page
        stale=(source_page in self.snapshot_options and self.snapshot_options[source_page]!=asdict(self.session.settings))
        text=TABS[self.page]+' | '+(data['command']+' | ' if data else '')+state+(' | SETTINGS CHANGED: refresh explicitly' if stale else '')
        if data: text+=' | '+str(data.get('collected_at',''))
        self.query_one('#status-line',Static).update(literal(text+' | '+self.notice))

    def select_page(self,page): self.query_one('#sections',TabbedContent).active='page-'+str(page)
    def action_previous_tab(self): self.select_page((self.page-1)%8)
    def action_next_tab(self): self.select_page((self.page+1)%8)
    def on_tabbed_content_tab_activated(self,event):
        sections=self.query_one('#sections',TabbedContent)
        if event.tabbed_content is not sections or event.pane.id!=sections.active: return
        page=int(event.pane.id.removeprefix('page-'))
        if page!=self.page: self.page=page; self.populate(self.page)
        self.update_status()
        self.query_one('#grid-'+str(self.page),DataTable).focus()

    def action_refresh(self):
        if self.job is not None: self.notice='Collection already running. Esc cancels.'; self.update_status(); return
        if self.page>=6: self.notice='This section does not collect. Choose a source section.'; self.update_status(); return
        page=self.page; options=replace(self.session.settings)
        self.snapshots.pop(page,None); self.populate(page)
        self.notice='Collecting '+TABS[page]+'... Esc cancels; q exits.'; self.update_status()
        self.job=asyncio.create_task(self.load(page,options))

    async def load(self,page,options):
        try:
            value=await self.collector(page,options)
            self.snapshots[page]=value; self.snapshot_options[page]=asdict(options)
            self.notice='Snapshot collected. Open a row for meaning and original evidence.'
        except asyncio.CancelledError: self.notice='Collection cancelled; no replacement snapshot retained.'
        except (OSError,ValueError,TimeoutError): self.notice='Collection unavailable within source limits; no evidence was guessed.'
        finally:
            self.job=None
            if self.is_running:
                self.populate(self.page); self.update_status()

    async def action_cancel(self):
        if self.job is not None:
            self.job.cancel(); await self.job
    async def action_quit(self): await self.action_cancel(); self.exit(0)
    async def action_interrupt(self): await self.action_cancel(); self.exit(130)
    async def on_unmount(self): await self.action_cancel()

    def selected(self):
        entries=self.entries.get(self.page,[]); table=self.query_one('#grid-'+str(self.page),DataTable)
        return entries[table.cursor_row] if entries else None

    def action_open(self):
        entry=self.selected()
        if entry: self.open_entry(entry,self.data())
    def on_data_table_row_selected(self,event):
        if len(self.screen_stack)==1: event.stop(); self.action_open()

    def open_entry(self,entry,data):
        if len(self.screen_stack)>=32: return
        if entry.kind=='finding' and entry.detail is None:
            from .presentation import finding_view
            entry=replace(entry,detail=finding_view(entry.original))
        if entry.kind=='setting':
            key=entry.original; value=getattr(self.session.settings,key)
            if type(value) is bool:
                self.session.update_setting(key); self.populate(7); self.update_status()
            else:
                def save(text):
                    self.session.update_setting(key,text); self.populate(7); self.update_status()
                self.push_screen(ValueDialog(entry.cells[0],value,save))
        elif entry.kind=='raw': self.push_screen(RawDialog(entry.original))
        elif entry.kind in {'finding_group','sockets','atop','pstore','pstore_archive','ssh_analysis','firewall_analysis','event_search','analysis','timeline'}:
            self.push_screen(SourceDialog(entry,data))
        else: self.push_screen(DetailDialog(entry,data))

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
            'Collection':['System status loads on startup. Other sources collect only on explicit refresh.',
            'Optional sources default off. Settings apply to later collection, never to server configuration.',
            'Tables retain the latest bounded snapshot for each source section; timestamps and changed options remain visible.'],
            'Confidence':'A reported event is not a confirmed cause. Missing evidence is not an all-clear.'}
        self.push_screen(DetailDialog(Entry(('Keyboard and evidence help',),detail,detail),None))

    def action_summary(self):
        from .workspace import Entry
        data=self.data()
        if data: self.push_screen(DetailDialog(Entry(('Snapshot meaning and coverage',),data,guide(data)),data))
