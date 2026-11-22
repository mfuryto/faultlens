"""UserDock navigation parity on invented models, never production account data."""
import asyncio
import copy
import io
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch

from textual.widgets import DataTable,Input,Static,TabbedContent,TabPane,Tabs
from faultlens.textual_app import FaultlensApp,DetailDialog,RawDialog,SourceDialog,ValueDialog,ServiceDialog
from faultlens.models import Observation,report
from faultlens.tui_model import Session
from faultlens.workspace import page_table,Entry
from faultlens.overview import incidents
from tests.test_incident_overview import OverviewRunner
from tests.test_sockets import SocketRunner
from tests.test_service import service_report
from tests.support import SyntheticSources,SyntheticRunner,SyntheticPhase3Runner,SyntheticNetworkSources


def status_report():
    session=Session(sources=SyntheticSources(),runner=SyntheticRunner()); session.refresh(); return session.data


class WorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2
    async def wait_until(self,pilot,condition):
        async with asyncio.timeout(3):
            while not condition(): await pilot.pause(0.01)

    def app(self):
        async def service_collector(unit):return service_report(unit)
        app=FaultlensApp(initial_collect=False,service_collector=service_collector); app.snapshots[0]=status_report(); return app

    async def test_arrows_change_tabs_and_row_selection_opens_a_dialog_not_a_field_tree(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01)
            self.assertEqual(4,len(app.query_one('#grid-0',DataTable).columns))
            await pilot.press('down','enter'); self.assertIsInstance(app.screen,DetailDialog)
            selected=app.screen.entry.original
            await pilot.press('e'); self.assertIsInstance(app.screen,RawDialog)
            self.assertIs(selected,app.screen.value)
            await pilot.press('escape','escape','right'); self.assertEqual(1,app.page)
            await pilot.press('left'); self.assertEqual(0,app.page)
            for _ in range(8): await pilot.press('right')
            self.assertEqual(0,app.page)

    async def test_keyboard_works_at_compact_ssh_sizes_and_after_resize(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01)
            for size in ((40,10),(80,24),(100,30)):
                await pilot.resize_terminal(*size); await pilot.pause(0.01)
                table=app.query_one('#grid-0',DataTable)
                self.assertGreater(table.size.height,0)
                await pilot.press('enter'); self.assertIsInstance(app.screen,DetailDialog)
                await pilot.press('escape')

    async def test_settings_use_typed_session_values_and_dialog_arrows_do_not_switch_tabs(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(7); await pilot.pause(0.01)
            table=app.query_one('#grid-7',DataTable)
            table.move_cursor(row=2); await pilot.press('enter')
            self.assertIsInstance(app.screen,ValueDialog)
            app.screen.query_one(Input).value='nan'
            await pilot.press('left','right','enter'); self.assertEqual(7,app.page)
            self.assertIsInstance(app.screen,ValueDialog)
            self.assertEqual(0.1,app.session.settings.sample_seconds)
            app.screen.query_one(Input).value='0.2'; await pilot.press('enter')
            self.assertEqual(0.2,app.session.settings.sample_seconds)
            self.assertIsNone(app.job)

    async def test_preference_edits_survive_restart_and_invalid_edits_do_not_change_file(self):
        import tempfile
        from pathlib import Path
        from faultlens.settings_store import SettingsStore
        with tempfile.TemporaryDirectory() as folder:
            store=SettingsStore(Path(folder)/'config')
            app=FaultlensApp(initial_collect=False,settings_store=store)
            async with app.run_test(size=(100,30)) as pilot:
                await pilot.pause(0.01); app.select_page(7)
                await self.wait_until(pilot,lambda: app.page==7)
                table=app.query_one('#grid-7',DataTable)
                table.move_cursor(row=6); await pilot.press('enter')
                self.assertFalse(app.session.settings.sockets)
                table.move_cursor(row=2); await pilot.press('enter')
                app.screen.query_one(Input).value='0.2'; await pilot.press('enter')
                previous=store.path.read_bytes()
                await pilot.press('enter'); app.screen.query_one(Input).value='nan'
                await pilot.press('enter'); self.assertIsInstance(app.screen,ValueDialog)
                self.assertEqual(previous,store.path.read_bytes())
                await pilot.press('escape')
            loaded,message=SettingsStore(store.base).load(Session().settings)
            self.assertFalse(loaded.sockets); self.assertEqual(0.2,loaded.sample_seconds)
            self.assertIn('loaded',message)

    async def test_preference_write_failure_is_visible_without_leaking_exception_details(self):
        from unittest.mock import Mock
        store=Mock(); store.path='/invented/preferences/settings.json'
        store.save.side_effect=OSError('invented-sensitive-error')
        app=FaultlensApp(initial_collect=False,settings_store=store)
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(7)
            await self.wait_until(pilot,lambda: app.page==7)
            app.query_one('#grid-7',DataTable).move_cursor(row=6)
            await pilot.press('enter')
            self.assertFalse(app.session.settings.sockets)
            self.assertIn('NOT CONFIRMED',app.settings_status)
            self.assertNotIn('invented-sensitive-error',app.settings_status)
            summary=str(app.query_one('#summary-7',Static).render())
            self.assertIn('NOT CONFIRMED',summary)

    async def test_history_selection_pins_id_without_an_implicit_query(self):
        from unittest.mock import Mock
        app=self.app(); app.snapshots[4]=incidents(OverviewRunner())
        app.settings_store=Mock(); app.settings_store.path='/invented/settings.json'
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(4); await pilot.pause(0.01)
            app.query_one('#grid-4',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[4]) if row.kind=='boot'))
            await pilot.press('enter'); self.assertIsInstance(app.screen,DetailDialog)
            boot=app.screen.entry.original.get('boot',app.screen.entry.original)
            await pilot.click('#select-boot'); await pilot.pause(0.01)
            self.assertEqual(5,app.page)
            self.assertEqual(boot['boot_id'],app.session.settings.boot_selector)
            self.assertIsNone(app.job); self.assertNotIn(5,app.snapshots)
            app.settings_store.save.assert_called_once()
            self.assertEqual(boot['boot_id'],app.settings_store.save.call_args.args[0].boot_selector)

    async def test_root_and_modal_evidence_do_not_interpret_rich_or_terminal_markup(self):
        app=self.app(); value='[bold red]synthetic[/]\x1b]52;c;payload\x07\u202e'
        app.snapshots[0]=report('status',[Observation('system.kernel_release',value,'','synthetic')])
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01)
            cell=app.query_one('#grid-0',DataTable).get_cell_at((0,1))
            self.assertIn('[bold red]',cell.plain); self.assertIn('\\u001b',cell.plain)
            self.assertNotIn('\x1b',cell.plain); self.assertFalse(cell.spans)
            await pilot.press('e'); self.assertIsInstance(app.screen,RawDialog)
            self.assertEqual(value,app.screen.value['value'])

    async def test_grouped_reports_page_without_losing_originals_or_changing_main_section(self):
        session=Session(sources=SyntheticNetworkSources(),runner=SyntheticPhase3Runner())
        session.choose_page(5); session.update_setting('search_ssh'); session.refresh()
        app=FaultlensApp(initial_collect=False); app.snapshots[5]=session.data
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(5); await pilot.pause(0.01)
            app.query_one('#grid-5',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[5]) if row.kind=='finding_group'))
            await pilot.press('enter'); self.assertIsInstance(app.screen,SourceDialog)
            screen=app.screen; self.assertEqual(64,screen.query_one(DataTable).row_count)
            self.assertGreater(len(screen.entries),64)
            await pilot.press('ctrl+right'); self.assertEqual(64,screen.page_offset)
            await pilot.press('enter'); self.assertIsInstance(app.screen,DetailDialog)
            self.assertIs(session.data['findings'][64],app.screen.entry.original)
            self.assertEqual(5,app.page)

    async def test_manual_collection_remains_responsive_when_automatic_loading_is_disabled(self):
        started=asyncio.Event(); stopped=asyncio.Event(); calls=[]
        async def slow(page,settings):
            calls.append((page,asdict(settings))); started.set()
            try: await asyncio.Event().wait()
            finally: stopped.set()
        app=FaultlensApp(collector=slow,initial_collect=False)
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); await pilot.press('right','left'); self.assertEqual([],calls)
            await pilot.press('r'); await asyncio.wait_for(started.wait(),1)
            await pilot.press('right'); self.assertEqual(1,app.page)
            await pilot.press('escape'); await asyncio.wait_for(stopped.wait(),1)
            self.assertIsNone(app.job); self.assertNotIn(0,app.snapshots)

    async def test_late_focus_from_previous_pane_cannot_undo_explicit_tab_selection(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(.01);app.select_page(7);await pilot.pause(.01)
            sections=app.query_one('#sections',TabbedContent)
            app.select_page(1)
            sections.post_message(TabPane.Focused(app.query_one('#page-7',TabPane)))
            await self.wait_until(pilot,lambda: app.page==1)
            self.assertEqual('page-1',sections.active)
            self.assertEqual(1,app.page)
            app.query_one('#grid-1',DataTable).focus();await pilot.pause(.01)
            self.assertEqual('page-1',sections.active)
            await pilot.press('right');self.assertEqual(2,app.page)

    async def test_late_inner_tab_activation_cannot_undo_newer_selection(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(.01)
            sections=app.query_one('#sections',TabbedContent);tabs=sections.query_one(Tabs)
            app.select_page(5);await pilot.pause(.01)
            tabs.post_message(Tabs.TabActivated(tabs,sections.get_tab('page-0')))
            await pilot.pause(.03)
            self.assertEqual('page-5',sections.active)
            self.assertEqual(5,app.page)
            await pilot.click('#'+sections.get_tab('page-2').id)
            self.assertEqual(2,app.page)

    async def test_unopened_diagnostic_and_evidence_tables_are_not_built_during_startup_or_resize(self):
        from faultlens.incidents import diagnose
        from tests.test_incidents import JournalRunner,record
        data=diagnose(JournalRunner([record('Out of memory: Killed process 42',__CURSOR='s=synthetic')]),show_evidence=True)
        original=copy.deepcopy(data);calls=[]
        def table(page,source,settings):
            calls.append(page);return page_table(page,source,settings)
        app=self.app();app.snapshots[5]=data
        with patch('faultlens.textual_app.page_table',side_effect=table):
            async with app.run_test(size=(100,30)) as pilot:
                await pilot.pause(.01);await pilot.resize_terminal(110,32);await pilot.pause(.01)
                self.assertNotIn(5,calls);self.assertNotIn(6,calls)
                self.assertFalse(app.query("#grid-5"));self.assertFalse(app.query("#grid-6"))
                app.select_page(5);await pilot.pause(.02)
                self.assertIn(5,calls);self.assertNotIn(6,calls)
                self.assertTrue(app.query("#grid-5"));self.assertFalse(app.query("#grid-6"))
                self.assertTrue(any(row.kind=='finding' for row in app.entries[5]))
                before=calls.count(5)
                await pilot.resize_terminal(120,34);await pilot.pause(.01)
                self.assertEqual(before,calls.count(5))
                replacement=copy.deepcopy(data);replacement['findings'][0]['title']='Synthetic replacement finding'
                app.snapshots[5]=replacement;app.populate(5);await pilot.pause(.01)
                self.assertTrue(any(row.cells[0]=='Synthetic replacement finding' for row in app.entries[5]))
                app.select_page(6);await pilot.pause(.02)
                self.assertIn(6,calls)
                self.assertIs(replacement,next(row.original for row in app.entries[6] if row.cells[0]=='Full original report'))
        self.assertEqual(original,data)

    async def test_opening_source_tabs_loads_once_and_reuses_cached_sections(self):
        calls=[]
        async def collect(page,settings): calls.append((page,asdict(settings))); return status_report()
        app=FaultlensApp(collector=collect)
        async with app.run_test(size=(100,30)) as pilot:
            await self.wait_until(pilot,lambda: 0 in app.snapshots and app.job is None)
            self.assertEqual([0],[page for page,options in calls])
            self.assertTrue(calls[0][1]['pstore']); self.assertTrue(calls[0][1]['sockets'])
            source=app.snapshots[0]
            await pilot.press('right')
            await self.wait_until(pilot,lambda: 1 in app.snapshots and app.job is None)
            await pilot.press('left'); self.assertIs(source,app.snapshots[0])
            self.assertEqual([0,1],[page for page,options in calls])
            for page in range(2,8):
                app.select_page(page)
                async with asyncio.timeout(3):
                    while app.page!=page or app.job is not None or (page<6 and app.data(page) is None):
                        await pilot.pause(0.01)
            self.assertEqual([0,1,2,5,4],[page for page,options in calls])
            app.select_page(1)
            await self.wait_until(pilot,lambda: app.page==1 and app.job is None)
            self.assertEqual(5,len(calls))
            app.session.update_setting('sample_seconds','0.2')
            app.select_page(0)
            await self.wait_until(pilot,lambda: app.snapshot_options.get(0,{}).get('sample_seconds')==0.2 and app.job is None)
            self.assertEqual(0,calls[-1][0]); self.assertEqual(0.2,calls[-1][1]['sample_seconds'])

    async def test_tab_loading_waits_for_active_read_and_only_loads_the_current_tab(self):
        started=asyncio.Event(); release=asyncio.Event(); calls=[]; active=0
        async def collect(page,settings):
            nonlocal active
            active+=1; self.assertEqual(1,active); calls.append(page)
            try:
                if page==0: started.set(); await release.wait()
                return status_report()
            finally: active-=1
        app=FaultlensApp(collector=collect)
        async with app.run_test(size=(100,30)) as pilot:
            await asyncio.wait_for(started.wait(),1)
            app.select_page(1); await pilot.pause(0.01)
            app.select_page(2); await pilot.pause(0.01)
            self.assertEqual([0],calls)
            release.set()
            await self.wait_until(pilot,lambda: 2 in app.snapshots and app.job is None)
            self.assertEqual([0,2],calls); self.assertIn(2,app.snapshots)

    async def test_queued_tab_activation_does_not_collect_the_previous_page(self):
        calls=[]
        async def collect(page,settings): calls.append(page);return status_report()
        app=FaultlensApp(collector=collect,initial_collect=False)
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(1);await self.wait_until(pilot,lambda: app.page==1)
            app.initial_collect=True
            app.select_page(2)
            app.ensure_snapshot()
            await self.wait_until(pilot,lambda: 2 in app.snapshots and app.job is None)
            self.assertEqual([2],calls)

    async def test_failed_tab_read_does_not_retry_until_refresh_or_changed_options(self):
        calls=[]
        async def collect(page,settings):
            calls.append(page); raise OSError('synthetic unavailable source')
        app=FaultlensApp(collector=collect)
        async with app.run_test(size=(100,30)) as pilot:
            await self.wait_until(pilot,lambda: calls==[0] and app.job is None)
            await pilot.press('right')
            await self.wait_until(pilot,lambda: calls==[0,1] and app.job is None)
            await pilot.press('left')
            await self.wait_until(pilot,lambda: app.page==0)
            self.assertEqual([0,1],calls)
            await pilot.press('r')
            await self.wait_until(pilot,lambda: calls==[0,1,0] and app.job is None)
            self.assertEqual([0,1,0],calls); self.assertIsNone(app.job)

    async def test_cancel_stops_loading_without_starting_the_waiting_tab(self):
        calls=[]; started=asyncio.Event()
        async def collect(page,settings):
            calls.append(page); started.set(); await asyncio.Event().wait()
        app=FaultlensApp(collector=collect)
        async with app.run_test(size=(100,30)) as pilot:
            await asyncio.wait_for(started.wait(),1)
            app.select_page(1); await pilot.pause(0.01)
            await pilot.press('escape'); await pilot.pause(0.05)
            self.assertEqual([0],calls); self.assertIsNone(app.job)

    async def test_search_moves_cursor_without_hiding_rows(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); table=app.query_one('#grid-0',DataTable); count=table.row_count
            await pilot.press('/'); app.screen.query_one(Input).value='RAM'; await pilot.press('enter')
            self.assertEqual(count,table.row_count); self.assertGreater(table.cursor_row,0)
            self.assertEqual('RAM',app.search_query)

    async def test_network_domain_rows_and_socket_dialog_preserve_numeric_endpoints(self):
        session=Session(sources=SyntheticNetworkSources(),runner=SocketRunner(),sample_seconds=0.05)
        session.choose_page(2); session.update_setting('sockets'); session.refresh()
        app=FaultlensApp(initial_collect=False); app.snapshots[2]=session.data
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(2); await pilot.pause(0.01)
            table=app.query_one('#grid-2',DataTable)
            self.assertTrue({'network_issues','network_context','network_samples'}.issubset({row.kind for row in app.entries[2]}))
            self.assertLessEqual(sum(row.kind=='network_issue' for row in app.entries[2]),3)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[2]) if row.kind=='sockets'))
            await pilot.press('enter'); self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter'); self.assertIsInstance(app.screen,DetailDialog)
            self.assertEqual('0.0.0.0:2222',app.screen.entry.original['local']['original'])

    async def test_every_diagnostic_source_opens_its_table_and_source_explanation(self):
        session=Session(sources=SyntheticNetworkSources(),runner=SyntheticPhase3Runner(),
            pstore_collector=SyntheticSources().pstore_snapshot,pstore_archive_collector=SyntheticSources().pstore_snapshot)
        session.choose_page(5)
        for key in ('search_events','search_ssh','search_firewall','pstore','pstore_archive'): session.update_setting(key)
        session.update_setting('atop_date','20260101'); session.update_setting('atop_extended'); session.refresh()
        app=FaultlensApp(initial_collect=False); app.snapshots[5]=session.data
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.select_page(5); await pilot.pause(0.01)
            for kind in ('timeline','ssh_analysis','firewall_analysis','event_search','atop','pstore','pstore_archive'):
                index=next(i for i,row in enumerate(app.entries[5]) if row.kind==kind)
                app.query_one('#grid-5',DataTable).move_cursor(row=index)
                await pilot.press('enter'); self.assertIsInstance(app.screen,SourceDialog)
                for row in app.screen.entries:
                    self.assertEqual(len(app.screen.columns),len(row.cells))
                if kind=='timeline':
                    await pilot.press('enter'); self.assertIsInstance(app.screen,DetailDialog)
                    self.assertEqual('finding',app.screen.entry.kind)
                    self.assertIs(session.data['timeline'][0],app.screen.entry.detail['Timeline position'])
                    await pilot.press('escape')
                await pilot.press('s'); self.assertIsInstance(app.screen,DetailDialog)
                await pilot.press('escape','escape')
            self.assertIs(session.data,app.snapshots[5])

    async def test_fatal_ui_error_does_not_render_evidence_locals_or_exception_text(self):
        app=self.app()
        with self.assertRaisesRegex(RuntimeError,'invented sensitive evidence'):
            async with app.run_test(size=(100,30)) as pilot:
                await pilot.pause(0.01); app._handle_exception(RuntimeError('invented sensitive evidence'))
        self.assertFalse(app._exit_renderables)

    async def test_signals_reuse_the_selected_inquiry_and_do_not_fall_back_to_network(self):
        from tests.test_problem_workflows import Runner,START,END
        from faultlens.workflows import collect
        historical=collect(Runner([]),mode='period',since_us=START,until_us=END)
        app=self.app();app.snapshots[5]=historical;app.snapshots[3]=status_report()
        original=copy.deepcopy(historical);options=asdict(app.session.settings)
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(3);await self.wait_until(pilot,lambda:app.page==3)
            self.assertIs(historical,app.data(3))
            self.assertTrue(any(row.cells[0]=='Source coverage' for row in app.entries[3]))
            self.assertFalse(any(row.kind=='sockets' for row in app.entries[3]))
            app.query_one('#grid-3',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[3]) if row.kind=='investigation_focus'))
            await pilot.press('enter');await self.wait_until(pilot,lambda:app.page==5)
            self.assertIs(historical,app.data());self.assertEqual(options,asdict(app.session.settings))
            self.assertEqual(original,historical)

    async def test_signals_collection_uses_inquiry_and_cancel_failure_states_remain_visible(self):
        started=asyncio.Event();calls=[]
        async def slow(page,settings):
            calls.append(page)
            if page==5:started.set();await asyncio.Event().wait()
            return status_report()
        app=FaultlensApp(collector=slow)
        async with app.run_test(size=(40,10)) as pilot:
            await self.wait_until(pilot,lambda:app.job is None and 0 in app.snapshots)
            app.select_page(3);await asyncio.wait_for(started.wait(),3)
            self.assertEqual([0,5],calls);self.assertNotIn(3,app.snapshots)
            self.assertIsNone(app.data(3));self.assertEqual('Loading',app.entries[3][0].cells[1])
            await pilot.press('escape');await self.wait_until(pilot,lambda:app.job is None)
            self.assertEqual('Cancelled',app.entries[3][0].cells[1])
            for error in (OSError('invented private source'),RuntimeError('invented private error')):
                async def fail(page,settings):raise error
                app.collector=fail;await pilot.press('r')
                await self.wait_until(pilot,lambda:app.job is None and app.collection_states.get(5)=='failed')
                self.assertEqual('Unavailable',app.entries[3][0].cells[1]);self.assertNotIn('invented private',app.notice)
                await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
                self.assertIn('No security or health conclusion',app.screen.entry.detail['What it means'])
                await pilot.press('escape')

    async def test_current_sections_show_useful_normal_review_and_unavailable_scenarios(self):
        from faultlens.health import collect
        from faultlens.commands import Command,Result
        from faultlens.models import report
        from tests.test_network_analysis import NetworkSources,analyze,stats
        from tests.test_current_overview import UNIT
        normal=collect(SyntheticSources(),SyntheticRunner(),sample_seconds=0.05,preservation=True)
        runner=SyntheticRunner();runner.results[Command.FAILED_SERVICES]=Result('completed',UNIT,0)
        runner.results[Command.SYSTEM_STATE]=Result('completed','degraded',1)
        review=collect(SyntheticSources(),runner,sample_seconds=0.05)
        unavailable=report('health',[Observation('cpu.busy',None,'percent','synthetic','unavailable')])
        unavailable['failed_services']={'state':'unavailable','rows':[],'limitations':['Invented unavailable source.']}
        network_cases=(analyze(),analyze(NetworkSources(tcp=[stats(),stats((1,0,0,0,0))])),
                       analyze(NetworkSources(devices=[OSError('invented')]*2,tcp=[OSError('invented')]*2,udp=[OSError('invented')]*2)))
        app=self.app()
        async with app.run_test(size=(110,30)) as pilot:
            await pilot.pause(0.01)
            for index,health in enumerate((normal,review,unavailable)):
                for page,data in ((0,dict(health,command='status')),(1,health),(2,network_cases[index])):
                    app.snapshots[page]=data; app.select_page(page)
                    await self.wait_until(pilot,lambda: app.page==page)
                    app.populate(page)
                    table=app.query_one('#grid-'+str(page),DataTable)
                    self.assertEqual(4,len(table.columns));self.assertGreater(table.row_count,0)
                    for entry in app.entries[page]:
                        self.assertTrue(all(str(cell).strip() for cell in entry.cells))
                    await pilot.press('enter')
                    self.assertIsInstance(app.screen,(DetailDialog,SourceDialog))
                    await pilot.press('escape')
            app.snapshots[1]=review; app.select_page(1)
            await self.wait_until(pilot,lambda: app.page==1);app.populate(1)
            table=app.query_one('#grid-1',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[1]) if row.kind=='failed_services'))
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,ServiceDialog)
            self.assertEqual('example-worker.service',app.screen.entry.original['unit'])
            await pilot.press('escape','escape')
            await pilot.resize_terminal(40,10);await pilot.pause(0.01)
            self.assertGreater(app.query_one('#grid-1',DataTable).size.height,0)
            self.assertTrue(all(entry.cells[1] and entry.cells[2] for entry in app.entries[1]))

    async def test_original_json_cannot_promote_itself_to_settings_or_finding_actions(self):
        app=self.app(); original={'kind':'setting','rule_id':'kernel.panic','value':'untrusted','callback':'untrusted'}
        before=copy.deepcopy(app.session.settings)
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01); app.push_screen(RawDialog([original])); await pilot.pause(0.01)
            await pilot.press('enter'); self.assertIsInstance(app.screen,RawDialog)
            self.assertIs(original,app.screen.value)
            self.assertEqual(before,app.session.settings); self.assertIsNone(app.job)

    def test_cli_import_does_not_require_or_import_the_optional_frontend(self):
        import subprocess,sys
        script='import sys; sys.path.insert(0,"."); import faultlens.cli; assert "textual" not in sys.modules'
        result=subprocess.run([sys.executable,'-I','-c',script],capture_output=True)
        self.assertEqual(0,result.returncode)
