"""UserDock navigation parity on invented models, never production account data."""
import asyncio
import copy
import io
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch

from textual.widgets import DataTable,Input,Static,TabbedContent
from faultlens.textual_app import FaultlensApp,DetailDialog,RawDialog,SourceDialog,ValueDialog
from faultlens.models import Observation,report
from faultlens.tui_model import Session
from faultlens.workspace import page_table,Entry
from faultlens.overview import incidents
from tests.test_incident_overview import OverviewRunner
from tests.test_sockets import SocketRunner
from tests.support import SyntheticSources,SyntheticRunner,SyntheticPhase3Runner,SyntheticNetworkSources


def status_report():
    session=Session(sources=SyntheticSources(),runner=SyntheticRunner()); session.refresh(); return session.data


class WorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2
    async def wait_until(self,pilot,condition):
        async with asyncio.timeout(3):
            while not condition(): await pilot.pause(0.01)

    def app(self):
        app=FaultlensApp(initial_collect=False); app.snapshots[0]=status_report(); return app

    async def test_arrows_change_tabs_and_row_selection_opens_a_dialog_not_a_field_tree(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01)
            self.assertEqual(3,len(app.query_one('#grid-0',DataTable).columns))
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
            await pilot.press('down','enter'); self.assertIsInstance(app.screen,DetailDialog)
            boot=app.screen.entry.original['boot']
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
                    while app.page!=page or app.job is not None or (page<6 and page not in app.snapshots):
                        await pilot.pause(0.01)
            self.assertEqual(list(range(6)),[page for page,options in calls])
            app.select_page(1)
            await self.wait_until(pilot,lambda: app.page==1 and app.job is None)
            self.assertEqual(6,len(calls))
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
            self.assertGreater(table.row_count,128)
            table.move_cursor(row=len(app.entries[2])-1)
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
