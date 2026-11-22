"""Synthetic walkthroughs must never fall back to host evidence or preferences."""
import asyncio
import contextlib
import copy
import io
import unittest
from unittest.mock import patch

from textual.widgets import DataTable, Static
from faultlens.investigation import linked_records, story
from faultlens.textual_app import DetailDialog, RecordsDialog
from faultlens.tui_model import Settings
from scripts.investigation_demo import BANNER, BOOT, EPOCH_US, SCENARIOS, build_report, main, make_app


@contextlib.contextmanager
def no_native_access():
    with contextlib.ExitStack() as stack:
        for name in ('faultlens.commands.CommandRunner.__init__','faultlens.linux.LinuxSources.__init__',
                     'faultlens.ui_collection.collect','faultlens.settings_store.SettingsStore.load',
                     'faultlens.settings_store.SettingsStore.save','subprocess.Popen'):
            stack.enter_context(patch(name,side_effect=AssertionError('Synthetic walkthrough attempted native access')))
        yield


class DemoTests(unittest.TestCase):
    def test_three_cases_have_distinct_meaning_without_native_access(self):
        with no_native_access():
            reports={name:build_report(name,5,Settings(search_events=True)) for name in SCENARIOS}
            self.assertIn('Recorded problems',story(reports['oom'])['answer'])
            self.assertIn('No supported fault',story(reports['no-match'])['answer'])
            self.assertIn('could not be assessed',story(reports['unavailable'])['answer'])
            for data in reports.values():
                self.assertFalse(data['synthetic_demo']['native_collection'])
                self.assertEqual('Unknown',data['root_cause'])
                self.assertEqual(BANNER,data['limitations'][0])
            data=reports['oom'];original=copy.deepcopy(data)
            records=linked_records(data,data['findings'][0])
            self.assertIn('synthetic-demo-worker',records[0]['message'])
            self.assertIs(records[0],data['journal_records'][1])
            self.assertEqual(original,data)

    def test_scope_and_optional_settings_cannot_enable_native_sources(self):
        settings=Settings.administrator_defaults();settings.investigation_mode=''
        settings.boot_selector=BOOT;settings.system_journal=True
        settings.atop_date='20260101';settings.atop_extended=True
        settings.since_us=str(EPOCH_US+60_000_000);settings.until_us=settings.since_us
        with no_native_access():
            for scenario in SCENARIOS:
                for page in range(6):
                    data=build_report(scenario,page,settings)
                    self.assertIn('synthetic_demo',data)
                data=build_report(scenario,5,settings)
                self.assertIn(data['atop']['state'],{'unavailable','not_requested'})
                self.assertEqual('unavailable',data['pstore']['state'])
                self.assertEqual('unavailable',data['pstore_archive']['state'])
                if scenario=='oom':
                    self.assertEqual(1,data['records_examined'])
                    self.assertIn('synthetic-demo-worker',data['journal_records'][0]['message'])
            settings.since_us=str(EPOCH_US+120_000_000);settings.until_us=''
            self.assertEqual([],build_report('oom',5,settings)['findings'])
            settings.boot_selector='0'
            self.assertEqual('unavailable',build_report('oom',5,settings)['state'])

    def test_primary_period_and_current_inquiries_never_query_real_sources(self):
        with no_native_access():
            for mode in ('now','period','before-restart'):
                settings=Settings.administrator_defaults();settings.investigation_mode=mode
                settings.since_us=str(EPOCH_US);settings.until_us=str(EPOCH_US+120000000)
                data=build_report('oom',5,settings)
                self.assertEqual('investigate',data['command']);self.assertEqual(mode,data['mode'])
                self.assertFalse(data['synthetic_demo']['native_collection'])
                self.assertTrue(data['investigations'])
                self.assertEqual('Unknown',data['root_cause'])
                self.assertEqual('unavailable',data['pstore']['state'])

    def test_readable_entrypoint_is_marked_and_cli_needs_no_frontend(self):
        with no_native_access(),patch('scripts.investigation_demo.version',side_effect=AssertionError('Unexpected frontend check')):
            for scenario in SCENARIOS:
                output=io.StringIO()
                with contextlib.redirect_stdout(output): self.assertEqual(0,main(['--scenario',scenario,'--cli']))
                self.assertTrue(output.getvalue().startswith(BANNER))
                if scenario=='unavailable':
                    self.assertNotIn('No supported journal pattern matched',output.getvalue())
        with patch('scripts.investigation_demo.version',return_value='0'),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2,main([]))
        with patch('scripts.investigation_demo.version',return_value='8.2.8'),patch('sys.stdin.isatty',return_value=False),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2,main([]))


class DemoWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def wait_until(self,pilot,condition):
        async with asyncio.timeout(3):
            while not condition(): await pilot.pause(.01)

    async def test_history_to_original_records_and_other_tabs_stay_synthetic(self):
        with no_native_access():
            app=make_app('oom')
            async with app.run_test(size=(100,30)) as pilot:
                await self.wait_until(pilot,lambda: app.page==4)
                self.assertIn('SYNTHETIC DEMO',str(app.query_one('#demo-banner',Static).render()))
                app.action_open();await pilot.pause(.01)
                self.assertIsInstance(app.screen,DetailDialog)
                await pilot.click('#history-period')
                await self.wait_until(pilot,lambda: 5 in app.snapshots and app.job is None)
                self.assertEqual('',app.session.settings.boot_selector)
                self.assertEqual('period',app.session.settings.investigation_mode)
                rows=app.entries[5]
                app.query_one('#grid-5',DataTable).move_cursor(row=next(i for i,row in enumerate(rows) if row.kind=='finding'))
                app.action_open();await pilot.pause(.01);await pilot.click('#references')
                self.assertIsInstance(app.screen,RecordsDialog)
                self.assertIn('synthetic-demo-worker',str(app.screen.records))
                await pilot.press('escape','escape')
                for page in (0,1,2,3,6,7):
                    app.select_page(page)
                    await self.wait_until(pilot,lambda: app.page==page and app.job is None)
                self.assertIsNone(app.settings_store)
                app.session.update_setting('system_journal');app.persist_settings()
                self.assertTrue(app.session.settings.system_journal)
                await pilot.resize_terminal(40,10)
                self.assertTrue(app.query('#demo-banner'))
                self.assertTrue(all(data['synthetic_demo']['native_collection'] is False for data in app.snapshots.values()))

    async def test_unmatched_and_unavailable_workspaces_remain_distinct(self):
        with no_native_access():
            for scenario,expected in (('no-match','No supported fault'),('unavailable','could not be assessed')):
                app=make_app(scenario)
                async with app.run_test(size=(80,24)) as pilot:
                    await self.wait_until(pilot,lambda: app.page==4)
                    app.select_page(5)
                    await self.wait_until(pilot,lambda: 5 in app.snapshots and app.job is None)
                    self.assertIn(expected,str(app.query_one('#summary-5',Static).render()))
                    self.assertEqual('unavailable' if scenario=='unavailable' else 'available',app.snapshots[5]['state'])
                    self.assertEqual('Unknown',app.snapshots[5]['root_cause'])
