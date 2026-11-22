"""Real SSH statistics window/group/record navigation; synthetic sources only."""
import asyncio
import unittest
from textual.widgets import DataTable,Input,Static
from faultlens.textual_app import FaultlensApp,SshStatisticsDialog,SourceDialog,RecordsDialog,RawDialog
from faultlens.ssh_statistics import collect
from faultlens.network_sampling import practical
from tests.ssh_statistics_fixtures import Runner,START
from tests.support import SyntheticNetworkSources,SyntheticSocketRunner


class SshWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2
    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition():await pilot.pause(.01)
    def report(self):return collect(Runner(),window='period',since_us=START,until_us=START+86400000000)

    async def test_network_entry_groups_records_period_and_evidence_keep_original_context(self):
        calls=[];report=self.report()
        async def collector(**options):calls.append(options);return report
        app=FaultlensApp(initial_collect=False,ssh_collector=collector)
        app.snapshots[2]=practical(SyntheticNetworkSources(),SyntheticSocketRunner(),sample_seconds=.05,sockets=True)
        async with app.run_test(size=(110,36)) as pilot:
            app.select_page(2);await self.ready(pilot,lambda:app.page==2)
            app.query_one('#grid-2',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[2]) if row.kind=='ssh_statistics'))
            await pilot.press('enter');dialog=app.screen;self.assertIsInstance(dialog,SshStatisticsDialog)
            await self.ready(pilot,lambda:dialog.report is not None)
            self.assertEqual('boot',calls[0]['window'])
            await pilot.click('#ssh-users');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertIs(report['records'][0],app.screen.records[0])
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            await pilot.press('escape','escape','escape')
            await pilot.click('#ssh-hour');await self.ready(pilot,lambda:len(calls)==2 and dialog.report is not None)
            self.assertEqual('hour',calls[-1]['window'])
            await pilot.click('#ssh-day');await self.ready(pilot,lambda:len(calls)==3 and dialog.report is not None)
            self.assertEqual('day',calls[-1]['window'])
            await pilot.click('#ssh-period')
            app.screen.query_one('#period-start',Input).value='2026-01-01T00:00:00Z'
            app.screen.query_one('#period-end',Input).value='2026-01-02T00:00:00Z'
            await pilot.click('#period-apply');await self.ready(pilot,lambda:len(calls)==4 and dialog.report is not None)
            self.assertEqual(START,calls[-1]['since_us']);self.assertEqual('period',calls[-1]['window'])
            await pilot.click('#ssh-evidence');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(report,app.evidence_selection.report)
            self.assertIn('ssh',str(app.query_one('#summary-6',Static).render()))
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='ssh_report'))
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.resize_terminal(40,12);await pilot.press('enter');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertIs(report['records'][0],app.screen.records[0])

    async def test_cancel_and_failed_refresh_do_not_reuse_an_old_total(self):
        cancelled=asyncio.Event();started=asyncio.Event();calls=[]
        async def collector(**options):
            calls.append(options)
            if len(calls)==1:return self.report()
            started.set()
            try:await asyncio.Future()
            finally:cancelled.set()
        app=FaultlensApp(initial_collect=False,ssh_collector=collector)
        async with app.run_test(size=(90,28)) as pilot:
            await pilot.pause(.01);app.push_screen(SshStatisticsDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is not None)
            await pilot.click('#ssh-refresh');await self.ready(pilot,started.is_set)
            self.assertIsNone(dialog.report);self.assertIsNone(app.ssh_snapshot)
            await pilot.press('escape');await self.ready(pilot,cancelled.is_set)
            await pilot.pause(.03)
            async def unavailable(**options):raise ValueError('Synthetic unsupported collection')
            app.ssh_collector=unavailable;app.push_screen(SshStatisticsDialog());dialog=app.screen
            await self.ready(pilot,lambda:bool(dialog.query('#ssh-explanation')) and 'unavailable' in str(dialog.query_one('#ssh-explanation',Static).render()))
            self.assertIsNone(dialog.report)

    async def test_reported_unavailable_source_does_not_show_zero_failures_and_cache_keeps_scope(self):
        runner=Runner();from faultlens.commands import Result
        runner.failure=Result('timeout')
        report=collect(runner,window='period',since_us=START,until_us=START+1,system_journal=True)
        async def collector(**options):return report
        app=FaultlensApp(initial_collect=False,ssh_collector=collector)
        async with app.run_test(size=(90,28)) as pilot:
            await pilot.pause(.01);app.push_screen(SshStatisticsDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is not None)
            text=str(dialog.query_one('#ssh-explanation',Static).render())
            self.assertIn('could not be assessed',text);self.assertNotIn('0 explicit failed',text)
            await pilot.press('escape');app.push_screen(SshStatisticsDialog());await pilot.pause(.01)
            self.assertIs(report,app.screen.report);self.assertEqual('period',app.screen.options['window'])

    async def test_rapid_window_replacement_waits_for_cancelled_source_cleanup(self):
        active=0;maximum=0;calls=[];started=asyncio.Event()
        async def collector(**options):
            nonlocal active,maximum
            active+=1;maximum=max(maximum,active);calls.append(options['window'])
            try:
                if len(calls)==1:started.set();await asyncio.Future()
                return self.report()
            finally:await asyncio.sleep(.03);active-=1
        app=FaultlensApp(initial_collect=False,ssh_collector=collector)
        async with app.run_test(size=(90,28)) as pilot:
            await pilot.pause(.01);app.push_screen(SshStatisticsDialog());dialog=app.screen
            await self.ready(pilot,started.is_set)
            for window in ('hour','boot','day'):
                dialog.options={'window':window,'since_us':None,'until_us':None};dialog.action_refresh()
            await self.ready(pilot,lambda:dialog.report is not None)
            self.assertEqual(['boot','day'],calls);self.assertEqual(1,maximum)
