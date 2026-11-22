"""Real firewall/Fail2ban navigation with synthetic policy and source failures."""
import asyncio
import unittest
from textual.widgets import DataTable,Static
from faultlens.textual_app import FaultlensApp,FirewallDialog,SourceDialog,DetailDialog,RecordsDialog,RawDialog
from faultlens.firewall_state import collect
from faultlens.network_sampling import practical
from faultlens.commands import Command,Result
from tests.firewall_state_fixtures import Runner,START
from tests.support import SyntheticNetworkSources,SyntheticSocketRunner


class FirewallWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2
    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition():await pilot.pause(.01)
    def report(self,runner=None):return collect(runner or Runner(),window='period',since_us=START,until_us=START+86400000000)

    async def test_network_ban_matches_rules_logs_originals_and_evidence(self):
        report=self.report();calls=[]
        async def collector(**options):calls.append(options);return report
        app=FaultlensApp(initial_collect=False,firewall_collector=collector)
        app.snapshots[2]=practical(SyntheticNetworkSources(),SyntheticSocketRunner(),sample_seconds=.05,sockets=True)
        async with app.run_test(size=(110,36)) as pilot:
            app.select_page(2);await self.ready(pilot,lambda:app.page==2)
            app.query_one('#grid-2',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[2]) if row.kind=='firewall_state'))
            await pilot.press('enter');dialog=app.screen;self.assertIsInstance(dialog,FirewallDialog)
            await self.ready(pilot,lambda:dialog.report is not None);self.assertEqual('day',calls[0]['window'])
            await pilot.click('#firewall-bans');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('192.0.2.7',str(app.screen.entry.detail))
            self.assertIn('human Unknown',app.screen.entry.detail['Who initiated it'])
            await pilot.click('#firewall-matches');self.assertIsInstance(app.screen,SourceDialog)
            self.assertEqual(2,len(app.screen.entries));await pilot.press('enter')
            self.assertIn('only if this chain is reached',app.screen.entry.detail['What it means'])
            self.assertIn('TCP destination port equals 22',app.screen.entry.detail['Conditions'])
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            await pilot.press('escape','escape','escape');await pilot.click('#firewall-logs')
            self.assertIsInstance(app.screen,RecordsDialog);self.assertEqual(3,len(app.screen.records))
            self.assertIs(report['records'][0],app.screen.records[0])
            text=' '.join(str(widget.render()) for widget in app.screen.query(Static))
            self.assertIn('timezone / boot unverified',text)
            await pilot.press('escape','escape','escape');await pilot.click('#firewall-evidence')
            await self.ready(pilot,lambda:app.page==6);self.assertIs(report,app.evidence_selection.report)
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='firewall_report'))
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.resize_terminal(40,12);await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)

    async def test_jail_thresholds_chain_rules_and_source_failures_remain_independent(self):
        runner=Runner();runner.results[Command.UFW_STATUS]=Result('missing');report=self.report(runner)
        async def collector(**options):return report
        app=FaultlensApp(initial_collect=False,firewall_collector=collector)
        async with app.run_test(size=(100,34)) as pilot:
            await pilot.pause(.01);app.push_screen(FirewallDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is not None)
            await pilot.click('#firewall-jails');await pilot.press('enter')
            self.assertIn('maxretry 3',app.screen.entry.detail['Current trigger settings'])
            await pilot.click('#firewall-bans');self.assertEqual(1,len(app.screen.entries))
            await pilot.press('escape','escape','escape');await pilot.click('#firewall-sources')
            table=app.screen.query_one(DataTable);table.move_cursor(row=next(i for i,row in enumerate(app.screen.entries) if row.cells[0]=='ufw'))
            await pilot.press('enter');self.assertIn('No trusted optional',app.screen.entry.detail['What it means'])
            await pilot.press('escape','escape');await pilot.click('#firewall-chains');await pilot.press('enter')
            await pilot.click('#firewall-matches');self.assertIsInstance(app.screen,SourceDialog)
            self.assertTrue(app.screen.entries)

    async def test_cancelled_read_is_cleaned_up_and_does_not_restore_a_cached_policy(self):
        started=asyncio.Event();cancelled=asyncio.Event()
        async def collector(**options):
            started.set()
            try:await asyncio.Future()
            finally:cancelled.set()
        app=FaultlensApp(initial_collect=False,firewall_collector=collector)
        async with app.run_test(size=(90,28)) as pilot:
            await pilot.pause(.01);app.push_screen(FirewallDialog());await self.ready(pilot,started.is_set)
            await pilot.press('escape');await self.ready(pilot,cancelled.is_set)
            self.assertIsNone(app.firewall_snapshot)
