"""Synthetic network evidence navigation through the actual terminal frontend."""
import asyncio
import unittest
from textual.widgets import DataTable
from faultlens.textual_app import FaultlensApp,SourceDialog,DetailDialog,RecordsDialog,RawDialog,ServiceDialog
from faultlens.network_sampling import practical
from faultlens.workspace import Entry
from faultlens.incidents import diagnose
from tests.support import SyntheticNetworkSources,SyntheticSocketRunner
from tests.test_service import service_report
from tests.test_firewall import FirewallRunner,TCP
from tests.test_incidents import record


class NetworkInvestigationWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2

    def app(self):
        async def service_collector(unit):return service_report(unit)
        app=FaultlensApp(initial_collect=False,service_collector=service_collector)
        app.snapshots[2]=practical(SyntheticNetworkSources(),SyntheticSocketRunner(),sample_seconds=.05,sockets=True)
        return app

    async def source(self,app,pilot,kind):
        app.select_page(2);await pilot.pause(.01)
        app.query_one('#grid-2',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[2]) if row.kind==kind))
        await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
        return app.screen

    async def test_peer_card_opens_actual_sockets_owners_and_shared_service_reader(self):
        app=self.app()
        async with app.run_test(size=(110,36)) as pilot:
            screen=await self.source(app,pilot,'network_issues')
            screen.query_one(DataTable).move_cursor(row=next(i for i,row in enumerate(screen.entries) if row.original.get('reported_peer')))
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('198.51.100.1',app.screen.entry.detail['Observed'])
            self.assertIn('Alternative explanations',app.screen.entry.detail)
            await pilot.click('#network-sockets');self.assertIsInstance(app.screen,SourceDialog)
            self.assertEqual(512,len(app.screen.entries));await pilot.press('enter')
            self.assertIsInstance(app.screen,DetailDialog);await pilot.click('#socket-owners')
            self.assertIsInstance(app.screen,SourceDialog);await pilot.press('enter')
            self.assertIsInstance(app.screen,ServiceDialog)
            async with asyncio.timeout(4):
                while app.screen.report is None:await pilot.pause(.01)
            self.assertEqual('example-worker.service',app.screen.report['unit'])
            await pilot.press('escape','escape','escape');await pilot.resize_terminal(40,10);await pilot.pause(.01)
            self.assertIsInstance(app.screen,SourceDialog);self.assertGreater(app.screen.query_one(DataTable).row_count,0)

    async def test_dual_stack_context_intervals_and_originals_remain_readable(self):
        app=self.app()
        async with app.run_test(size=(100,32)) as pilot:
            screen=await self.source(app,pilot,'network_context')
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            self.assertEqual(128,len(app.screen.entries));self.assertIn('2001:db8::1',' '.join(app.screen.entries[0].cells))
            await pilot.press('enter','e');self.assertIsInstance(app.screen,RawDialog)
            self.assertEqual('net0',app.screen.value['ifname'])
            await pilot.press('escape','escape','escape','escape')
            screen=await self.source(app,pilot,'network_samples')
            self.assertEqual(3,len(screen.entries));await pilot.press('enter')
            self.assertIn('Measurements',app.screen.entry.detail)
            self.assertIn('packets/s',str(app.screen.entry.detail['Measurements']))

    async def test_historical_card_opens_referenced_records_and_bounded_log_followup(self):
        rows=[record(TCP.replace('DPT=22','DPT='+str(2000+i)),monotonic=i,__CURSOR='i='+str(i)) for i in range(10)]
        data=diagnose(FirewallRunner(rows),search_firewall=True)
        app=self.app();app.session.settings.boot_selector='b'*32
        async with app.run_test(size=(110,36)) as pilot:
            await pilot.pause(.01)
            app.open_entry(Entry(('Network observations',),data['network_review'],kind='network_issues'),data)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('2000',app.screen.entry.detail['Observed'])
            await pilot.click('#network-records');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertEqual(10,len(app.screen.records));self.assertIn('DPT=2000',app.screen.records[0]['message'])
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            await pilot.press('escape','escape');await pilot.click('#network-logs');await pilot.pause(.01)
            self.assertEqual('period',app.session.settings.investigation_mode)
            self.assertEqual('',app.session.settings.boot_selector)
            self.assertTrue(app.session.settings.search_ssh);self.assertTrue(app.session.settings.search_firewall)
            self.assertEqual(5,app.page);self.assertIn('not peer-filtered',app.notice)
            self.assertLess(int(app.session.settings.since_us),int(app.session.settings.until_us))
