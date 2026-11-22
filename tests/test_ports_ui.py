"""Actual port workflow navigation, cancellation and retained evidence semantics."""
import asyncio
import unittest
from textual.widgets import DataTable,Static
from faultlens.commands import Command,Result
from faultlens.ports import collect
from faultlens.textual_app import FaultlensApp,PortsDialog,SourceDialog,DetailDialog,RawDialog,ServiceDialog
from faultlens.network_sampling import practical
from tests.port_fixtures import Runner
from tests.support import SyntheticNetworkSources,SyntheticSocketRunner
from tests.test_service import service_report


class PortWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2
    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition():await pilot.pause(.01)

    async def test_port_list_reports_actual_input_decisions_with_external_scope_separate(self):
        from tests.test_input_policy import runner,match
        data=collect(runner([[match('dport',22),{'accept':None}]]))
        async def collector():return data
        app=FaultlensApp(initial_collect=False,ports_collector=collector)
        async with app.run_test(size=(110,34)) as pilot:
            await pilot.pause(.01);app.push_screen(PortsDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is not None)
            await pilot.click('#ports-listeners')
            self.assertEqual(['Allowed','Blocked','Blocked','Allowed'],[entry.cells[3] for entry in app.screen.entries])
            self.assertIn('Firewall INPUT',app.screen.columns)
            await pilot.press('enter')
            self.assertEqual('Allowed',app.screen.entry.detail['Firewall INPUT assessment'])
            self.assertIn('new UDP',app.screen.entry.detail['Assessment scope'])
            self.assertIn('Unknown',app.screen.entry.detail['External access'])
            await pilot.click('#port-policy');await pilot.press('enter')
            self.assertIn('accept',app.screen.entry.detail['Reported verdicts'])

    async def test_network_port_opens_policy_addresses_routes_service_and_external_guidance(self):
        data=collect(Runner());calls=[];services=[]
        async def collector(**options):calls.append(options);return data
        async def service(unit):services.append(unit);return service_report(unit)
        app=FaultlensApp(initial_collect=False,ports_collector=collector,service_collector=service)
        app.snapshots[2]=practical(SyntheticNetworkSources(),SyntheticSocketRunner(),sample_seconds=.05,sockets=True)
        async with app.run_test(size=(110,36)) as pilot:
            app.select_page(2);await self.ready(pilot,lambda:app.page==2)
            self.assertEqual([],calls)
            app.query_one('#grid-2',DataTable).move_cursor(row=next(i for i,r in enumerate(app.entries[2]) if r.kind=='port_accessibility'))
            await pilot.press('enter');dialog=app.screen;self.assertIsInstance(dialog,PortsDialog)
            await self.ready(pilot,lambda:dialog.report is not None);self.assertEqual([{}],calls)
            self.assertFalse(dialog.query('#ports-boot'));await pilot.click('#ports-listeners');await pilot.press('enter')
            self.assertIsInstance(app.screen,DetailDialog);self.assertIn('0.0.0.0:22',str(app.screen.entry.detail))
            self.assertIn('example-worker.service',str(app.screen.entry.detail))
            await pilot.click('#port-policy');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIn('TCP destination port equals 22',app.screen.entry.detail['Conditions'])
            self.assertIn('192.0.2.7',str(app.screen.entry.detail['Referenced set evidence']))
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog);self.assertIn('example_bans',str(app.screen.value))
            await pilot.press('escape','escape','escape');await pilot.click('#port-addresses');await pilot.press('enter')
            self.assertIn('192.0.2.1',str(app.screen.entry.detail));await pilot.press('escape','escape')
            await pilot.click('#port-routes');await pilot.press('enter');self.assertIn('do not verify',app.screen.entry.detail['What it means'])
            await pilot.press('escape','escape');await pilot.click('#port-service');await pilot.press('enter')
            self.assertIsInstance(app.screen,ServiceDialog);await self.ready(pilot,lambda:app.screen.report is not None)
            self.assertEqual(['example-worker.service'],services);await pilot.press('escape','escape')
            await pilot.click('#port-external');self.assertIn('Not performed',app.screen.entry.detail['State'])
            self.assertIn('TCP connection',app.screen.entry.detail['TCP check']);await pilot.press('escape')
            await pilot.click('#pin-evidence');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(data,app.evidence_selection.report)
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,r in enumerate(app.entries[6]) if r.kind=='port'))
            await pilot.press('enter');self.assertIn('External access',app.screen.entry.detail)
            await pilot.resize_terminal(40,12);await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            self.assertIn('tcp LISTEN',app.screen.value['socket']['original']);self.assertEqual([{}],calls)

    async def test_translation_without_listener_and_unavailable_family_are_explained(self):
        runner=Runner();runner.results[Command.LISTENERS4]=Result('completed','',0);runner.results[Command.LISTENERS6]=Result('missing');data=collect(runner)
        async def collector():return data
        app=FaultlensApp(initial_collect=False,ports_collector=collector)
        async with app.run_test(size=(90,30)) as pilot:
            await pilot.pause(.01);app.push_screen(PortsDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is not None)
            text=str(dialog.query_one('#ports-explanation',Static).render());self.assertIn('family was unavailable',text)
            await pilot.click('#ports-translations');await pilot.press('enter')
            self.assertIn('8080',str(app.screen.entry.detail));self.assertIn('192.0.2.10',str(app.screen.entry.detail))
            await pilot.click('#port-policy');self.assertTrue(app.screen.entries)
            await pilot.press('escape','escape','escape');await pilot.click('#ports-evidence')
            await self.ready(pilot,lambda:app.page==6)
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,r in enumerate(app.entries[6]) if r.kind=='ports_report'))
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.resize_terminal(40,10);await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            self.assertEqual([],app.screen.entries)

    async def test_serial_refresh_cancel_and_failure_do_not_revive_old_exposure_data(self):
        first=collect(Runner());calls=[];started=asyncio.Event();cleaned=asyncio.Event()
        async def collector():
            calls.append(1)
            if len(calls)==1:return first
            started.set()
            try:await asyncio.Future()
            finally:cleaned.set()
        app=FaultlensApp(initial_collect=False,ports_collector=collector)
        async with app.run_test(size=(90,30)) as pilot:
            await pilot.pause(.01);app.push_screen(PortsDialog());dialog=app.screen
            await self.ready(pilot,lambda:dialog.report is first)
            await pilot.press('escape');app.push_screen(PortsDialog());await pilot.pause(.02)
            self.assertEqual(1,len(calls));await pilot.press('r');await self.ready(pilot,started.is_set)
            self.assertIsNone(app.ports_snapshot);await pilot.press('escape');await self.ready(pilot,cleaned.is_set)
            self.assertIsNone(app.ports_snapshot)
            async def unavailable():raise ValueError('Synthetic unavailable source')
            app.ports_collector=unavailable;app.push_screen(PortsDialog());dialog=app.screen
            await self.ready(pilot,lambda:bool(dialog.query('#ports-explanation')) and 'unavailable' in str(dialog.query_one('#ports-explanation',Static).render()))
            self.assertIsNone(dialog.report);self.assertIsNone(app.ports_snapshot)
