"""Synthetic failed-service navigation and cancellable unit reads in the real frontend."""
import asyncio
import unittest
from textual.widgets import Button,DataTable,Static

from faultlens.health import collect
from faultlens.textual_app import FaultlensApp,SourceDialog,ServiceDialog,RecordsDialog,RawDialog,DetailDialog
from faultlens.commands import Command,Result
from tests.support import SyntheticSources,SyntheticRunner
from tests.test_service import ServiceRunner,service_report,PARSER_ERROR


class ServiceWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition(): await pilot.pause(0.01)

    def app(self,collector,unit="apparmor.service"):
        runner=SyntheticRunner()
        runner.results[Command.FAILED_SERVICES]=Result('completed',unit+' loaded failed failed Synthetic service\n',0)
        app=FaultlensApp(initial_collect=False,service_collector=collector)
        app.snapshots[1]=collect(SyntheticSources(),runner,sample_seconds=0.05)
        return app

    async def open_service(self,app,pilot):
        app.select_page(1);await self.ready(pilot,lambda:app.page==1)
        table=app.query_one('#grid-1',DataTable)
        table.move_cursor(row=next(i for i,row in enumerate(app.entries[1]) if row.kind=='failed_services'))
        await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
        await pilot.press('enter');self.assertIsInstance(app.screen,ServiceDialog)
        return app.screen

    async def test_enter_loads_explains_and_opens_all_messages_and_original_fields(self):
        calls=[]
        async def collector(unit): calls.append(unit);return service_report(unit)
        app=self.app(collector)
        async with app.run_test(size=(105,32)) as pilot:
            screen=await self.open_service(app,pilot)
            await self.ready(pilot,lambda:screen.report is not None)
            self.assertEqual(['apparmor.service'],calls)
            self.assertIn('could not open',str(screen.query_one('#service-explanation',Static).render()))
            self.assertIn('line 17',str(screen.query_one('#service-explanation',Static).render()))
            await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn(PARSER_ERROR,app.screen.entry.detail['Recorded message'])
            await pilot.click('#service-context');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertEqual(PARSER_ERROR,app.screen.records[0]['message'])
            self.assertEqual(3,len(app.screen.records))
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            await pilot.press('escape','escape','escape','escape','r');await self.ready(pilot,lambda:len(calls)==2 and screen.collection_task is None)
            await pilot.resize_terminal(45,12);await pilot.pause(0.01)
            self.assertTrue(screen.query_one('#service-logs',Button).is_mounted)
            await pilot.press('escape','escape');self.assertEqual(1,len(app.screen_stack))

    async def test_loading_cancellation_releases_worker_and_preserves_parent(self):
        started=asyncio.Event();cancelled=asyncio.Event()
        async def collector(unit):
            started.set()
            try:await asyncio.Event().wait()
            finally:cancelled.set()
        app=self.app(collector)
        async with app.run_test(size=(100,30)) as pilot:
            screen=await self.open_service(app,pilot);await started.wait()
            self.assertTrue(screen.query_one('#service-logs',Button).disabled)
            await pilot.press('escape');await asyncio.wait_for(cancelled.wait(),3)
            self.assertIsInstance(app.screen,SourceDialog)
            self.assertIsNone(screen.collection_task)

    async def test_failed_and_unavailable_reads_are_explained_and_can_retry(self):
        calls=[]
        async def collector(unit):
            calls.append(unit)
            if len(calls)==1:raise ValueError('Synthetic worker error')
            runner=ServiceRunner();runner.journal_result=Result('timeout')
            from faultlens.service import collect
            return collect(unit,runner)
        app=self.app(collector)
        async with app.run_test(size=(100,30)) as pilot:
            screen=await self.open_service(app,pilot)
            await self.ready(pilot,lambda:screen.collection_task is None)
            self.assertIsNone(screen.report)
            self.assertIn('No fault or absence',str(screen.query_one('#service-explanation',Static).render()))
            await pilot.press('r');await self.ready(pilot,lambda:screen.report is not None)
            self.assertIn('logs unavailable',str(screen.query_one('#service-explanation',Static).render()))
            self.assertTrue(screen.query_one('#service-logs',Button).disabled)
            self.assertFalse(screen.query_one('#service-original',Button).disabled)

    async def test_arbitrary_service_unknown_message_can_open_context_and_period(self):
        from faultlens.service import collect
        from faultlens.service_diagnostics import followup_window
        for unit in ('example-web.service','example-mail.service','example-worker@one.service'):
            async def collector(selected):return collect(selected,ServiceRunner(['Synthetic unfamiliar failure']))
            app=self.app(collector,unit)
            async with app.run_test(size=(110,34)) as pilot:
                screen=await self.open_service(app,pilot)
                await self.ready(pilot,lambda:screen.report is not None)
                self.assertEqual(unit,screen.report['unit'])
                await pilot.press('enter','enter');self.assertIsInstance(app.screen,DetailDialog)
                record=app.screen.entry.original
                self.assertIn('No supported specific',app.screen.entry.detail['What it means'])
                await pilot.click('#service-period')
                await self.ready(pilot,lambda:app.page==5 and len(app.screen_stack)==1)
                self.assertEqual('period',app.session.settings.investigation_mode)
                self.assertEqual('',app.session.settings.boot_selector)
                start,end=followup_window(record)
                self.assertEqual((str(start),str(end)),(app.session.settings.since_us,app.session.settings.until_us))
                self.assertIsNone(app.job)

    async def test_common_network_error_can_open_current_network_from_message(self):
        from faultlens.service import collect
        async def collector(unit):return collect(unit,ServiceRunner(['Synthetic bind: Address already in use']))
        app=self.app(collector,'example-web.service')
        async with app.run_test(size=(110,34)) as pilot:
            screen=await self.open_service(app,pilot);await self.ready(pilot,lambda:screen.report is not None)
            await pilot.press('enter','enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertEqual(2,app.screen.entry.navigation['current_page'])
            await pilot.click('#service-current')
            await self.ready(pilot,lambda:app.page==2 and len(app.screen_stack)==1)
            self.assertIn('earlier service error',app.notice)

    async def test_controlled_child_cli_uses_literal_unit_and_cancellation_contract(self):
        from unittest.mock import patch
        from faultlens import ui_collection
        expected=['service','--unit','apparmor.service','--json']
        async def child(args):self.assertEqual(expected,args);return service_report()
        with patch('faultlens.ui_collection.collect_arguments',side_effect=child):
            self.assertEqual('service',(await ui_collection.collect_service('apparmor.service'))['command'])
            with self.assertRaises(ValueError):await ui_collection.collect_service('apparmor*.service')
