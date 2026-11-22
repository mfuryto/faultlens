"""Synthetic failed-service navigation and cancellable unit reads in the real frontend."""
import asyncio
import unittest
from textual.widgets import Button,DataTable,Static

from faultlens.health import collect
from faultlens.textual_app import FaultlensApp,SourceDialog,ServiceDialog,RecordsDialog,RawDialog
from faultlens.commands import Command,Result
from tests.support import SyntheticSources,SyntheticRunner
from tests.test_service import ServiceRunner,service_report,PARSER_ERROR


class ServiceWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition(): await pilot.pause(0.01)

    def app(self,collector):
        runner=SyntheticRunner()
        runner.results[Command.FAILED_SERVICES]=Result('completed','apparmor.service loaded failed failed Synthetic profile loader\n',0)
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
            await pilot.press('enter');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertEqual(PARSER_ERROR,app.screen.records[0]['message'])
            self.assertEqual(3,len(app.screen.records))
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            await pilot.press('escape','escape','r');await self.ready(pilot,lambda:len(calls)==2 and screen.collection_task is None)
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

    async def test_controlled_child_cli_uses_literal_unit_and_cancellation_contract(self):
        from unittest.mock import patch
        from faultlens import ui_collection
        expected=['service','--unit','apparmor.service','--json']
        async def child(args):self.assertEqual(expected,args);return service_report()
        with patch('faultlens.ui_collection.collect_arguments',side_effect=child):
            self.assertEqual('service',(await ui_collection.collect_service('apparmor.service'))['command'])
            with self.assertRaises(ValueError):await ui_collection.collect_service('apparmor*.service')
