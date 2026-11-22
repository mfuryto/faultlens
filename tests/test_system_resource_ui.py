"""Synthetic process/storage navigation, failures and literal original evidence."""
import asyncio
import unittest
from textual.widgets import DataTable

from faultlens.filesystems import capacity
from faultlens.textual_app import FaultlensApp,SourceDialog,DetailDialog,RawDialog,ServiceDialog
from faultlens.tui_model import Session
from tests.support import SyntheticRunner,SyntheticSources
from tests.system_resource_fixtures import fs_values
from tests.test_service import service_report


class SystemResourceWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2

    def app(self):
        session=Session(sources=SyntheticSources(),runner=SyntheticRunner());session.refresh()
        async def service_collector(unit):return service_report(unit)
        app=FaultlensApp(session=session,initial_collect=False,service_collector=service_collector)
        app.snapshots[0]=session.data
        return app

    async def open_source(self,app,pilot,kind):
        await pilot.pause(0.01)
        app.query_one('#grid-0',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[0]) if row.kind==kind))
        await pilot.press('enter');self.assertIsInstance(app.screen,SourceDialog)
        return app.screen

    async def test_process_cpu_rss_original_and_reported_service_navigation(self):
        app=self.app();row=app.snapshots[0]['processes']['rows'][0]
        row['name']='synthetic\x1b[31m\n[bold] worker'
        async with app.run_test(size=(110,34)) as pilot:
            source=await self.open_source(app,pilot,'processes')
            self.assertEqual(2,len(source.entries))
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('one logical CPU',app.screen.entry.detail['CPU sample'])
            self.assertIn('RSS',app.screen.entry.detail['What it means'])
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog)
            self.assertIs(row,app.screen.value)
            await pilot.press('escape');await pilot.click('#process-service')
            self.assertIsInstance(app.screen,ServiceDialog)
            async with asyncio.timeout(4):
                while app.screen.report is None:await pilot.pause(0.01)
            self.assertEqual('example-worker.service',app.screen.report['unit'])
            await pilot.press('escape','escape');await pilot.resize_terminal(40,10)
            await pilot.pause(0.01);self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)

    async def test_full_independent_mount_inodes_and_unmeasured_rows_remain_accessible(self):
        app=self.app();source=app.snapshots[0]['filesystems']
        var=next(row for row in source['rows'] if row['target']=='/var')
        var['capacity']=capacity(fs_values(20,99))
        run=next(row for row in source['rows'] if row['target']=='/run')
        run.update(state='not_probed',capacity=None,reason='filesystem_type_not_probed',filesystem_type='nfs')
        async with app.run_test(size=(100,30)) as pilot:
            await pilot.pause(0.01)
            self.assertTrue(any(row.cells[0]=='/var' and 'Critical' in row.cells for row in app.entries[0]))
            screen=await self.open_source(app,pilot,'filesystems')
            self.assertEqual(3,len(screen.entries));self.assertIs(var,screen.entries[0].original)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('99.0%',str(app.screen.entry.detail['Measurements']))
            await pilot.press('escape')
            screen.query_one(DataTable).move_cursor(row=next(i for i,row in enumerate(screen.entries) if row.original is run))
            await pilot.press('enter');self.assertIn('without capacity',app.screen.entry.detail['Observed'])
            self.assertIn('No capacity',str(app.screen.entry.detail['Measurements']))

    async def test_unavailable_or_empty_sources_do_not_display_zero_cpu_or_healthy_storage(self):
        app=self.app()
        for key in ('processes','filesystems'):
            app.snapshots[0][key].update(state='unavailable',rows=[],coverage={},reason='command_unsuccessful')
        async with app.run_test(size=(80,24)) as pilot:
            await pilot.pause(0.01)
            for kind in ('processes','filesystems'):
                entry=next(row for row in app.entries[0] if row.kind==kind)
                self.assertIn('Could not be assessed',entry.cells);self.assertIn('Gap',entry.cells)
                screen=await self.open_source(app,pilot,kind)
                self.assertEqual([],screen.entries)
                await pilot.press('escape')
