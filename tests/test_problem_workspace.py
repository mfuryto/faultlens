"""Actual primary UI actions select questions/time, keeping boot filters optional."""
import asyncio
import copy
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch

from textual.widgets import DataTable,Input,Static
from faultlens.textual_app import FaultlensApp,PeriodDialog,DetailDialog,RecordsDialog,ValueDialog
from faultlens.tui_model import Settings,investigation_options
from faultlens.ui_collection import arguments
from faultlens.workflows import collect
from tests.test_problem_workflows import Runner,START,END,A,B
from tests.support import SyntheticNetworkSources,SyntheticSources


class ProblemWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2
    async def wait_until(self,pilot,condition):
        async with asyncio.timeout(3):
            while not condition():await pilot.pause(.01)
    def app(self):
        self.calls=[]
        async def collector(page,settings):
            if page!=5:raise ValueError('Synthetic test models investigation only')
            self.calls.append(copy.deepcopy(settings))
            return collect(Runner(),sources=SyntheticNetworkSources(),clock=lambda:END/1000000,
                           pstore_collector=SyntheticSources().pstore_snapshot,
                           pstore_archive_collector=SyntheticSources().pstore_snapshot,
                           **investigation_options(settings))
        return FaultlensApp(collector=collector,initial_collect=False)

    async def test_period_action_is_atomic_and_cross_boot_records_keep_their_context(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(5);await self.wait_until(pilot,lambda:app.page==5)
            self.assertEqual(['now','period','before-restart'],[row.original for row in app.entries[5] if row.kind=='investigation_start'])
            table=app.query_one('#grid-5',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[5]) if row.kind=='investigation_start' and row.original=='period'))
            app.action_open();await pilot.pause(.01);self.assertIsInstance(app.screen,PeriodDialog)
            before=asdict(app.session.settings)
            app.screen.query_one('#period-start',Input).value='2026-01-01T00:02:00Z'
            app.screen.query_one('#period-end',Input).value='2026-01-01T00:00:00Z'
            await pilot.click('#period-apply');self.assertIsInstance(app.screen,PeriodDialog)
            self.assertEqual(before,asdict(app.session.settings));self.assertEqual([],self.calls)
            app.screen.query_one('#period-start',Input).value='2026-01-01T00:00:00Z'
            app.screen.query_one('#period-end',Input).value='2026-01-01T00:02:00Z'
            app.initial_collect=True
            app.screen.query_one('#period-end',Input).focus()
            await pilot.press('enter')
            await self.wait_until(pilot,lambda:5 in app.snapshots and app.job is None)
            self.assertEqual('',app.session.settings.boot_selector)
            self.assertEqual('period',app.session.settings.investigation_mode)
            self.assertEqual(2,len(app.snapshots[5]['investigations']))
            for identity in (A,B):
                index=next(i for i,row in enumerate(app.entries[5]) if row.kind=='finding' and row.context['selected_boot']['boot_id']==identity)
                table.move_cursor(row=index);app.action_open();await pilot.pause(.01)
                self.assertIsInstance(app.screen,DetailDialog)
                await pilot.click('#references');self.assertIsInstance(app.screen,RecordsDialog)
                self.assertTrue(all(row['reference']['boot_id']==identity for row in app.screen.records))
                await pilot.press('escape','escape')
            for value,count in ((A,1),('',2)):
                index=next(i for i,row in enumerate(app.entries[5]) if row.kind=='setting')
                table.move_cursor(row=index);app.action_open();await pilot.pause(.01)
                self.assertIsInstance(app.screen,ValueDialog)
                app.screen.query_one(Input).value=value
                await pilot.press('enter')
                await self.wait_until(pilot,lambda:app.job is None and app.snapshots.get(5,{}).get('boot_filter',{}).get('requested')==(value or None))
                self.assertEqual(count,len(app.snapshots[5]['investigations']))
            await pilot.resize_terminal(40,10)
            self.assertEqual(5,app.page)

    async def test_now_and_pre_restart_are_direct_actions_and_clear_old_filters(self):
        app=self.app()
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(5);await self.wait_until(pilot,lambda:app.page==5)
            app.initial_collect=True
            app.session.settings.boot_selector=A
            app.session.settings.since_us=str(START);app.session.settings.until_us=str(END)
            app.start_investigation('now')
            await self.wait_until(pilot,lambda:5 in app.snapshots and app.job is None)
            self.assertEqual('',app.session.settings.boot_selector)
            self.assertEqual('now',app.snapshots[5]['mode']);self.assertTrue(app.snapshots[5]['current'])
            app.start_investigation('before-restart')
            await self.wait_until(pilot,lambda:app.snapshots.get(5,{}).get('mode')=='before-restart' and app.job is None)
            self.assertEqual(A,app.snapshots[5]['boot_filter']['resolved'])
            self.assertEqual({},app.snapshots[5]['current'])
            self.assertEqual(str(START),app.session.settings.since_us)


class RequestTests(unittest.TestCase):
    def test_primary_arguments_do_not_send_a_boot_filter_or_saved_period_for_now(self):
        settings=Settings.administrator_defaults();settings.since_us=str(START);settings.until_us=str(END)
        args=arguments(5,settings)
        self.assertEqual(['investigate','--json','--mode','now'],args[:4])
        for flag in ('--boot','--boot-id','--since-us','--until-us'):self.assertNotIn(flag,args)
        settings.investigation_mode='period';settings.boot_selector=B
        args=arguments(5,settings)
        self.assertIn('--since-us',args);self.assertIn('--boot-id',args)
        settings.boot_selector='';self.assertNotIn('--boot-id',arguments(5,settings))
        settings.search_events=False;self.assertIn('--no-search-events',arguments(5,settings))
