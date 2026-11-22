"""Real frontend navigation preserves selected original evidence across source changes."""
import asyncio
import copy
import unittest
from dataclasses import asdict
from textual.widgets import DataTable,Static

from faultlens.textual_app import FaultlensApp,DetailDialog,RecordsDialog,RawDialog,SourceDialog,ServiceDialog
from faultlens.workflows import collect
from faultlens.overview import incidents
from faultlens.workspace import Entry,source_table
from tests.test_problem_workflows import Runner,START,END
from tests.test_incident_overview import OverviewRunner
from tests.test_service import service_report,ServiceRunner


class InvestigationFlowWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2

    async def ready(self,pilot,condition):
        async with asyncio.timeout(4):
            while not condition():await pilot.pause(.01)

    def inquiry(self):return collect(Runner(),mode='period',since_us=START,until_us=END)

    async def select(self,app,pilot,page,kind):
        app.select_page(page);await self.ready(pilot,lambda:app.page==page)
        app.query_one('#grid-'+str(page),DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[page]) if row.kind==kind))
        await pilot.press('enter')

    async def test_history_event_opens_original_message_and_selected_period_without_forcing_boot(self):
        history=incidents(OverviewRunner());app=FaultlensApp(initial_collect=False);app.snapshots[4]=history
        app.session.settings.boot_selector='b'*32
        async with app.run_test(size=(110,34)) as pilot:
            await self.select(app,pilot,4,'history_event');self.assertIsInstance(app.screen,DetailDialog)
            event=app.screen.entry.original
            await pilot.click('#history-record');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertIs(event['record'],app.screen.records[0]);await pilot.press('escape')
            await pilot.click('#history-period');await self.ready(pilot,lambda:app.page==5)
            self.assertEqual('period',app.session.settings.investigation_mode);self.assertEqual('',app.session.settings.boot_selector)
            timestamp=event['reference']['realtime_us']
            self.assertEqual((timestamp-60000000,timestamp+60000000),(int(app.session.settings.since_us),int(app.session.settings.until_us)))
            self.assertIs(history,app.inquiry_anchor.report)
            self.assertTrue(any(row.kind=='inquiry_origin' for row in app.entries[5]))
            self.assertIsNone(app.job)

    async def test_pinned_finding_keeps_original_partition_after_refresh_and_unrelated_tab_visit(self):
        first=self.inquiry();app=FaultlensApp(initial_collect=False);app.snapshots[5]=first
        async with app.run_test(size=(110,34)) as pilot:
            await self.select(app,pilot,5,'finding');self.assertIsInstance(app.screen,DetailDialog)
            finding=app.screen.entry.original;owner=app.screen.data
            await pilot.press('escape')
            await pilot.press('v');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(owner,app.data(6));self.assertIs(finding,app.evidence_selection.entry.original)
            self.assertIn('optional boot filter none',str(app.query_one('#summary-6',Static).render()))
            replacement=self.inquiry();replacement['collected_at']='2026-01-02T00:00:00+00:00'
            app.snapshots[5]=replacement
            app.select_page(4);await self.ready(pilot,lambda:app.page==4)
            app.select_page(6);await self.ready(pilot,lambda:app.page==6)
            self.assertIs(owner,app.data());self.assertIs(finding,app.evidence_selection.entry.original)
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='finding'))
            await pilot.press('enter');await pilot.click('#references')
            self.assertIsInstance(app.screen,RecordsDialog);self.assertEqual(owner['selected_boot']['boot_id'],app.screen.records[0]['reference']['boot_id'])
            await pilot.press('escape','escape')
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='current_evidence'))
            await pilot.press('enter');self.assertIsNone(app.evidence_selection);self.assertIs(replacement,app.data())

    async def test_records_can_be_pinned_and_returned_to_source_without_collection(self):
        report=self.inquiry();owner=report['investigations'][0];record=owner['journal_records'][0]
        calls=[]
        async def collector(page,settings):calls.append(page);return report
        app=FaultlensApp(initial_collect=False,collector=collector);app.snapshots[5]=report
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(5);await self.ready(pilot,lambda:app.page==5)
            app.push_screen(RecordsDialog(owner,record=record));await pilot.pause(.01)
            await pilot.click('#pin-evidence');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(record,app.evidence_selection.entry.original[0]);self.assertEqual([],calls)
            await self.select(app,pilot,6,'retained_records');self.assertIsInstance(app.screen,RecordsDialog)
            await pilot.press('e');self.assertIsInstance(app.screen,RawDialog);self.assertIs(record,app.screen.value[0])
            await pilot.press('escape','escape')
            await self.select(app,pilot,6,'return_source');await self.ready(pilot,lambda:app.page==5)
            self.assertEqual([],calls)

    async def test_pinned_service_message_preview_keeps_full_literal_message(self):
        from faultlens.service import collect as service_collect
        message='Synthetic worker failure: [bold]connection refused[/]\x1b]52;c;synthetic\x07'
        report=service_collect('example-worker.service',ServiceRunner([message]))
        _,_,rows=source_table(Entry(('Messages',),report,None,'service_messages'),report)
        app=FaultlensApp(initial_collect=False)
        async with app.run_test(size=(110,34)) as pilot:
            await pilot.pause(.01)
            app.show_evidence(rows[0],report);await self.ready(pilot,lambda:app.page==6)
            await pilot.pause(.05)
            table=app.query_one('#grid-6',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='service_message'))
            await pilot.pause(.05)
            preview=str(app.query_one('#selected-evidence-6',Static).render())
            self.assertIn('Synthetic worker failure: [bold]connection refused[/]',preview)
            self.assertIn('\\u001b',preview);self.assertNotIn('\x1b',preview)
            self.assertEqual(message,app.evidence_selection.entry.original['message'])

    async def test_pin_from_unpinned_evidence_returns_to_inquiry_instead_of_itself(self):
        report=self.inquiry();calls=[]
        async def collector(page,settings):calls.append(page);return report
        app=FaultlensApp(initial_collect=False,collector=collector);app.snapshots[5]=report
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(6);await self.ready(pilot,lambda:app.page==6)
            app.query_one('#grid-6',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[6]) if row.kind=='finding'))
            await pilot.press('v')
            self.assertEqual(5,app.evidence_selection.page)
            await self.select(app,pilot,6,'return_source');await self.ready(pilot,lambda:app.page==5)
            self.assertIs(report,app.data());self.assertEqual([],calls)

    async def test_pin_from_unpinned_evidence_returns_to_last_source_without_inquiry(self):
        from faultlens.tui_model import Session
        from tests.support import SyntheticSources,SyntheticRunner
        session=Session(sources=SyntheticSources(),runner=SyntheticRunner());session.refresh();report=session.data
        app=FaultlensApp(initial_collect=False);app.snapshots[0]=report
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(6);await self.ready(pilot,lambda:app.page==6)
            app.action_evidence()
            self.assertEqual(0,app.evidence_selection.page)
            await self.select(app,pilot,6,'return_source');await self.ready(pilot,lambda:app.page==0)
            self.assertIs(report,app.data());self.assertIsNone(app.job)

    async def test_service_report_pin_reopens_retained_messages_without_requery(self):
        calls=[]
        async def service(unit):calls.append(unit);return service_report(unit)
        app=FaultlensApp(initial_collect=False,service_collector=service);app.snapshots[5]=self.inquiry()
        async with app.run_test(size=(110,34)) as pilot:
            app.open_entry(Entry(('example-worker.service',),{'unit':'example-worker.service'},kind='service'),app.snapshots[5])
            await self.ready(pilot,lambda:app.screen.report is not None)
            retained=app.screen.report
            await pilot.click('#service-evidence');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(retained,app.data())
            await self.select(app,pilot,6,'service_messages');self.assertIsInstance(app.screen,SourceDialog)
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIs(retained,app.screen.data);self.assertEqual(['example-worker.service'],calls)

    async def test_signals_reuse_inquiry_and_evidence_pin_survives_compact_resize(self):
        report=self.inquiry();calls=[]
        async def collector(page,settings):calls.append(page);return report
        app=FaultlensApp(initial_collect=False,collector=collector);app.snapshots[5]=report
        async with app.run_test(size=(100,30)) as pilot:
            await self.select(app,pilot,3,'finding')
            finding=app.screen.entry.original
            await pilot.resize_terminal(40,10);await pilot.press('v');await self.ready(pilot,lambda:app.page==6)
            self.assertIs(finding,app.evidence_selection.entry.original);self.assertEqual(3,app.evidence_selection.page)
            await self.select(app,pilot,6,'return_source');await self.ready(pilot,lambda:app.page==3)
            self.assertIs(report,app.data());self.assertEqual([],calls)

    async def test_whole_inquiry_pin_opens_retained_report_and_continue_preserves_stale_options(self):
        report=self.inquiry();calls=[]
        async def collector(page,settings):calls.append(page);return self.inquiry()
        app=FaultlensApp(collector=collector,initial_collect=False);app.snapshots[5]=report
        app.snapshot_options[5]=asdict(app.session.settings)
        async with app.run_test(size=(110,34)) as pilot:
            app.select_page(3);await self.ready(pilot,lambda:app.page==3)
            app.query_one('#grid-3',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[3]) if row.kind=='investigation_focus'))
            await pilot.press('v');await self.ready(pilot,lambda:app.page==6)
            self.assertEqual('retained_report',app.evidence_selection.entry.kind)
            app.snapshots[5]=self.inquiry()
            await self.select(app,pilot,6,'retained_report');self.assertIsInstance(app.screen,SourceDialog)
            self.assertIs(report,app.screen.entry.original);self.assertIs(report,app.screen.data)
            await pilot.press('escape')
            app.select_page(3);await self.ready(pilot,lambda:app.page==3)
            app.session.settings.system_journal=True;app.initial_collect=True
            app.query_one('#grid-3',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[3]) if row.kind=='investigation_focus'))
            current=app.snapshots[5];await pilot.press('enter');await self.ready(pilot,lambda:app.page==5)
            await pilot.pause(.03)
            self.assertIs(current,app.data());self.assertEqual([],calls)
            self.assertIn('SETTINGS CHANGED',str(app.query_one('#status-line',Static).render()))

    async def test_settings_explain_purpose_and_cached_access_without_collection(self):
        app=FaultlensApp(initial_collect=False);app.snapshots[5]=self.inquiry()
        original=asdict(app.session.settings)
        async with app.run_test(size=(100,30)) as pilot:
            app.select_page(7);await self.ready(pilot,lambda:app.page==7)
            row=next(row for row in app.entries[7] if row.original=='search_ssh')
            self.assertIn('not all key/PAM/MFA',row.cells[2]);self.assertIn('No retained query state',row.cells[2])
            row=next(row for row in app.entries[7] if row.original=='since_us')
            self.assertIn('Selected period',row.cells[2]);self.assertEqual(original,asdict(app.session.settings));self.assertIsNone(app.job)
