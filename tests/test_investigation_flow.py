"""Invented incidents exercise operator decisions, exact messages and non-causal gaps."""
import asyncio
import copy
import io
import json
import unittest
from unittest.mock import patch

from textual.widgets import DataTable,Static
from faultlens.cli import main
from faultlens.commands import Result,CommandRunner
from faultlens.incidents import diagnose
from faultlens.investigation import story,finding_detail,linked_records
from faultlens.journal import UNIT_START_FAILED,SHUTDOWN_REQUEST
from faultlens.textual_app import FaultlensApp,DetailDialog,RecordsDialog
from faultlens.tui_model import Settings
from faultlens.workspace import page_table
from tests.test_incidents import record,JournalRunner
from tests.test_atop import AtopRunner,sample,EPOCH
from tests.test_incident_overview import OverviewRunner,IDS
from faultlens.overview import incidents


def incident(message='Out of memory: Killed process 42 (example-worker)',**fields):
    return record(message,__CURSOR='s=synthetic-record',**fields)


class InvestigationTests(unittest.TestCase):
    def test_oom_shows_killed_process_exact_time_and_proportionate_follow_up(self):
        data=diagnose(JournalRunner([incident()]),show_evidence=True)
        original=copy.deepcopy(data);finding=data['findings'][0]
        detail=finding_detail(data,finding)
        self.assertIn('example-worker',str(detail['Recorded evidence']))
        self.assertIn('2026-01-01T00:00:00.000000+00:00',str(detail['Recorded evidence']))
        self.assertIn('memory',str(detail['What you can do']))
        self.assertIs(data['journal_records'][0],linked_records(data,finding)[0])
        self.assertIn('Recorded problems',story(data)['answer'])
        self.assertEqual('Unknown',data['root_cause']);self.assertEqual(original,data)
        output=io.StringIO();main(['diagnose'],runner=JournalRunner([incident()]),stdout=output)
        self.assertIn('Killed process 42 (example-worker)',output.getvalue())
        self.assertIn('Recorded:',output.getvalue())
        output=io.StringIO();main(['diagnose','--json'],runner=JournalRunner([incident()]),stdout=output)
        self.assertNotIn('journal_records',json.loads(output.getvalue()))

    def test_failed_service_and_shutdown_reports_are_not_verified_host_causes(self):
        for message,marker,expected in [('example-worker.service failed to start',UNIT_START_FAILED,'failed unit'),
                                        ('Synthetic shutdown request',SHUTDOWN_REQUEST,'No supported fault')]:
            data=diagnose(JournalRunner([incident(message,_PID='1',_COMM='systemd',_TRANSPORT='journal',MESSAGE_ID=marker)]),show_evidence=True)
            self.assertIn(expected,story(data)['answer'])
            self.assertIn(message,str(finding_detail(data,data['findings'][0])['Recorded evidence']))
            self.assertEqual('Unknown',data['root_cause'])
            if marker==SHUTDOWN_REQUEST:
                self.assertIn('completion unknown',data['shutdown_assessment'])
                self.assertIn('does not prove',story(data)['ending'])

    def test_no_match_and_forced_reboot_like_silence_show_last_evidence_not_a_crash_diagnosis(self):
        data=diagnose(JournalRunner([incident('Synthetic ordinary workload heartbeat')]),show_evidence=True)
        view=story(data);self.assertIn('No supported fault',view['answer'])
        self.assertIn('Later conditions are unknown',view['ending'])
        rows=page_table(5,data,Settings())[1]
        self.assertTrue(any('heartbeat' in row.cells[2] for row in rows))
        self.assertIn('broader event search',view['next'])
        output=io.StringIO();main(['diagnose'],runner=JournalRunner([incident('Synthetic heartbeat')]),stdout=output)
        self.assertIn('Last retained message: Synthetic heartbeat',output.getvalue())

    def test_unavailable_and_unresolved_references_do_not_invent_empty_success_or_a_message(self):
        runner=JournalRunner();runner.result=Result('timeout')
        view=story(diagnose(runner,show_evidence=True))
        self.assertIn('could not be assessed',view['answer'])
        self.assertIn('existing authorized access',view['next'])
        data=diagnose(JournalRunner([incident()]),show_evidence=True)
        data['journal_records'][0]['reference']['cursor_sha256']='f'*64
        detail=finding_detail(data,data['findings'][0])
        self.assertIn('unresolved',detail['Evidence linkage'])
        self.assertNotIn('example-worker',str(detail['Recorded evidence']))

    def test_history_exposes_bounded_report_examples_and_utc_ranges(self):
        runner=OverviewRunner(count=2)
        runner.results[IDS[1]]=Result('completed',json.dumps(incident(_BOOT_ID=IDS[1])),0)
        data=incidents(runner);summary=data['summaries'][0]
        self.assertIn('example-worker',summary['notable_reports'][0]['message_excerpt'])
        columns,rows=page_table(4,data,Settings());row=next(row for row in rows if row.original is summary)
        self.assertNotIn('Boot ID',columns)
        self.assertIn('2026-01-01',row.cells[1])
        event=next(item for item in page_table(4,data,Settings())[1] if item.kind=='history_event')
        self.assertIn('OOM',event.cells[0]);self.assertIn('example-worker',event.cells[3])
        self.assertIn('example-worker',str(row.detail['Recorded examples']))

    def test_reference_deduplication_preserves_distinct_equal_records_and_source_identity(self):
        first={'reference':{'source':'systemd-journal','boot_id':'a'*32},'message':'Synthetic report'}
        second=copy.deepcopy(first)
        finding={'evidence':[{'source_analysis':'ssh_analysis','boot_id':'a'*32,'candidate_indices':[0,0,1]}]}
        data={'ssh_analysis':{'records':[first,second]},'security_analysis':{'findings':[finding]}}
        rows=linked_records(data,finding)
        self.assertEqual(2,len(rows));self.assertIs(first,rows[0]);self.assertIs(second,rows[1])

    def test_two_hour_replay_can_include_six_ten_minute_samples_before_anchor(self):
        anchor=EPOCH+7200
        runner=AtopRunner(records=[incident(realtime=anchor*1000000,monotonic=7200000000)],
            text=''.join(sample(anchor-3000+i*600,period=600) for i in range(6)))
        data=diagnose(runner,atop_date='20260101')
        self.assertEqual(6,len(data['atop']['samples']))
        self.assertFalse(data['atop']['coverage']['possible_gaps'])
        self.assertEqual((anchor-3600,anchor+3600),runner.atop_calls[0][1:])
        self.assertIn('midnight',' '.join(data['atop']['limitations']))
        with self.assertRaises(ValueError): CommandRunner().read_atop('20260101',anchor,anchor+7201)

    def test_unclassified_warnings_show_actual_content_without_guessed_classification(self):
        from tests.test_event_search import SearchRunner,candidate
        from faultlens.investigation import unclassified_records
        data=diagnose(SearchRunner([incident('Synthetic heartbeat')],
            kernel=[candidate('Synthetic driver warning',__CURSOR='s=warning')]),search_events=True,show_evidence=True)
        record=unclassified_records(data)[0]
        self.assertIs(data['event_search']['queries'][0]['records'][0],record)
        self.assertIn('Unclassified warning',story(data)['answer'])
        self.assertIn('Synthetic driver warning',str(page_table(5,data,Settings())[1]))
        data['event_search']['queries'][0]['candidate_review']['unclassified_examples'][0]['candidate_index']=5
        self.assertEqual([],unclassified_records(data))

    def test_midnight_replay_is_one_file_and_outside_samples_remain_excluded(self):
        anchor=EPOCH+600
        runner=AtopRunner(records=[incident(realtime=anchor*1000000,monotonic=600000000)],
            text=sample(EPOCH+600,period=600)+sample(anchor+3601,period=600))
        data=diagnose(runner,atop_date='20260101')
        self.assertEqual(1,len(runner.atop_calls));self.assertEqual('20260101',runner.atop_calls[0][0])
        self.assertEqual(1,len(data['atop']['samples']))
        self.assertLess(runner.atop_calls[0][1],EPOCH)
        self.assertIn('midnight',' '.join(data['atop']['limitations']))


class InvestigationWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def test_history_to_diagnostics_to_actual_readable_original_and_evidence(self):
        history_runner=OverviewRunner(count=2)
        history_data=incidents(history_runner)
        data=diagnose(JournalRunner([incident()]),show_evidence=True)
        calls=[]
        async def collect(page,settings):
            calls.append((page,settings.boot_selector));return data
        app=FaultlensApp(initial_collect=False,collector=collect);app.snapshots[4]=history_data
        async with app.run_test(size=(110,32)) as pilot:
            await pilot.pause(.01);app.select_page(4);await pilot.pause(.01)
            table=app.query_one('#grid-4',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[4]) if row.original.get('boot',{}).get('boot_id')==IDS[1]))
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            app.initial_collect=True
            await pilot.click('#select-boot')
            async with asyncio.timeout(3):
                while 5 not in app.snapshots: await pilot.pause(.01)
            self.assertEqual([(5,IDS[1])],calls)
            table=app.query_one('#grid-5',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[5]) if row.kind=='finding'))
            await pilot.pause(.01)
            self.assertIn('example-worker',str(app.query_one('#selected-evidence-5',Static).render()))
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertIn('example-worker',str(app.screen.entry.detail['Recorded evidence']))
            await pilot.click('#references');self.assertIsInstance(app.screen,RecordsDialog)
            self.assertIs(data['journal_records'][0],app.screen.records[0])
            text=' '.join(str(widget.render()) for widget in app.screen.query(Static))
            self.assertIn('Killed process 42 (example-worker)',text)
            await pilot.resize_terminal(40,12);await pilot.pause(.01)
            await pilot.press('escape','escape');app.select_page(6);await pilot.pause(.01)
            self.assertTrue(any(row.kind=='finding' for row in app.entries[6]))

    async def test_hostile_message_is_readable_without_terminal_or_markup_execution(self):
        message='Out of memory: Killed process 42 ([bold]invented[/])\x1b]52;c;synthetic\x07'
        data=diagnose(JournalRunner([incident(message)]),show_evidence=True)
        app=FaultlensApp(initial_collect=False)
        async with app.run_test() as pilot:
            await pilot.pause(.01);app.push_screen(RecordsDialog(data,data['findings'][0]));await pilot.pause(.01)
            text=' '.join(str(widget.render()) for widget in app.screen.query(Static))
            self.assertIn('[bold]invented[/]',text);self.assertNotIn('\x1b',text);self.assertIn('\\u001b',text)


    async def test_many_readable_records_are_paged_without_losing_originals(self):
        records=[record('Out of memory: Killed process '+str(index),__CURSOR='s=synthetic'+str(index),monotonic=index) for index in range(40)]
        data=diagnose(JournalRunner(records),show_evidence=True)
        finding=data['findings'][0];finding['evidence']=[item['reference'] for item in data['journal_records']]
        app=FaultlensApp(initial_collect=False)
        async with app.run_test(size=(110,32)) as pilot:
            await pilot.pause(.01);app.push_screen(RecordsDialog(data,finding));await pilot.pause(.01)
            screen=app.screen
            self.assertEqual(40,len(screen.records))
            self.assertLessEqual(len(screen.query('#readable-records Static')),32)
            await pilot.click('#record-next');await pilot.pause(.01)
            self.assertEqual(16,screen.record_offset)
            self.assertIs(data['journal_records'][16],screen.records[screen.record_offset])
            await pilot.press('ctrl+right');await pilot.pause(.01)
            self.assertEqual(32,screen.record_offset)
            self.assertIn('40 of 40',str(screen.query_one('#record-position',Static).render()))
