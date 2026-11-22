"""Snapshot provenance, cross-boot history and inquiry subjects use invented data only."""
import copy
import unittest
from faultlens.investigation_flow import Selection,context,evidence,history_entries,period,signals,availability
from faultlens.workflows import collect
from faultlens.overview import incidents
from faultlens.tui_model import Settings
from faultlens.workspace import Entry
from tests.test_problem_workflows import Runner,START,END,event
from tests.test_incident_overview import OverviewRunner


class InvestigationFlowTests(unittest.TestCase):
    def test_history_event_retains_original_message_and_partition_identity(self):
        report=incidents(OverviewRunner());original=copy.deepcopy(report)
        entries=history_entries(report);events=[row for row in entries if row.kind=='history_event']
        self.assertEqual(3,len(events))
        for row in events:
            retained=row.original['record']
            self.assertIn('Out of memory',retained['message'])
            self.assertEqual(retained['reference']['boot_id'],row.navigation['reference']['boot_id'])
            self.assertIs(retained,row.navigation['record'])
            self.assertTrue(period(row.navigation['reference']))
        self.assertEqual(original,report)

    def test_selected_partition_retains_parent_window_without_inventing_a_boot_filter(self):
        data=collect(Runner(),mode='period',since_us=START,until_us=END)
        entries=signals(data,Settings())
        findings=[row for row in entries if row.kind=='finding']
        self.assertEqual(2,len(findings))
        for row in findings:
            scope=context(row.context)
            self.assertIn('optional boot filter none',scope)
            self.assertIn('inquiry period',scope)
            self.assertEqual({'since_realtime_us':START,'until_realtime_us':END},row.context['inquiry_context']['requested_window'])
            self.assertIn(row.context['selected_boot']['boot_id'],scope)

    def test_evidence_selection_keeps_exact_owned_objects_and_has_explicit_replacement(self):
        data=collect(Runner(),mode='period',since_us=START,until_us=END)
        row=next(row for row in signals(data,Settings()) if row.kind=='finding')
        selection=Selection(row,row.context,3)
        entries=evidence(selection,row.context)
        retained=next(value for value in entries if value.kind=='finding')
        self.assertIs(row.original,retained.original);self.assertIs(row.context,retained.context)
        self.assertTrue(any(value.kind=='return_source' for value in entries))
        self.assertTrue(any(value.kind=='current_evidence' for value in entries))
        self.assertIs(row.context,next(value.original for value in entries if value.cells[0]=='Full original report'))

    def test_period_rejects_unknown_and_out_of_range_receipt_times(self):
        for value in (None,-1,True,'2026',253402300800000000):self.assertIsNone(period({'realtime_us':value}))
        self.assertEqual((0,60000000),period({'realtime_us':0}))

    def test_empty_unavailable_and_capped_queries_have_different_signal_explanations(self):
        empty=collect(Runner([]),mode='period',since_us=START,until_us=END)
        self.assertTrue(any(row.cells[0]=='No retained review signal established' for row in signals(empty,Settings())))
        runner=Runner([]);runner.fail={None,'kernel_warnings','systemd_events'}
        unavailable=collect(runner,mode='period',since_us=START,until_us=END)
        self.assertTrue(any(row.cells[0]=='Signals could not be assessed' for row in signals(unavailable,Settings())))
        self.assertIn('No retained query state',availability('search_ssh',{5:empty}))
        self.assertIn('Retained inquiry:',availability('since_us',{5:empty}))
        self.assertIn('No optional source',availability('pstore',{}))

    def test_successful_but_capped_queries_remain_prominent_coverage_gaps(self):
        rows=[event(offset=60,mono=index) for index in range(501)]
        for index,row in enumerate(rows):row['__CURSOR']='s=synthetic-cap-'+str(index)
        data=collect(Runner(rows),mode='period',since_us=START,until_us=END)
        self.assertEqual('available',data['state'])
        coverage=next(row for row in signals(data,Settings()) if row.cells[0]=='Source coverage')
        self.assertEqual('partial',coverage.cells[1]);self.assertIn('incomplete/capped',coverage.cells[2])
        self.assertIn('cap reached',str(coverage.detail['Coverage']))
