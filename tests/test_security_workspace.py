"""Signals reuse inquiry evidence; CLI security retains its independent counter contract."""
import copy
import io
import unittest
from faultlens.tui_model import Settings
from faultlens.workspace import page_table
from faultlens.workflows import collect
from faultlens.presentation import render
from tests.test_problem_workflows import Runner,START,END
from tests.test_network_analysis import analyze,NetworkSources,stats


class SecurityWorkspaceTests(unittest.TestCase):
    def test_no_matches_explain_selected_period_and_readable_empty_coverage(self):
        data=collect(Runner([]),mode='period',since_us=START,until_us=END);original=copy.deepcopy(data)
        columns,entries=page_table(3,data,Settings.administrator_defaults())
        self.assertTrue(any(row.cells[0]=='No retained review signal established' for row in entries))
        link=next(row for row in entries if row.kind=='investigation_focus')
        self.assertIs(data,link.original);self.assertIn('Selected period',link.cells[2]);self.assertNotIn('sockets',{row.kind for row in entries})
        self.assertEqual(original,data)

    def test_unavailable_and_partial_inquiry_sources_are_not_an_all_clear(self):
        for failed,expected in (({None},'partial'),({None,'kernel_warnings','systemd_events'},'unavailable')):
            runner=Runner([]);runner.fail=failed
            data=collect(runner,mode='period',since_us=START,until_us=END)
            entries=page_table(3,data,Settings())[1]
            self.assertEqual(expected,data['state'])
            coverage=next(row for row in entries if row.cells[0]=='Source coverage')
            self.assertEqual(expected,coverage.cells[1]);self.assertIn('unavailable',str(coverage.detail['Coverage']))
            self.assertEqual('Unknown',data['root_cause'])

    def test_cross_boot_reports_keep_their_original_owning_partition(self):
        data=collect(Runner(),mode='period',since_us=START,until_us=END)
        entries=page_table(3,data,Settings())[1];findings=[row for row in entries if row.kind=='finding']
        self.assertEqual(2,len(findings))
        self.assertEqual(2,len({row.context['selected_boot']['boot_id'] for row in findings}))
        self.assertTrue(all(any(row.original is item for item in row.context['findings']) for row in findings))

    def test_cli_security_still_explains_counter_growth_and_unknown_attack_assessment(self):
        data=analyze(NetworkSources(tcp=[stats(),stats((1,0,0,0,0))]),command='security')
        original=copy.deepcopy(data);output=io.StringIO();render(data,output)
        self.assertIn('counters increased',output.getvalue());self.assertEqual('Unknown',data['attack_assessment'])
        self.assertEqual(original,data)

    def test_empty_sections_have_meaningful_rows_without_invented_findings(self):
        for page in range(7):
            entries=page_table(page,None,Settings())[1]
            self.assertTrue(entries);self.assertIsNone(entries[0].original)
            self.assertIn('No security or health conclusion',entries[0].detail['What it means'])
