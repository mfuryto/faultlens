"""Invented live samples distinguish empty findings from unavailable security evidence."""
import copy
import io
import unittest

from faultlens.commands import Result
from faultlens.presentation import guide,render
from faultlens.sockets import attach
from faultlens.tui_model import Settings
from faultlens.workspace import page_table
from tests.test_network_analysis import NetworkSources,analyze,stats
from tests.test_sockets import SocketRunner


class SecurityWorkspaceTests(unittest.TestCase):
    def test_no_matches_still_explains_current_coverage_and_separate_history(self):
        data=analyze(command='security'); original=copy.deepcopy(data)
        columns,entries=page_table(3,data,Settings.administrator_defaults())
        self.assertGreater(len(entries),3)
        self.assertTrue(any('No supported network indicators' in row.cells[0] for row in entries))
        link=next(row for row in entries if row.kind=='diagnostics_link')
        self.assertEqual('-1',link.original['boot_selector'])
        self.assertEqual('visible',link.original['journal_scope'])
        self.assertTrue(link.original['search_ssh'])
        self.assertEqual(original,data); self.assertEqual([],data['findings'])
        self.assertIn('Unknown',guide(data)['Summary'])
        self.assertIn('not inspected',str(guide(data)['What the evidence means']))

    def test_partial_and_unavailable_reads_never_become_a_clean_security_verdict(self):
        cases=[NetworkSources(devices=[OSError('invented')]*2),
               NetworkSources(devices=[OSError('invented')]*2,tcp=[OSError('invented')]*2,udp=[OSError('invented')]*2)]
        for sources,expected in zip(cases,('partial','unavailable')):
            data=analyze(sources,command='security')
            columns,entries=page_table(3,data,Settings())
            coverage=next(row for row in entries if row.cells[0]=='Current network security coverage')
            self.assertEqual(expected,coverage.cells[1]); self.assertEqual('Unknown',data['attack_assessment'])
            summary=guide(data)['Summary']
            self.assertIn('incomplete' if expected=='partial' else 'unavailable',summary)
            if expected=='unavailable':
                self.assertTrue(any(row.cells[0]=='No usable network counter evidence' for row in entries))

    def test_socket_unavailable_empty_and_listener_results_retain_source_status(self):
        for result,state,count in ((Result('completed','',0),'available',0),
                                   (Result('completed','',1),'unavailable',0),
                                   (None,'available',1)):
            data=analyze(command='security'); attach(data,SocketRunner(result))
            columns,entries=page_table(3,data,Settings())
            sockets=next(row for row in entries if row.kind=='sockets')
            self.assertIs(data['sockets'],sockets.original)
            self.assertEqual(state,sockets.cells[1]); self.assertEqual(count,len(sockets.original['rows']))
            self.assertIn('reachability unverified',sockets.cells[3])

    def test_positive_counter_growth_keeps_findings_and_unknown_attack_assessment(self):
        data=analyze(NetworkSources(tcp=[stats(),stats((1,0,0,0,0))]),command='security')
        original=copy.deepcopy(data)
        columns,entries=page_table(3,data,Settings())
        group=next(row for row in entries if row.kind=='finding_group')
        self.assertIs(data['findings'][0],group.original[0])
        self.assertIn('Unknown',guide(data)['Summary']); self.assertEqual(original,data)
        output=io.StringIO(); render(data,output)
        self.assertIn('counters increased',output.getvalue())
        self.assertNotIn('confirmed attack',guide(data)['Summary'].lower())

    def test_empty_source_sections_have_a_meaningful_row_without_invented_findings(self):
        for page in range(7):
            columns,entries=page_table(page,None,Settings())
            self.assertTrue(entries); self.assertIsNone(entries[0].original)
            self.assertIn('No security or health conclusion',entries[0].detail['What it means'])


if __name__=='__main__': unittest.main()
