"""Invented references only; links never collect data or infer identity from timestamps."""
import copy
import unittest
from unittest.mock import patch

from faultlens.evidence_links import resolve
from faultlens.incidents import diagnose
from faultlens.security_analysis import assess
from faultlens.tui_model import Session
from tests.test_incidents import JournalRunner,record
from tests.test_event_search import SearchRunner
from tests.test_ssh_analysis import SshRunner,ssh_record
from tests.test_security_analysis import history
from tests.test_firewall import FirewallRunner,TCP
from tests.support import SyntheticNetworkSources


def linked(view):
    return [item for ref in view['References'] for item in ref['Retained source evidence']]


class EvidenceLinkTests(unittest.TestCase):
    def test_main_journal_links_keep_originals_and_references_without_mutation(self):
        data=diagnose(JournalRunner([record('Kernel panic - not syncing: invented',__CURSOR='synthetic:1')]),show_evidence=True)
        finding=data['findings'][0]
        original=copy.deepcopy(data)
        result=resolve(data,finding)
        self.assertEqual('journal_records[0]',linked(result)[0]['Location'])
        self.assertIs(data['journal_records'][0],linked(result)[0]['Original evidence'])
        self.assertIs(finding['evidence'][0],result['References'][0]['Source reference'])
        self.assertEqual(original,data)

    def test_missing_or_ambiguous_cursor_never_links_by_timestamp_alone(self):
        data=diagnose(JournalRunner([record('Kernel panic - not syncing: invented')]),show_evidence=True)
        self.assertEqual([],linked(resolve(data,data['findings'][0])))
        data=diagnose(JournalRunner([record('Kernel panic - not syncing: invented',__CURSOR='synthetic:1')]),show_evidence=True)
        data['journal_records'].append(copy.deepcopy(data['journal_records'][0]))
        self.assertEqual([],linked(resolve(data,data['findings'][0])))

    def test_filtered_query_uses_only_its_own_retained_records(self):
        event=record('Kernel panic - not syncing: invented',__CURSOR='synthetic:1',PRIORITY='3')
        data=diagnose(SearchRunner([event],kernel=[event]),search_events=True,show_evidence=True)
        query=data['event_search']['queries'][0]
        finding=query['findings'][0]
        result=resolve(data,finding)
        self.assertEqual('event_search.queries[0].records[0]',linked(result)[0]['Location'])
        self.assertIs(query['records'][0],linked(result)[0]['Original evidence'])
        query['records']=[]
        self.assertEqual([],linked(resolve(data,finding)))
        self.assertTrue(data['journal_records'])

    def test_candidate_index_is_source_scoped_and_requires_matching_reference(self):
        data=diagnose(SshRunner(ssh=[ssh_record()]),search_ssh=True)
        finding=data['ssh_analysis']['findings'][0]
        self.assertIs(data['ssh_analysis']['records'][0],linked(resolve(data,finding))[0]['Original evidence'])
        for index in (True,-1,999):
            finding['evidence'][0]['candidate_index']=index
            self.assertEqual([],linked(resolve(data,finding)))
        finding['evidence'][0]['candidate_index']=0
        finding['evidence'][0]['boot_id']='b'*32
        self.assertEqual([],linked(resolve(data,finding)))

    def test_derived_log_indicator_exposes_contributing_candidates_not_other_sources(self):
        data=diagnose(SshRunner(ssh=[ssh_record(monotonic=i+1) for i in range(10)]),search_ssh=True)
        finding=data['security_analysis']['findings'][0]
        original=copy.deepcopy(data)
        result=resolve(data,finding)
        self.assertEqual(10,len(linked(result)))
        for index,value in enumerate(linked(result)):
            self.assertIs(data['ssh_analysis']['records'][index],value['Original evidence'])
        self.assertEqual(original,data)
        data['ssh_analysis']['records'].pop()
        result=resolve(data,finding)
        self.assertEqual(9,len(linked(result)))
        self.assertIn('1 unresolved',result['References'][0]['Resolution'])
        finding['evidence'][0]['source_analysis']='journal_records'
        self.assertEqual([],linked(resolve(data,finding)))

    def test_firewall_references_keep_packet_originals_and_boot_scope(self):
        data=diagnose(FirewallRunner([record(TCP)]),search_firewall=True)
        finding=data['firewall_analysis']['findings'][0]
        result=resolve(data,finding)
        self.assertIs(data['firewall_analysis']['records'][0],linked(result)[0]['Original evidence'])
        self.assertEqual(TCP,linked(result)[0]['Original evidence']['message'])

    def test_recording_baseline_requires_same_output_and_unique_sample_indices(self):
        data={'atop':history()}
        assess(data)
        finding=data['security_analysis']['findings'][0]
        original=copy.deepcopy(data)
        result=resolve(data,finding)
        self.assertEqual(6,len(linked(result)))
        self.assertIs(data['atop']['samples'][5],linked(result)[0]['Original evidence'])
        self.assertIn('Host/boot identity is unverified',result['References'][0]['Resolution'])
        self.assertEqual(original,data)
        data['atop']['samples'].append(copy.deepcopy(data['atop']['samples'][5]))
        self.assertEqual(5,len(linked(resolve(data,finding))))
        data['atop']['output_sha256']='b'*64
        self.assertEqual([],linked(resolve(data,finding)))

    def test_copied_forged_or_replaced_findings_cannot_resolve_against_snapshot(self):
        data=diagnose(SshRunner(ssh=[ssh_record()]),search_ssh=True)
        finding=data['ssh_analysis']['findings'][0]
        self.assertEqual([],resolve(data,copy.deepcopy(finding))['References'])
        self.assertEqual([],resolve({},finding)['References'])
        data['findings']=[finding]
        self.assertEqual([],resolve(data,finding)['References'])

    def test_tui_evidence_navigation_is_raw_and_keeps_source_references(self):
        session=Session(runner=SshRunner(ssh=[ssh_record()]))
        session.choose_page(5); session.update_setting('search_ssh'); session.refresh()
        with patch.object(session,'refresh',side_effect=AssertionError('No link collection')):
            session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='analysis' and r.value is session.data['ssh_analysis'])
            session.open_row()
            session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='findings')
            session.open_row(); session.open_row()
            session.selected=next(i for i,r in enumerate(session.rows()) if r.label=='Referenced source evidence')
            self.assertEqual('inspect',session.rows()[session.selected].action)
            session.open_row()
            self.assertIs(session.data['ssh_analysis']['records'][0],linked(session.value)[0]['Original evidence'])
            self.assertTrue(all(row.action=='inspect' for row in session.rows()))

    def test_current_network_findings_are_explained_without_inventing_raw_records(self):
        session=Session(sources=SyntheticNetworkSources())
        session.choose_page(3); session.refresh()
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='findings')
        session.open_row(); session.open_row()
        result=session.value['Referenced source evidence']
        self.assertEqual([],linked(result))
        self.assertIn('embedded',result['References'][0]['Resolution'])


if __name__=='__main__':
    unittest.main()
