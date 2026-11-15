"""Invented recording windows; explanation does not replay, attribute or alter evidence."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.incidents import diagnose
from faultlens.recording_presentation import recording_view,sample_view
from faultlens.tui_model import Session
from tests.test_atop import AtopRunner,sample,EPOCH


class RecordingPresentationTests(unittest.TestCase):
    def test_gaps_overlaps_and_resets_remain_possible_not_proof_of_lost_history(self):
        text=sample()+sample(EPOCH+90)+sample(EPOCH+100)+sample(EPOCH+120,reset=True)
        source=diagnose(AtopRunner(text=text),atop_date='20260101')['atop']
        original=copy.deepcopy(source)
        view=recording_view(source)
        meaning=' '.join(view['What it means'])
        self.assertIn('1 possible gaps, 1 overlapping intervals, 1 RESET samples',meaning)
        self.assertIn('No gaps does not prove continuous recording',' '.join(view['Evidence limits']))
        self.assertIn('Host/boot identity remains unverified',meaning)
        self.assertIn('Requested recording filename date: 20260101',meaning)
        self.assertIn('Requested replay window (UTC)',meaning)
        self.assertIn('not an incident boundary',meaning)
        self.assertIs(source,view['Technical details'])
        self.assertEqual(original,source)

    def test_reason_specific_failures_do_not_claim_absent_recordings_or_permissions(self):
        messages={
            'journal_scope_unavailable':'anchor',
            'ambiguous_journal_clock_mapping':'varied',
            'recording_collection_unavailable':'does not identify',
            'unsupported_or_ambiguous_samples':'no successful sample prefix',
            'no_samples_in_window':'outside that window'}
        for reason,expected in messages.items():
            view=recording_view({'state':'unavailable','reason':reason,'samples':[]})
            self.assertEqual('Historical recording unavailable',view['Observed'])
            self.assertIn(expected,' '.join(view['What it means']))
        view=recording_view({'state':'not_requested','samples':[]})
        self.assertIn('No missing recording',' '.join(view['What it means']))

    def test_reset_and_missing_cpu_values_never_become_zero_or_interval_measurements(self):
        source=diagnose(AtopRunner(text=sample(reset=True)),atop_date='20260101')['atop']
        value=source['samples'][0]
        view=sample_view(value)
        self.assertIn('RESET aggregate',view['Observed'])
        self.assertIn('not a comparable',' '.join(view['What it means']))
        self.assertTrue(all('Not comparable' in row for row in view['Measurements'][:4]))
        self.assertNotIn('CPU execution: 0.00%',view['Measurements'])
        value['since_boot']=False
        self.assertIn('CPU execution: Not comparable',sample_view(value)['Measurements'])

    def test_readable_sample_preserves_host_originals_and_memory_semantics(self):
        source=diagnose(AtopRunner(),atop_date='20260101')['atop']
        sample_value=source['samples'][0]; original=copy.deepcopy(sample_value)
        view=sample_view(sample_value)
        self.assertEqual('synthetic.test',view['Recorded host'])
        self.assertIn('2026-01-01T',view['Observed'])
        self.assertIn('not necessarily the event time',' '.join(view['What it means']))
        self.assertIn('not MemAvailable',' '.join(view['Evidence limits']))
        self.assertIs(sample_value,view['Technical details'])
        self.assertEqual(original,sample_value)

    def test_cli_readable_details_and_json_keep_replay_and_evidence_contracts(self):
        for flags in ([],['--details'],['--json']):
            runner=AtopRunner(); output=io.StringIO()
            self.assertEqual(0,main(['diagnose','--atop-date','20260101',*flags],runner=runner,stdout=output))
            self.assertEqual(1,len(runner.atop_calls))
            if not flags:
                self.assertIn('Recorded resources',output.getvalue())
                self.assertIn('CPU execution:',output.getvalue())
                self.assertIn('Free RAM snapshot:',output.getvalue())
            elif flags==['--json']:
                source=json.loads(output.getvalue())['atop']
                self.assertNotIn('Measurements',source['samples'][0])
                self.assertTrue(source['samples'][0]['source_records'])
            else:
                self.assertNotIn('Free RAM snapshot:',output.getvalue())

    def test_tui_browses_coverage_and_samples_by_reference_without_replaying(self):
        session=Session(runner=AtopRunner())
        session.choose_page(5); session.update_setting('atop_date','20260101'); session.refresh()
        source=session.data['atop']; original=copy.deepcopy(session.data)
        with patch.object(session,'refresh',side_effect=AssertionError('No replay during navigation')):
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='recording')
            session.open_row()
            self.assertIs(source['coverage'],session.value['Reported coverage'])
            self.assertIs(source['samples'],session.value['Retained samples'])
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='recording_samples')
            session.open_row(); session.open_row()
            self.assertIs(source['samples'][0],session.value['Technical details'])
            self.assertIn('Measurements',session.value)
        self.assertEqual(original,session.data)

    def test_raw_recording_access_and_original_tree_roles_remain_available(self):
        session=Session(runner=AtopRunner())
        session.choose_page(5); session.update_setting('atop_date','20260101'); session.refresh()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='recording')
        session.open_row(inspect_only=True)
        self.assertIs(session.data['atop'],session.value)
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))
        session.stack=[(session.data['atop']['samples'],'Raw samples',0,0,'inspect')]
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))


if __name__=='__main__':
    unittest.main()
