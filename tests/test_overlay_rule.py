"""Synthetic OverlayFS warnings; no actual mounts, containers or host logs."""
import io
import json
import unittest

from faultlens.cli import main
from faultlens.incidents import diagnose
from tests.test_atop import AtopRunner, EPOCH, sample
from tests.test_event_search import SearchRunner
from tests.test_incidents import JournalRunner, record


def warning(role='upperdir'):
    return ('overlayfs: ' + role + ' is in-use as upperdir/workdir of another mount, '
            'accessing files from both mounts will result in undefined behavior.')


class OverlayRuleTests(unittest.TestCase):
    def test_supported_roles_confirm_historical_report_without_causal_or_current_state_claim(self):
        for role in ('upperdir', 'workdir'):
            for suffix in ('', '\n'):
                data = diagnose(JournalRunner([record(warning(role) + suffix)]))
                finding, = data['findings']
                self.assertEqual('kernel.overlay_layer_reuse', finding['rule_id'])
                self.assertEqual('Confirmed', finding['confidence'])
                self.assertEqual('Unknown', finding['cause_confidence'])
                self.assertEqual('warning', finding['severity'])
                self.assertIn(role, finding['observation'])
                self.assertIn('not a currently active conflict', ' '.join(finding['limitations']))
                self.assertTrue(finding['recommendations'])
                self.assertEqual('Unknown', data['root_cause'])
                self.assertEqual('Unknown', data['shutdown_assessment'])
                self.assertEqual('kernel.overlay_layer_reuse', data['timeline'][0]['rule_id'])

    def test_application_quotes_loose_mentions_and_unsupported_variants_do_not_match(self):
        self.assertEqual([], diagnose(JournalRunner([record(warning(), _TRANSPORT='stdout')]))['findings'])
        for text in ('Example: ' + warning(), warning() + ' extra', warning() + '\nextra',
                     warning()[:-1], warning('lowerdir'), warning('private-path'),
                     warning().replace('upperdir is', 'upperdir=/synthetic/private is'),
                     warning().replace('undefined behavior.', "mount with '-o index=off' to override protection."),
                     'overlayfs warning', 'exit code 137', 'Container failed to exit within 15s of signal 15'):
            self.assertEqual([], diagnose(JournalRunner([record(text)]))['findings'], text)

    def test_original_suffix_is_literal_and_never_loosely_classified(self):
        for payload in ('synthetic-private-payload', '\x1b]52;c;synthetic\x07'):
            output = io.StringIO()
            main(['diagnose'], runner=JournalRunner([record(warning() + payload)]), stdout=output)
            if '\x1b' in payload: self.assertNotIn(payload,output.getvalue())
            else: self.assertIn(payload,output.getvalue())
            self.assertNotIn('Kernel reported OverlayFS layer reuse', output.getvalue())

    def test_targeted_candidates_become_matches_without_losing_other_unknowns(self):
        values = [record(warning('upperdir'), PRIORITY='4', monotonic=10),
                  record(warning('workdir'), PRIORITY='4', monotonic=20),
                  record('Other synthetic kernel warning', PRIORITY='4', monotonic=30)]
        data = diagnose(SearchRunner([record()], kernel=values), search_events=True)
        query = data['event_search']['queries'][0]
        self.assertEqual(2, len(query['findings']))
        self.assertEqual(2, query['candidate_review']['matched_candidates'])
        self.assertEqual(1, query['candidate_review']['unclassified_candidates'])
        self.assertEqual(2, query['candidate_review']['unclassified_examples'][0]['candidate_index'])
        self.assertEqual([], data['findings'])
        self.assertEqual('Unknown', data['event_search']['root_cause'])
        self.assertIn('same mount operation', ' '.join(query['findings'][0]['limitations']))

    def test_same_timestamp_reference_does_not_mark_a_different_warning_as_matched(self):
        values = [record(warning(), PRIORITY='4'), record('Other synthetic warning', PRIORITY='4')]
        query = diagnose(SearchRunner([record()], kernel=values), search_events=True)['event_search']['queries'][0]
        self.assertEqual(1, query['candidate_review']['matched_candidates'])
        self.assertEqual(1, query['candidate_review']['unclassified_candidates'])

    def test_text_and_json_show_findings_but_not_raw_messages(self):
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose'] + (['--json'] if json_mode else []),
                 runner=JournalRunner([record(warning())]), stdout=output)
            self.assertIn('OverlayFS layer reuse', output.getvalue())
            self.assertNotIn(warning(), output.getvalue())
            if json_mode:
                self.assertEqual('Unknown', json.loads(output.getvalue())['root_cause'])

    def test_atop_overlap_is_temporal_only_for_overlay_reports(self):
        runner = AtopRunner(records=[record(warning(), realtime=(EPOCH + 15) * 1000000,
                                          monotonic=15000000)], text=sample())
        data = diagnose(runner, atop_date='20260101')
        self.assertEqual('kernel.overlay_layer_reuse', data['findings'][0]['rule_id'])
        self.assertEqual('Possible', data['atop']['correlations'][0]['confidence'])
        self.assertEqual('Unknown', data['root_cause'])
