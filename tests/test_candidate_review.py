"""Synthetic explanations only; raw private-looking payloads must stay out of output."""
import io
import json
import unittest

from faultlens.cli import main
from faultlens.commands import Result
from faultlens.incidents import diagnose
from tests.test_event_search import SearchRunner, candidate, systemd_candidate
from tests.test_incidents import record


class CandidateReviewTests(unittest.TestCase):
    def review(self, kernel):
        data = diagnose(SearchRunner([record()], kernel=kernel), search_events=True)
        return data['event_search']['queries'][0]

    def test_counts_distinguish_supported_unknown_and_unavailable_content(self):
        query = self.review([candidate(), record('Other synthetic report', PRIORITY='4', monotonic=200),
                             record(message=[1, 2], PRIORITY='3', monotonic=300)])
        review = query['candidate_review']
        self.assertEqual(3, review['retained_candidates'])
        self.assertEqual(1, review['matched_candidates'])
        self.assertEqual(2, review['unclassified_candidates'])
        self.assertEqual(1, review['message_unavailable_candidates'])
        self.assertEqual({'3': 2, '4': 1}, review['reported_priority_counts'])
        self.assertEqual({'no_supported_signature': 1, 'unsupported_message_content': 1}, review['unclassified_reason_counts'])
        self.assertEqual(['warning', 'error'], [item['reported_priority_label'] for item in review['unclassified_examples']])
        self.assertTrue(all(item['classification_confidence'] == 'Unknown' and item['cause_confidence'] == 'Unknown'
                            for item in review['unclassified_examples']))
        self.assertIn('not declared benign', review['unclassified_examples'][0]['explanation'])
        self.assertEqual(1, len(query['findings']))

    def test_identical_references_without_cursors_do_not_conflate_candidate_classification(self):
        query = self.review([candidate(), candidate('Unclassified synthetic warning')])
        review = query['candidate_review']
        self.assertEqual(1, review['matched_candidates'])
        self.assertEqual(1, review['unclassified_candidates'])
        example, = review['unclassified_examples']
        self.assertEqual(1, example['candidate_index'])
        self.assertEqual(query['findings'][0]['evidence'][0], example['reference'])
        self.assertIsNone(example['reference']['cursor_sha256'])

    def test_counts_cover_retained_set_while_examples_are_newest_twenty(self):
        query = self.review([record('Synthetic unknown warning', PRIORITY=str(index % 5), monotonic=index)
                             for index in range(501)])
        review = query['candidate_review']
        self.assertEqual(500, review['retained_candidates'])
        self.assertEqual(500, review['unclassified_candidates'])
        self.assertEqual({'0': 100, '1': 100, '2': 100, '3': 100, '4': 100}, review['reported_priority_counts'])
        self.assertEqual(20, len(review['unclassified_examples']))
        self.assertEqual(list(range(480, 500)), [item['candidate_index'] for item in review['unclassified_examples']])
        self.assertEqual(481, review['unclassified_examples'][0]['reference']['monotonic_us'])
        self.assertEqual(500, review['unclassified_examples'][-1]['reference']['monotonic_us'])
        self.assertTrue(review['unclassified_examples_truncated'])
        self.assertTrue(query['record_limit_reached'])

    def test_example_truncation_is_distinct_from_candidate_record_cap(self):
        query = self.review([candidate('Unknown synthetic warning', monotonic=index) for index in range(30)])
        self.assertFalse(query['record_limit_reached'])
        self.assertTrue(query['candidate_review']['unclassified_examples_truncated'])
        self.assertEqual(30, query['candidate_review']['unclassified_reason_counts']['no_supported_signature'])
        query = self.review([candidate('Unknown synthetic warning', monotonic=index) for index in range(16)])
        self.assertFalse(query['candidate_review']['unclassified_examples_truncated'])
        self.assertEqual(16, len(query['candidate_review']['unclassified_examples']))

    def test_structured_ids_can_match_even_when_message_content_is_unavailable(self):
        data = diagnose(SearchRunner([record()], systemd=[systemd_candidate(MESSAGE=[1, 2])]), search_events=True)
        review = data['event_search']['queries'][1]['candidate_review']
        self.assertEqual(1, review['matched_candidates'])
        self.assertEqual(0, review['unclassified_candidates'])
        self.assertEqual(1, review['message_unavailable_candidates'])
        self.assertEqual({'unspecified': 1}, review['reported_priority_counts'])
        self.assertEqual([], review['unclassified_examples'])

    def test_response_unsupported_count_is_separate_from_retained_content_count(self):
        query = self.review([record(message=[1, 2], PRIORITY='3', monotonic=index) for index in range(501)])
        self.assertEqual(501, query['unsupported_messages_in_response'])
        self.assertEqual(500, query['candidate_review']['message_unavailable_candidates'])
        self.assertEqual(500, query['candidate_review']['unclassified_reason_counts']['unsupported_message_content'])

    def test_failed_queries_have_no_review_and_empty_queries_do_not_assert_health(self):
        query = self.review([])
        self.assertEqual('available', query['candidate_review']['state'])
        self.assertEqual(0, query['candidate_review']['retained_candidates'])
        self.assertEqual({}, query['candidate_review']['reported_priority_counts'])
        self.assertEqual([], query['candidate_review']['unclassified_examples'])
        for result in (Result('timeout'), Result('output_limit'), Result('completed', 'private error', 1),
                       Result('completed', 'malformed', 0)):
            runner = SearchRunner([record()])
            runner.candidates['kernel_warnings'] = result
            query = diagnose(runner, search_events=True)['event_search']['queries'][0]
            self.assertIsNone(query['candidate_review'])
            self.assertEqual('unavailable', query['state'])

    def test_private_messages_process_names_and_controls_are_not_copied_to_review(self):
        marker = 'synthetic-private-payload'
        runner = SearchRunner([record()], kernel=[record(marker + '\x1b]52;c;hidden\x07', PRIORITY='3',
                              _COMM=marker, _HOSTNAME=marker, __CURSOR='s=' + marker)])
        for json_mode in (True, False):
            output = io.StringIO()
            main(['diagnose', '--search-events'] + (['--json'] if json_mode else []), runner=runner, stdout=output)
            text = output.getvalue()
            self.assertNotIn(marker, text)
            self.assertNotIn('\x1b', text)
            self.assertNotIn('52;c;hidden', text)
            if json_mode:
                example = json.loads(text)['event_search']['queries'][0]['candidate_review']['unclassified_examples'][0]
                self.assertEqual('no_supported_signature', example['reason'])
                self.assertNotIn('message_sha256', example)
                self.assertEqual(64, len(example['reference']['cursor_sha256']))
            else:
                self.assertIn('Candidate review: matched 0; unclassified 1;', text)
                self.assertIn('Selection:', text)
                self.assertIn('not declared benign', text)

    def test_reverse_input_and_ties_preserve_normalized_candidate_indices(self):
        query = self.review([candidate('Later unknown', monotonic=300), candidate(monotonic=100),
                             candidate('Earlier unknown', monotonic=200), candidate('Tied unknown', monotonic=200)])
        examples = query['candidate_review']['unclassified_examples']
        self.assertEqual([1, 2, 3], [item['candidate_index'] for item in examples])
        self.assertEqual([200, 200, 300], [item['reference']['monotonic_us'] for item in examples])
        self.assertEqual(1, query['candidate_review']['matched_candidates'])
