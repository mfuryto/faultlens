"""Unavailable and partial synthetic logs never become an empty-success assessment."""
import asyncio
import copy
import io
import unittest

from textual.widgets import Static
from faultlens.cli import main
from faultlens.commands import Result
from faultlens.incidents import diagnose
from faultlens.investigation import story
from faultlens.presentation import guide,render
from faultlens.textual_app import FaultlensApp
from tests.test_event_search import SearchRunner,candidate
from tests.test_incidents import record


class UnavailableLogPresentationTests(unittest.TestCase):
    def assert_not_no_match(self,text):
        for phrase in ('No supported journal pattern matched','No supported fault pattern matched',
                       'No supported fault was identified even with broader search','No supported event signatures matched'):
            self.assertNotIn(phrase,text)

    def test_listing_failure_reproduces_operator_case_without_no_match_or_not_requested_claims(self):
        runner=SearchRunner();runner.boot_result=Result('completed','',1)
        data=diagnose(runner,system_journal=True,search_events=True,show_evidence=True)
        original=copy.deepcopy(data);output=io.StringIO();render(data,output)
        text=output.getvalue();self.assert_not_no_match(text)
        self.assertIn('selected journal tail could not be assessed',text)
        self.assertIn('Broader event search could not be assessed',text)
        self.assertNotIn('Broader event search was not requested',text)
        self.assertNotIn('not usable or not requested',text)
        self.assertEqual([],runner.searches);self.assertEqual(original,data)
        self.assertIn('no pattern-matching conclusion',' '.join(guide(data)['What the evidence means']))
        for flags in ([],['--details']):
            output=io.StringIO()
            self.assertEqual(0,main(['diagnose','--boot','0','--system-journal','--search-events',
                '--since','2026-11-14T23:20:00+01:00','--until','2026-11-14T23:40:00+01:00',*flags],
                runner=runner,stdout=output))
            self.assert_not_no_match(output.getvalue())

    def test_failed_empty_invalid_and_unsupported_tails_never_become_no_faults(self):
        for result in (Result('timeout'),Result('output_limit'),Result('completed','',0),
                       Result('completed','not JSON',0),Result('completed','',1)):
            runner=SearchRunner();runner.result=result
            for flags in ([],['--details']):
                output=io.StringIO();self.assertEqual(0,main(['diagnose',*flags],runner=runner,stdout=output))
                self.assert_not_no_match(output.getvalue())
            data=diagnose(runner)
            self.assertIn('could not be assessed',story(data)['answer'])
        data=diagnose(SearchRunner([record([0,255])]),show_evidence=True)
        self.assertEqual('available',data['state']);self.assertEqual(1,data['unsupported_messages'])
        self.assert_not_no_match(str(guide(data))+str(story(data))+str(data['limitations']))
        self.assertIn('could not be assessed',story(data)['answer'])

    def test_readable_no_match_is_retained_and_scoped_to_the_checked_tail(self):
        data=diagnose(SearchRunner([record('Synthetic ordinary event')]),show_evidence=True)
        self.assertIn('No supported fault pattern matched the readable retained journal tail',story(data)['answer'])
        self.assertIn('readable retained tail',' '.join(guide(data)['What the evidence means']))
        self.assertIn('not unavailable or unrequested logs',' '.join(guide(data)['What the evidence means']))
        self.assertIn('Broader event search was not requested',' '.join(story(data)['gaps']))

    def test_partial_query_never_claims_search_completed_without_faults(self):
        runner=SearchRunner([record('Synthetic ordinary event')])
        runner.candidates['kernel_warnings']=Result('timeout')
        data=diagnose(runner,search_events=True,show_evidence=True)
        original=copy.deepcopy(data);view=story(data)
        self.assertIn('some requested log evidence could not be assessed',view['answer'])
        self.assert_not_no_match(view['answer']+view['next'])
        self.assertIn('kernel_warnings search could not be assessed',' '.join(view['gaps']))
        self.assertEqual('available',data['state']);self.assertEqual('partial',data['event_search']['state'])
        self.assertEqual(original,data)

    def test_independent_positive_finding_survives_unavailable_main_tail(self):
        runner=SearchRunner(kernel=[candidate(__CURSOR='s=synthetic-positive')]);runner.result=Result('timeout')
        data=diagnose(runner,search_events=True,show_evidence=True);original=copy.deepcopy(data)
        output=io.StringIO();render(data,output);text=output.getvalue()
        self.assertIn('Kernel reported a panic',text);self.assertIn('Kernel panic - not syncing: synthetic',text)
        self.assertIn('independently available sources',story(data)['answer'])
        self.assert_not_no_match(text);self.assertEqual(original,data)

    def test_requested_ssh_and_firewall_failures_are_not_ignored_in_primary_answer(self):
        from tests.test_firewall import FirewallRunner
        for key,flag in (('ssh_analysis','search_ssh'),('firewall_analysis','search_firewall')):
            runner=FirewallRunner(records=[record('Synthetic ordinary event')])
            if flag=='search_ssh': runner.ssh_result=Result('timeout')
            else: runner.firewall_result=Result('timeout')
            data=diagnose(runner,**{flag:True})
            self.assertEqual('unavailable',data[key]['state'])
            self.assert_not_no_match(story(data)['answer']+story(data)['next'])
            self.assertIn('log search could not be assessed',' '.join(story(data)['gaps']))

    def test_unreadable_optional_log_messages_are_not_called_no_supported_patterns(self):
        from tests.test_ssh_analysis import SshRunner,ssh_record
        from tests.test_firewall import FirewallRunner
        cases=[(SshRunner(records=[record()],ssh=[ssh_record([0,255])]),'search_ssh','SSH authentication'),
               (FirewallRunner([record([0,255])],records=[record()]),'search_firewall','firewall logging')]
        for runner,flag,label in cases:
            data=diagnose(runner,**{flag:True})
            text=' '.join(guide(data)['What the evidence means'])
            self.assertIn('Some '+label+' message bodies could not be assessed',text)
            self.assertNotIn('No supported '+label+' pattern matched',text)
            self.assertIn('could not be assessed',story(data)['answer'])


class UnavailableLogWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def test_actual_diagnostics_and_evidence_views_show_unassessed_not_no_matches(self):
        for partial in (False,True):
            runner=SearchRunner([record('Synthetic ordinary event')])
            if partial: runner.candidates['kernel_warnings']=Result('timeout')
            else: runner.boot_result=Result('completed','',1)
            data=diagnose(runner,search_events=True,show_evidence=True);original=copy.deepcopy(data)
            app=FaultlensApp(initial_collect=False);app.snapshots[5]=data
            async with app.run_test(size=(110,32)) as pilot:
                for page in (5,6):
                    await pilot.pause(.01);app.select_page(page);await pilot.pause(.01)
                    text=str(app.query_one('#summary-'+str(page),Static).render())
                    self.assertIn('could not be assessed',text)
                    self.assertNotIn('No supported fault',text)
                    answer=next(row for row in app.entries[page] if row.cells[0]=='Investigation answer')
                    self.assertIn('could not be assessed',answer.detail['Observed'])
                await pilot.resize_terminal(40,12);await pilot.pause(.01)
                self.assertEqual(original,data)
