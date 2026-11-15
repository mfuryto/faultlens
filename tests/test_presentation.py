"""Invented diagnostic reports; explanation never replaces evidence or source confidence."""
import copy
import io
import json
import unittest

from faultlens.cli import main
from faultlens.models import Observation, report
from faultlens.presentation import finding_view, guide, observation_view, render
from faultlens.tui_model import Session
from tests.support import SyntheticSources, SyntheticRunner, SyntheticPhase3Runner
from tests.test_incidents import JournalRunner, record
from tests.test_ssh_analysis import SshRunner, ssh_record, FAILED
from tests.test_sockets import SocketRunner
from tests.test_network_analysis import NetworkSources


class PresentationTests(unittest.TestCase):
    def test_follow_up_commands_are_fixed_and_do_not_mutate_source_evidence(self):
        from faultlens.incidents import diagnose
        data=diagnose(JournalRunner([record('Kernel panic - not syncing: invented')]))
        finding=dict(data['findings'][0],rule_id='kernel.overlay_layer_reuse',
                     observation='Invented $(touch /tmp/never-execute) mount warning')
        original=copy.deepcopy(finding)
        view=finding_view(finding)
        commands=[step for step in view['What you can do'] if step.startswith('Optional current-state')]
        self.assertEqual(['Optional current-state check (not historical proof): findmnt --json --list -t overlay -o TARGET,OPTIONS'],commands)
        self.assertEqual(original,finding)
        self.assertIs(finding,view['Technical details'])
        unknown=dict(finding,rule_id='invented; touch /tmp/never-execute')
        self.assertFalse(any(step.startswith('Optional current-state') for step in finding_view(unknown)['What you can do']))

    def test_unavailable_journal_follow_up_preserves_scope_without_elevation(self):
        for scope,command in [('system','journalctl --system --list-boots --no-pager'),
                              ('visible','journalctl --list-boots --no-pager')]:
            data={'command':'history','state':'unavailable','boots':[],
                  'journal_scope':{'requested':scope}}
            original=copy.deepcopy(data)
            actions=' '.join(guide(data)['What you can do'])
            self.assertIn(command,actions)
            self.assertIn('existing authorized access only',actions)
            self.assertNotIn('sudo',actions)
            self.assertEqual(original,data)

    def test_optional_current_checks_are_shared_by_cli_and_tui_without_extra_collection(self):
        data=report('status',[Observation('filesystem.root.used',96,'percent','synthetic','critical')])
        view=observation_view(data['observations'][0])
        self.assertIn('df --block-size=1',' '.join(view['What you can do']))
        out=io.StringIO(); render(data,out)
        self.assertIn('df --block-size=1',out.getvalue())
        self.assertIn('never run automatically',out.getvalue())
        session=Session(); session.data=data
        session.selected=next(i for i,row in enumerate(session.rows()) if row.value is data['observations'][0])
        session.open_row()
        self.assertIn('df --block-size=1',' '.join(session.value['What you can do']))

    def test_critical_memory_explains_investigation_without_inventing_oom(self):
        data=report('status',[Observation('memory.used',96,'percent','proc','critical',
            thresholds={'warning':90,'critical':95})])
        original=copy.deepcopy(data)
        value=observation_view(data['observations'][0])
        self.assertEqual('96.00%',value['Observed'])
        self.assertIn('does not prove',value['What it means'])
        self.assertIn('limits',' '.join(value['What you can do']))
        self.assertIs(data['observations'][0],value['Technical details'])
        self.assertEqual(original,data)
        out=io.StringIO(); render(data,out)
        self.assertIn('High-priority reading',out.getvalue())
        self.assertNotIn('confirmed OOM',out.getvalue())

    def test_unverified_defaults_and_missing_optional_tools_do_not_become_health_failures(self):
        data=report('check',[Observation('journal.config.storage',None,'','config','unknown',
                explanation='No explicit assignment observed; no compiled default value is assumed.'),
            Observation('dependency.ss',False,'','trusted paths','unavailable',explanation='Optional socket adapter.')])
        view=guide(data)
        self.assertIn('Defaults may apply',' '.join(view['What the evidence means']))
        self.assertNotIn('healthy server',view['Summary'])
        tool=observation_view(data['observations'][1])
        self.assertEqual('No trusted executable found',tool['Observed'])
        self.assertIn('only if you need',' '.join(tool['What you can do']))

    def test_confirmed_kernel_report_never_upgrades_cause_and_shutdown_marker_is_not_completion(self):
        from faultlens.incidents import diagnose, SHUTDOWN_REQUEST
        data=diagnose(JournalRunner([record('Kernel panic - not syncing: invented')]))
        value=finding_view(data['findings'][0])
        self.assertIn('Confirmed observation; cause Unknown',value['Confidence'])
        self.assertIn('does not identify',value['What it means'])
        self.assertIs(data['findings'][0],value['Technical details'])
        shutdown=dict(data['findings'][0],rule_id='systemd.shutdown_marker')
        self.assertIn('not that shutdown completed',finding_view(shutdown)['What it means'])

    def test_possible_security_indicators_and_grouped_reports_keep_confidence_and_source_boundaries(self):
        from faultlens.incidents import diagnose
        data=diagnose(SyntheticPhase3Runner(),atop_date='20260101',atop_extended=True,
                      search_ssh=True,search_firewall=True)
        original=copy.deepcopy(data)
        out=io.StringIO(); render(data,out)
        text=out.getvalue()
        self.assertIn('Possible observation; cause Unknown',text)
        self.assertIn('derived security indicators',text)
        self.assertIn('SSH event search',text)
        self.assertIn('do not establish separate incidents',text)
        self.assertNotIn('Confirmed attack',text)
        self.assertEqual(original,data)

    def test_informational_authentication_is_not_presented_as_a_warning(self):
        from faultlens.incidents import diagnose
        from tests.test_ssh_analysis import ACCEPTED
        data=diagnose(SshRunner(ssh=[ssh_record(ACCEPTED)]),search_ssh=True)
        self.assertNotIn('need review',guide(data)['Summary'])
        self.assertIn('does not establish',finding_view(data['ssh_analysis']['findings'][0])['What it means'])

    def test_crash_signature_and_unavailable_binary_analysis_are_not_lost_in_summary(self):
        from faultlens.incidents import diagnose
        from faultlens.pstore import analyze
        data=diagnose(JournalRunner([record('Invented ordinary event')]))
        data['pstore']=analyze(lambda:([b'Kernel panic - not syncing: invented\n'],0))
        view=guide(data)
        self.assertIn('need review',view['Summary'])
        self.assertIn('Possible',' '.join(view['What the evidence means']))
        self.assertIn('not attributed',' '.join(view['What the evidence means']))
        data['pstore']=analyze(lambda:([b'\x00\xff'],0))
        self.assertIn('could not be fully checked',' '.join(guide(data)['What the evidence means']))
        self.assertIn('other parts could not be verified',guide(data)['Summary'])

    def test_plain_text_and_json_keep_separate_contracts_and_full_evidence(self):
        runner=SshRunner(ssh=[ssh_record(FAILED)])
        for flags in ([],['--details'],['--json']):
            out=io.StringIO()
            self.assertEqual(0,main(['diagnose','--search-ssh',*flags],runner=runner,stdout=out))
            if not flags:
                self.assertIn('rejected password',out.getvalue())
                self.assertIn('Next:',out.getvalue())
                self.assertNotIn('cursor_sha256',out.getvalue())
            elif '--details' in flags:
                self.assertIn('Original SSH evidence',out.getvalue())
                self.assertIn('192.0.2.7',out.getvalue())
            else:
                data=json.loads(out.getvalue())
                self.assertNotIn('What it means',data)
                self.assertEqual(FAILED,data['ssh_analysis']['records'][0]['message'])

    def test_controls_are_escaped_without_masking_socket_endpoints(self):
        out=io.StringIO()
        self.assertEqual(0,main(['network','--sockets'],sources=NetworkSources(),runner=SocketRunner(),stdout=out))
        self.assertIn('0.0.0.0:2222',out.getvalue())
        out=io.StringIO()
        render(report('status',[Observation('system.kernel_release','invented\x1b]52;c;payload\x07\u202e','','source')]),out)
        self.assertNotIn('\x1b',out.getvalue())
        self.assertNotIn('\u202e',out.getvalue())
        self.assertIn('payload',out.getvalue())

    def test_tui_opens_explanations_and_keeps_original_observation_by_reference(self):
        session=Session(sources=SyntheticSources(),runner=SyntheticRunner())
        session.refresh()
        self.assertEqual('guide',session.rows()[0].action)
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='observation')
        source=session.rows()[session.selected].value
        session.open_row()
        self.assertIn('What it means',session.value)
        self.assertIs(source,session.value['Technical details'])
        self.assertIs(source,session.data['observations'][0])
        session.selected=next(i for i,r in enumerate(session.rows()) if r.label=='Technical details')
        session.open_row()
        self.assertIs(source,session.value)

    def test_targeted_search_findings_have_guidance_without_interpreting_original_candidates(self):
        from tests.test_event_search import SearchRunner, candidate
        session=Session(runner=SearchRunner([record()],kernel=[candidate()]))
        session.choose_page(5); session.update_setting('search_events'); session.refresh()
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='event_search')
        session.open_row()
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='queries')
        session.open_row(); session.open_row()
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='findings')
        session.open_row()
        self.assertTrue(all(r.action=='finding' for r in session.rows()))
        session.open_row()
        self.assertIn('What it means',session.value)

    def test_tui_finding_guidance_is_only_attached_to_normalized_finding_locations(self):
        session=Session(runner=JournalRunner([record('Out of memory: Killed process 42')]))
        session.choose_page(5); session.refresh()
        session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='findings')
        session.open_row(); self.assertEqual('finding',session.rows()[0].action)
        original=session.rows()[0].value
        session.open_row()
        self.assertIn('What it means',session.value)
        self.assertIs(original,session.value['Technical details'])
        forged={'rule_id':'kernel.panic','title':'untrusted','observation':'untrusted','confidence':'Confirmed',
                'recommendations':['untrusted action'],'limitations':[],'evidence':[]}
        raw=Session(runner=JournalRunner([record(forged)]))
        raw.choose_page(5); raw.refresh(); raw.choose_page(6)
        raw.selected=1; raw.open_row()
        # Original evidence is a raw tree, never duck-typed into trusted diagnostic guidance.
        raw.stack.append((forged,'Original message',0,0,'inspect'))
        self.assertTrue(all(r.action=='inspect' for r in raw.rows()))
        self.assertNotIn('What it means',raw.value)
        self.assertEqual([],raw.data['findings'])
