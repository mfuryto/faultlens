"""Invented per-boot summaries; presentation never queries or upgrades their evidence."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Result
from faultlens.overview import incidents
from faultlens.presentation import boot_summary_view,guide,render
from faultlens.tui_model import Session
from tests.test_incident_overview import OverviewRunner,IDS


class BootPresentationTests(unittest.TestCase):
    def test_recorded_reports_are_visible_in_summary_and_not_described_as_no_warning(self):
        data=incidents(OverviewRunner())
        original=copy.deepcopy(data)
        self.assertIn('need review',guide(data)['Summary'])
        self.assertIn('remaining boots were not examined',' '.join(guide(data)['What the evidence means']))
        out=io.StringIO(); render(data,out)
        text=out.getvalue()
        self.assertIn('1 matched report in 1 retained record',text)
        self.assertIn('kernel reported killing a process',text)
        self.assertNotIn('without a matched warning',text)
        self.assertIn('not separate incidents',text)
        self.assertEqual(original,data)

    def test_unavailable_boot_is_not_an_empty_or_healthy_boot(self):
        runner=OverviewRunner()
        runner.results[IDS[2]]=Result('timeout')
        data=incidents(runner)
        value=boot_summary_view(data['summaries'][1])
        self.assertIn('Journal evidence unavailable',value['Observed'])
        self.assertNotIn('0 matched',value['Observed'])
        self.assertIn('does not establish absent logs',' '.join(value['What it means']))
        self.assertIs(data['summaries'][1],value['Technical details'])

    def test_no_matches_caps_and_unclassified_messages_keep_their_limits(self):
        summary=incidents(OverviewRunner())['summaries'][0]
        summary.update(finding_count=0,finding_counts_by_rule={},record_limit_reached=True,
                       unsupported_messages_in_response=2)
        value=boot_summary_view(summary)
        self.assertIn('not ruled out',' '.join(value['What it means']))
        self.assertIn('earlier entries may be omitted',' '.join(value['Evidence limits']))
        self.assertIn('2 message bodies',' '.join(value['Evidence limits']))
        data={'command':'incidents','state':'available','summaries':[summary]}
        self.assertIn('other parts could not be verified',guide(data)['Summary'])

    def test_follow_up_command_pins_boot_identity_and_preserves_scope(self):
        for system in (False,True):
            summary=incidents(OverviewRunner(),system_journal=system)['summaries'][0]
            value=boot_summary_view(summary)
            actions=' '.join(value['What you can do'])
            self.assertIn('./bin/faultlens diagnose --boot-id '+IDS[1],actions)
            self.assertEqual(system,'--system-journal' in actions)
            self.assertNotIn('sudo',actions)
            summary['boot']['boot_id']='$(touch /tmp/never-execute)'
            self.assertNotIn('./bin/faultlens',' '.join(boot_summary_view(summary)['What you can do']))

    def test_cli_readable_details_and_json_keep_separate_contracts(self):
        for flags in ([],['--details'],['--json']):
            runner=OverviewRunner()
            out=io.StringIO()
            self.assertEqual(0,main(['incidents',*flags],runner=runner,stdout=out))
            self.assertEqual(3,len(runner.reads))
            if not flags:
                self.assertIn('Boot summaries',out.getvalue())
                self.assertIn('1 matched report',out.getvalue())
            elif flags==['--json']:
                value=json.loads(out.getvalue())
                self.assertNotIn('Observed',value['summaries'][0])
                self.assertEqual({'kernel.oom':1},value['summaries'][0]['finding_counts_by_rule'])
            else:
                self.assertNotIn('Optional fresh diagnosis',out.getvalue())

    def test_tui_explains_boot_and_selects_id_without_collecting_or_replacing_report(self):
        session=Session(runner=OverviewRunner())
        session.choose_page(4); session.refresh()
        data=session.data
        summary=data['summaries'][0]
        with patch.object(session,'refresh',side_effect=AssertionError('Explicit refresh required')):
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='boot_summaries')
            session.open_row()
            self.assertEqual('boot_summary',session.rows()[0].action)
            session.open_row()
            self.assertIs(summary,session.value['Technical details'])
            self.assertIs(summary['boot'],session.value['Diagnose this boot'])
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='boot')
            session.open_row()
            self.assertEqual(5,session.page)
            self.assertEqual(summary['boot']['boot_id'],session.settings.boot_selector)
            self.assertIs(data,session.data)
            self.assertIn('Press r',session.notice)

    def test_original_summary_access_and_raw_evidence_roles_remain_available(self):
        session=Session(runner=OverviewRunner())
        session.choose_page(4); session.refresh()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='boot_summaries')
        session.open_row(); session.open_row(inspect_only=True)
        self.assertIs(session.data['summaries'][0],session.value)
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))
        session.stack=[(session.data['summaries'],'Raw original summaries',0,0,'inspect')]
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))


if __name__=='__main__':
    unittest.main()
