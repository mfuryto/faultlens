"""Synthetic complete frontend acceptance; no live host evidence or remote traffic."""
import copy
import io
import unittest
from unittest.mock import patch

from faultlens.interface_presentation import interface_view
from faultlens.presentation import advice_line,render
from faultlens.tui_model import Session,PAGES
from tests.test_network_analysis import NetworkSources,HEADER,device,analyze
from tests.test_incident_overview import OverviewRunner
from tests.support import SyntheticNetworkSources,SyntheticPhase3Runner,SyntheticSources


class Phase4CloseoutTests(unittest.TestCase):
    def test_interface_rates_keep_actual_timing_originals_and_valid_zero_changes(self):
        data=analyze(); observation=data['observations'][0]; row=observation['value'][0]
        original=copy.deepcopy(data)
        view=interface_view(row,data['sample'])
        self.assertIn('200.0 B/s',' '.join(view['Measurements']))
        self.assertIn('0 additional counter events',' '.join(view['Measurements']))
        self.assertEqual('0.50 seconds',view['Measured batch interval'])
        self.assertIs(row,view['Technical details']); self.assertIs(data['sample'],view['Sample timing'])
        self.assertEqual(original,data)

    def test_interface_appearance_disappearance_and_decrease_never_infer_zero_rates(self):
        for devices,expected in [([HEADER,HEADER+device()],'only in the second'),
                                  ([HEADER+device(),HEADER],'only in the first'),
                                  ([HEADER+device(received=200),HEADER+device(received=100)],'decrease')]:
            data=analyze(NetworkSources(devices=devices)); row=data['observations'][0]['value'][0]
            view=interface_view(row,data['sample'])
            self.assertIn(expected,view['What it means'])
            self.assertIn('no zero values',' '.join(view['Measurements']))
            self.assertIsNone(row['per_second'])
            output=io.StringIO(); render(data,output)
            self.assertIn(expected,output.getvalue())
            self.assertNotIn('Receive 0.0 B/s',output.getvalue())

    def test_error_drop_growth_is_readable_without_becoming_an_attack_or_device_failure(self):
        after=device(received=200,sent=400).replace('200 10 0 0','200 10 2 3').replace('400 20 0 0','400 20 4 5')
        data=analyze(NetworkSources(devices=[HEADER+device(),HEADER+after]))
        output=io.StringIO(); render(data,output)
        self.assertIn('Receive errors: 2 additional counter events; 4.0/s',output.getvalue())
        self.assertIn('Send drops: 5 additional counter events; 10.0/s',output.getvalue())
        self.assertEqual([],data['findings'])
        self.assertEqual('Unknown',data['attack_assessment'])
        self.assertEqual('Unknown',data['root_cause'])

    def test_suggested_commands_stay_on_one_escaped_line(self):
        command='./bin/faultlens diagnose --boot-id '+'a'*32+' --system-journal'
        output=io.StringIO()
        advice_line(output,'Optional fresh diagnosis using this boot identity and existing access: '+command,'    ','Next: ')
        self.assertIn('      '+command,output.getvalue().splitlines())
        output=io.StringIO()
        advice_line(output,"To see the journal tool's own access/availability explanation, run: journalctl --system --list-boots --no-pager",'  - ')
        self.assertIn('journalctl --system --list-boots --no-pager',[line.strip() for line in output.getvalue().splitlines()])
        output=io.StringIO()
        advice_line(output,'Optional current-state check (not historical proof): invented\x1b\ncommand')
        self.assertNotIn('\x1b',output.getvalue())
        self.assertIn('invented\\u001b\\ncommand',output.getvalue())

    def test_interface_navigation_is_reference_based_and_raw_reports_stay_raw(self):
        session=Session(); session.data=analyze(); session.choose_page(2)
        original=copy.deepcopy(session.data)
        with patch.object(session,'refresh',side_effect=AssertionError('No hidden collection')):
            session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='observation' and r.value['key']=='network.interfaces')
            session.open_row()
            session.selected=next(i for i,r in enumerate(session.rows()) if r.action=='interface_samples')
            session.open_row(); session.open_row()
            self.assertIs(session.data['observations'][0]['value'][0],session.value['Technical details'])
            self.assertIs(session.data['sample'],session.value['Sample timing'])
            session.back(); session.open_row(inspect_only=True)
            self.assertTrue(all(r.action=='inspect' for r in session.rows()))
        self.assertEqual(original,session.data)

    def test_complete_frontend_session_explicit_collection_and_all_explained_source_flows(self):
        session=Session(sources=SyntheticNetworkSources(),runner=SyntheticPhase3Runner(),
            pstore_collector=SyntheticSources().pstore_snapshot,pstore_archive_collector=SyntheticSources().pstore_snapshot)
        for key in ('sockets','search_events','search_ssh','search_firewall','pstore','pstore_archive','atop_extended'):
            self.assertFalse(getattr(session.settings,key))
        for page in range(len(PAGES)):
            session.choose_page(page)
            if page<4: session.refresh()
            elif page==4:
                session.runner=OverviewRunner(); session.refresh()
            elif page==5:
                session.runner=SyntheticPhase3Runner()
                for key in ('search_ssh','search_firewall','pstore','pstore_archive'): session.update_setting(key)
                session.update_setting('atop_date','20260101'); session.update_setting('atop_extended'); session.refresh()
            else:
                previous=session.data; session.refresh(); self.assertIs(previous,session.data)
            self.assertTrue(session.rows())
        session.choose_page(5)
        original=session.data
        for action in ('recording','crash_source','analysis'):
            session.selected=next(i for i,r in enumerate(session.rows()) if r.action==action)
            with patch.object(session,'refresh',side_effect=AssertionError('No browsing collection')):
                session.open_row(); self.assertTrue(session.rows()); session.back()
            self.assertIs(original,session.data)
        session.timeline(); session.find(''); session.help()
        self.assertIn('Explained views',session.value)
        session.choose_page(6); session.selected=1; session.open_row()
        self.assertIs(original,session.value)


if __name__=='__main__':
    unittest.main()
