"""Invented socket rows; interpretations never infer exposure, owners or attacks."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Result
from faultlens.socket_presentation import row_view,snapshot_view
from faultlens.sockets import attach,parse
from faultlens.tui_model import Session
from tests.test_network_analysis import NetworkSources
from tests.test_sockets import SocketRunner


class SocketPresentationTests(unittest.TestCase):
    def test_bindings_do_not_become_reachability_or_service_claims(self):
        for address,expected in [('0.0.0.0','Wildcard'),('[::]','Wildcard'),('*','Wildcard'),
                                 ('127.0.0.1','Loopback'),('[::1]','Loopback'),
                                 ('192.0.2.7','Specific'),('[fe80::1%synthetic0]','Specific')]:
            row=parse('tcp LISTEN 0 128 '+address+':2222 *:*')[0]
            original=copy.deepcopy(row)
            value=row_view(row)
            self.assertIn(expected,value['Local binding'])
            self.assertIn(address+':2222',value['Observed'])
            self.assertIn('external reachability',' '.join(value['Evidence limits']))
            self.assertIs(row,value['Technical details'])
            self.assertEqual(original,row)

    def test_udp_is_not_described_as_a_tcp_handshake_or_listener(self):
        for state in ('UNCONN','ESTAB','LISTEN'):
            row=parse('udp '+state+' 0 0 *:53 *:*')[0]
            value=row_view(row)
            self.assertNotIn('Listening for TCP',value['State explained'])
            self.assertIn('UDP',' '.join(value['What it means']))
        value=row_view(parse('udp ESTAB 0 0 192.0.2.7:53 198.51.100.8:1234')[0])
        self.assertIn('no TCP-style handshake',' '.join(value['What it means']))

    def test_closing_handshake_and_unknown_tcp_states_are_not_incidents(self):
        for state in ('ESTAB','SYN-SENT','SYN-RECV','TIME-WAIT','CLOSE-WAIT','FIN-WAIT-1',
                      'FIN-WAIT-2','LAST-ACK','CLOSING','UNKNOWN','NEW-SYN-RECV','UNCONN'):
            row=parse('tcp '+state+' 123 456 192.0.2.7:1234 198.51.100.8:443')[0]
            value=row_view(row)
            self.assertIn(state,value['Observed'])
            self.assertIn('native ss semantics',' '.join(value['Evidence limits']))
            self.assertNotIn('critical',value)
            self.assertEqual(123,value['Technical details']['receive_queue'])
        closing=row_view(parse('tcp CLOSE-WAIT 0 0 192.0.2.7:1 198.51.100.8:2')[0])
        self.assertIn('does not prove an application leak',' '.join(closing['What it means']))

    def test_unavailable_sources_explain_failure_without_showing_partial_prefixes(self):
        for result in (Result('missing'),Result('timeout','tcp LISTEN 0 1 *:22 *:*'),
                       Result('output_limit'),Result('completed','',1),Result('completed','bad',0)):
            data={'state':'available','limitations':[]}
            attach(data,SocketRunner(result))
            original=copy.deepcopy(data)
            value=snapshot_view(data['sockets'])
            self.assertEqual('Socket snapshot unavailable',value['Observed'])
            self.assertEqual([],value['Technical details']['rows'])
            self.assertIn('No installation',' '.join(value['What you can do']))
            self.assertEqual(original,data)

    def test_empty_rows_do_not_prove_absence_and_duplicate_rows_are_not_distinct_services(self):
        data={'state':'available','limitations':[]}
        attach(data,SocketRunner(Result('completed','',0)))
        value=snapshot_view(data['sockets'])
        self.assertEqual('0 socket rows collected',value['Observed'])
        self.assertIn('does not prove that services are absent',' '.join(value['What it means']))
        attach(data,SocketRunner(Result('completed','tcp LISTEN 0 1 *:2222 *:*\n'*2,0)))
        value=snapshot_view(data['sockets'])
        self.assertEqual('2 socket rows collected',value['Observed'])
        self.assertEqual(2,len(value['Technical details']['rows']))

    def test_cli_explains_once_per_state_preserves_all_endpoints_and_json_contract(self):
        rows='tcp LISTEN 0 128 0.0.0.0:2222 *:*\ntcp LISTEN 0 64 [::]:2223 *:*\n'
        for flags in ([],['--details'],['--json']):
            out=io.StringIO(); runner=SocketRunner(Result('completed',rows,0))
            self.assertEqual(0,main(['network','--sockets',*flags],sources=NetworkSources(),runner=runner,stdout=out))
            self.assertEqual(1,len(runner.calls))
            self.assertIn('0.0.0.0:2222',out.getvalue()); self.assertIn('[::]:2223',out.getvalue())
            if not flags:
                self.assertEqual(1,out.getvalue().count('Listening for TCP connections'))
                self.assertIn('Wildcard local address',out.getvalue())
            elif flags==['--json']:
                data=json.loads(out.getvalue())
                self.assertNotIn('State explained',data['sockets']['rows'][0])
                self.assertEqual(rows.splitlines(),[value['original'] for value in data['sockets']['rows']])

    def test_tui_opens_socket_explanations_without_collection_or_evidence_copies(self):
        session=Session(sources=NetworkSources(),runner=SocketRunner())
        session.choose_page(2); session.update_setting('sockets'); session.refresh()
        snapshot=session.data['sockets']
        original=copy.deepcopy(session.data)
        with patch.object(session,'refresh',side_effect=AssertionError('No hidden collection')),patch('socket.socket',side_effect=AssertionError('No probes')):
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='socket_snapshot')
            session.open_row()
            self.assertIs(snapshot,session.value['Technical details'])
            self.assertIs(snapshot['rows'],session.value['Socket rows'])
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='socket_rows')
            session.open_row(); session.open_row()
            self.assertIs(snapshot['rows'][0],session.value['Technical details'])
            self.assertIn('Listening',session.value['State explained'])
        self.assertEqual(original,session.data)

    def test_raw_socket_tree_and_explicit_metadata_access_stay_raw(self):
        session=Session(sources=NetworkSources(),runner=SocketRunner())
        session.choose_page(3); session.update_setting('sockets'); session.refresh()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='socket_snapshot')
        session.open_row(inspect_only=True)
        self.assertIs(session.data['sockets'],session.value)
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))
        session.stack=[(session.data['sockets']['rows'],'Raw socket rows',0,0,'inspect')]
        self.assertTrue(all(row.action=='inspect' for row in session.rows()))


if __name__=='__main__':
    unittest.main()
