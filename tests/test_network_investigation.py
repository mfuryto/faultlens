"""Invented network conditions, not real traffic, probes or production attack tests."""
import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.commands import CATALOG,Command,Result
from faultlens.network_context import addresses,routes,owners,collect as context
from faultlens.network_sampling import practical,sampled
from faultlens.network_review import live,historical
from faultlens.network import collect,udp6_statistics
from faultlens.cli import main
from faultlens.incidents import diagnose
from tests.support import SyntheticRunner,SyntheticNetworkSources,SyntheticSocketRunner
from tests.network_context_fixtures import reply
from tests.test_firewall import FirewallRunner,TCP,UDP
from tests.test_incidents import record
from tests.test_ssh_analysis import FAILED,ssh_record
from tests.test_security_analysis import history


class ContextTests(unittest.TestCase):
    def test_address_route_assessment_does_not_inherit_an_unrelated_owner_failure(self):
        from faultlens.network_review import decisions
        runner=SyntheticRunner();runner.results[Command.SOCKET_OWNERS]=Result('completed','unsupported',0)
        runner.results[Command.SOCKETS]=Result('completed','',0)
        data=practical(SyntheticNetworkSources(),runner,sample_seconds=.05,sockets=True)
        self.assertEqual('partial',data['network_context']['state'])
        row=next(row for row in decisions(data) if row.label=='Addresses and routes')
        self.assertEqual('Measured',row.assessment)
        for command in (Command.NETWORK_ADDRESSES,Command.NETWORK_ROUTES4,Command.NETWORK_ROUTES6):
            runner.results[command]=Result('timeout')
        runner.results[Command.SOCKET_OWNERS]=reply(Command.SOCKET_OWNERS)
        data=practical(SyntheticNetworkSources(),runner,sample_seconds=.05,sockets=True)
        self.assertEqual('partial',data['network_context']['state'])
        self.assertEqual('Gap',next(row for row in decisions(data) if row.label=='Addresses and routes').assessment)

    def test_context_source_explanation_distinguishes_tool_failure_and_rejected_output(self):
        from faultlens.network_context import source_view
        for state,reason,expected in (('missing','command_unsuccessful','No trusted local ss'),
                ('timeout','command_unsuccessful','deadline'),('output_limit','command_unsuccessful','bounded output'),
                ('completed','unsupported_or_over_limit_output','completed successfully'),
                ('completed','command_unsuccessful','does not establish missing permission')):
            source={'state':'unavailable','rows':[],'command_state':state,'returncode':0 if reason=='unsupported_or_over_limit_output' else None,'reason':reason}
            detail=source_view('owners',source)
            self.assertIn(expected,detail['What it means']);self.assertTrue(detail['What you can do'])
            self.assertEqual(source['reason'],detail['Reader reason'])
        source={'state':'available','rows':[],'command_state':'completed','returncode':0,'reason':None}
        self.assertIn('empty readable source',source_view('routes4',source)['What it means'])

    def test_numeric_dual_stack_addresses_routes_and_original_metadata(self):
        values=addresses(reply(Command.NETWORK_ADDRESSES).stdout)
        self.assertEqual(['inet','inet6'],[row['family'] for row in values[0]['addr_info']])
        for family,command in ((4,Command.NETWORK_ROUTES4),(6,Command.NETWORK_ROUTES6)):
            values=routes(reply(command).stdout,family)
            self.assertEqual(family,values[0]['address_family']);self.assertEqual(254,values[0]['table'])
        for raw in ('{}','[{"ifindex":1,"ifindex":2}]','['+'{},'*256+'{}]', '[{"ifindex":true}]'):
            with self.assertRaises((ValueError,KeyError)):addresses(raw)
        for value in ({'type':[]},{'dst':0},{'dst':'2001:db8::/64'},{'gateway':'example.test'},{'dst':'192.0.2.0/33'}):
            with self.assertRaises((ValueError,TypeError)):routes(json.dumps([value]),4)
        values=json.loads(reply(Command.NETWORK_ADDRESSES).stdout);values[0]['addr_info'][0]['local']='2001:db8::1'
        with self.assertRaises(ValueError):addresses(json.dumps(values))

    def test_owner_parser_retains_multiple_names_pids_and_descriptors_without_execution(self):
        raw='tcp ESTAB 1 2 192.0.2.1:22 198.51.100.2:4567 users:(("synthetic worker",pid=42,fd=3),("synthetic",pid=43,fd=4))'
        values=owners(raw);self.assertEqual([42,43],[row['pid'] for row in values[0]['owners']])
        self.assertEqual(raw,values[0]['original'])
        for suffix in ('users:(("x",pid=0,fd=1))','users:(("x",pid=42,fd=-1))','users:(("x",pid=42,fd=1)); id','users:(("x\x1b",pid=42,fd=1))','unknown'):
            with self.assertRaises(ValueError):owners('tcp ESTAB 0 0 *:22 *:* '+suffix)

    def test_owner_parser_accepts_native_column_padding_without_losing_original(self):
        raw='tcp ESTAB 0 0 192.0.2.1:22 198.51.100.2:4567 users:(("synthetic worker",pid=42,fd=3))   \t'
        values=owners(raw)
        self.assertEqual(raw,values[0]['original'])
        self.assertEqual(42,values[0]['owners'][0]['pid'])
        for suffix in (' extra','\x1b','\r'):
            with self.assertRaises(ValueError):owners(raw+suffix)

    def test_unique_full_socket_match_and_bounded_reported_service_association(self):
        runner=SyntheticSocketRunner();data=practical(SyntheticNetworkSources(),runner,sockets=True,sample_seconds=.05)
        row=data['sockets']['rows'][0]
        self.assertEqual('reported_unique_snapshot_match',row['owner_state'])
        self.assertEqual('example-worker.service',row['owners'][0]['service'])
        self.assertEqual(100,row['owners'][0]['process_reference']['start_ticks'])
        self.assertEqual(3,len(data['network_samples']));self.assertEqual(512,len(data['sockets']['rows']))
        self.assertEqual(256,len(data['network_context']['sources']['routes6']['rows']))
        duplicate={'rows':[copy.deepcopy(row),copy.deepcopy(row)]}
        context(runner,sockets=duplicate,sample_seconds=.05)
        self.assertTrue(all(row['owner_state']=='not_established' and not row['owners'] for row in duplicate['rows']))

    def test_missing_sources_do_not_hide_independent_addresses_or_guess_ownership(self):
        runner=SyntheticRunner();runner.results[Command.NETWORK_ROUTES6]=Result('timeout')
        runner.results[Command.SOCKET_OWNERS]=Result('completed','unsupported',0)
        sockets={'rows':[]};data=context(runner,sockets=sockets)
        self.assertEqual('partial',data['state']);self.assertEqual('available',data['sources']['addresses']['state'])
        self.assertEqual('unavailable',data['sources']['owners']['state'])
        self.assertNotIn('processes',data)
        runner.results[Command.SOCKET_OWNERS]=reply(Command.SOCKET_OWNERS)
        runner.read_system_resources=lambda *a:Result('timeout')
        data=context(runner,sockets={'rows':[]})
        self.assertEqual('partial',data['state']);self.assertEqual('unavailable',data['processes']['state'])
        self.assertIsNone(data['sources']['owners']['rows'][0]['owners'][0]['service'])

    def test_catalog_only_reads_numeric_local_configuration_and_owners(self):
        for command in (Command.NETWORK_ADDRESSES,Command.NETWORK_ROUTES4,Command.NETWORK_ROUTES6):
            tool,args=CATALOG[command];self.assertEqual('ip',tool);self.assertIn('-j',args);self.assertIn('show',args)
            for forbidden in ('get','add','change','delete','flush'):self.assertNotIn(forbidden,args)
        self.assertIn('-p',CATALOG[Command.SOCKET_OWNERS][1]);self.assertIn('-n',CATALOG[Command.SOCKET_OWNERS][1])


class LiveInvestigationTests(unittest.TestCase):
    def test_three_intervals_keep_exact_deltas_and_do_not_create_a_baseline_or_attack(self):
        data=practical(SyntheticNetworkSources(),SyntheticSocketRunner(),sockets=True,sample_seconds=.05)
        refs=[ref for card in data['network_review']['cards'] for ref in card['evidence'] if 'counter' in ref]
        self.assertEqual({0,1,2},{ref['sample_index'] for ref in refs})
        self.assertTrue(all(ref['delta']==1 and ref['interval_seconds']>0 for ref in refs))
        self.assertEqual('Unknown',data['network_review']['attack_assessment'])
        self.assertTrue(any(card['assessment']=='Info' and card.get('reported_peer')=='198.51.100.1' for card in data['network_review']['cards']))
        self.assertTrue(all(card['root_cause']=='Unknown' for card in data['network_review']['cards']))

    def test_legitimate_high_traffic_without_pressure_does_not_become_an_attack_card(self):
        class Sources(SyntheticNetworkSources):
            def read(self,path,limit=262144):
                result=super().read(path,limit)
                if path=='/proc/net/dev':return result.replace(' 10 0 0',' 1000000 0 0').replace(': 10',': 1000000000')
                if path=='/proc/net/netstat':return result.splitlines()[0]+'\nTcpExt: 0 0 0 0 0\n'
                return result
        data=practical(Sources(),SyntheticRunner(),sample_seconds=.05)
        self.assertFalse(any(row['assessment'] in {'Review','Possible'} for row in data['network_review']['cards']))
        self.assertEqual('Unknown',data['network_review']['attack_assessment'])

    def test_listener_queue_and_state_rows_explain_capacity_and_benign_alternatives(self):
        runner=SyntheticSocketRunner();data=practical(SyntheticNetworkSources(),runner,sockets=True,sample_seconds=.05)
        from faultlens.sockets import parse
        data['sockets']['rows']=parse('tcp LISTEN 90 100 192.0.2.1:2222 *:*\n'+''.join(
            'tcp SYN-RECV 0 0 192.0.2.1:2222 198.51.100.1:'+str(2000+i)+'\n' for i in range(10)))
        live(data);cards=data['network_review']['cards']
        self.assertTrue(any('accept queue' in value['title'] for value in cards))
        self.assertTrue(any('SYN-RECV' in value['title'] for value in cards))
        self.assertTrue(all(value['alternatives'] and value['next_steps'] for value in cards))
        self.assertEqual('Unknown',data['network_review']['attack_assessment'])

    def test_missing_ipv6_reset_and_counter_wrap_are_gaps_not_zero_or_all_clear(self):
        class Sources(SyntheticNetworkSources):
            def read(self,path,limit=262144):
                if path=='/proc/net/snmp6':raise PermissionError('synthetic-private-error')
                result=super().read(path,limit)
                if path=='/proc/net/netstat' and self.network_reads[path]%2==0:
                    return result.splitlines()[0]+'\nTcpExt: 0 0 0 0 0\n'
                return result
        data=practical(Sources(),SyntheticRunner(),sample_seconds=.05)
        self.assertEqual('partial',data['state'])
        for sample in data['network_samples']:
            unknown=[row for row in sample['observations'] if row['key']=='network.udp6']
            self.assertEqual('unavailable',unknown[0]['state'])
        self.assertNotIn('synthetic-private-error',json.dumps(data))
        class Missing(SyntheticNetworkSources):
            def read(self,*args,**kwargs):raise PermissionError('synthetic')
        unavailable=practical(Missing(),SyntheticRunner(),sample_seconds=.05)
        self.assertEqual('unavailable',unavailable['counter_state'])
        self.assertEqual('partial',unavailable['state'])
        self.assertEqual('available',unavailable['network_context']['sources']['addresses']['state'])
        for value in ('Udp6InErrors -1','Udp6InErrors 18446744073709551616','Udp6InErrors 1\nUdp6InErrors 2'):
            with self.assertRaises(ValueError):udp6_statistics(value)

    def test_reported_link_address_and_route_problems_keep_configuration_limits(self):
        runner=SyntheticRunner();values=json.loads(reply(Command.NETWORK_ADDRESSES).stdout)
        values[0]['operstate']='DOWN';values[0]['addr_info'][1]['dadfailed']=True
        runner.results[Command.NETWORK_ADDRESSES]=Result('completed',json.dumps(values),0)
        runner.results[Command.NETWORK_ROUTES6]=Result('completed',json.dumps([{'dst':'2001:db8:1::/64','type':'prohibit','table':123}]),0)
        data=practical(SyntheticNetworkSources(),runner,sample_seconds=.05)
        cards=data['network_review']['cards']
        self.assertTrue(any('operational state DOWN' in row['title'] for row in cards))
        self.assertTrue(any('duplicate-address' in row['title'] for row in cards))
        route=next(row for row in cards if 'control entries' in row['title'])
        self.assertEqual('Info',route['assessment']);self.assertIn('Policy rules',route['meaning'])

    def test_context_flag_and_full_cli_details_work_without_native_calls(self):
        for command in ('network','security'):
            output=io.StringIO()
            with patch('subprocess.Popen',side_effect=AssertionError('No native fallback')):
                self.assertEqual(0,main([command,'--network-context','--sockets','--json','--sample-seconds','.05'],
                    sources=SyntheticNetworkSources(),runner=SyntheticSocketRunner(),stdout=output))
            value=json.loads(output.getvalue());self.assertIn('network_context',value);self.assertEqual(3,len(value['network_samples']))
        for args in (['status','--network-context'],['investigate','--network-context','--mode','period','--since-us','0','--until-us','1']):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):main(args,stdout=io.StringIO())


class HistoricalInvestigationTests(unittest.TestCase):
    def test_multiple_peers_and_failure_then_acceptance_keep_actual_records_and_unknowns(self):
        failures=[ssh_record(FAILED.replace('192.0.2.7','192.0.2.'+str(7+i%3)),monotonic=i*1000000,__CURSOR='i='+str(i)) for i in range(21)]
        failures.append(ssh_record('Accepted password for synthetic-admin from 192.0.2.7 port 2222 ssh2',monotonic=22000000,__CURSOR='i=accepted'))
        data=diagnose(FirewallRunner(ssh=failures),search_ssh=True)
        cards=data['network_review']['cards']
        self.assertTrue(any('reported peers' in row['title'] for row in cards))
        success=next(row for row in cards if 'acceptance after' in row['title'])
        self.assertEqual('ssh_analysis',success['source_key']);self.assertIn('192.0.2.7',success['observation'])
        self.assertTrue(success['window']);self.assertIn(21,success['candidate_indices'])
        self.assertEqual('Unknown',success['attack_assessment'])
        tied=[ssh_record(FAILED,monotonic=100,__CURSOR='i=t'+str(i)) for i in range(5)]
        tied.append(ssh_record('Accepted password for synthetic-admin from 192.0.2.7 port 2222 ssh2',monotonic=100,__CURSOR='i=same-time'))
        uncertain=diagnose(FirewallRunner(ssh=tied),search_ssh=True)
        self.assertFalse(any('acceptance after' in row['title'] for row in uncertain['network_review']['cards']))

    def test_scan_like_and_udp_report_bursts_are_traceable_not_verified_packets_or_attacks(self):
        rows=[record(TCP.replace('DPT=22','DPT='+str(2000+i)),monotonic=i*1000000,__CURSOR='i='+str(i)) for i in range(10)]
        rows += [record(UDP,monotonic=i*500000,__CURSOR='i=u'+str(i)) for i in range(100)]
        data=diagnose(FirewallRunner(rows),search_firewall=True)
        cards=data['network_review']['cards']
        self.assertTrue(any('multi-port' in row['title'] and '2000' in row['observation'] for row in cards))
        self.assertTrue(any('UDP traffic burst' in row['title'] and '2001:db8::7' in row['observation'] for row in cards))
        self.assertTrue(all(row['assessment']=='Possible' and row['candidate_indices'] for row in cards))
        self.assertEqual('Unknown',data['root_cause'])

    def test_historical_card_caps_propagate_without_hiding_source_references(self):
        from faultlens.security_analysis import assess
        data={'atop':history(tuple([10]*5+[10000])*12)};assess(data)
        review=data['network_review']
        self.assertEqual(32,len(review['cards']));self.assertTrue(review['cards_truncated'])
        self.assertGreater(review['matching_cards'],32)
        self.assertEqual(data['security_analysis']['matching_indicators'],review['matching_cards'])
        self.assertTrue(all(row['evidence'] for row in review['cards']))

    def test_insufficient_or_gapped_recordings_do_not_create_retrospective_traffic(self):
        from faultlens.security_analysis import assess
        for recording in (history((10,10)),history((10,10,10,10,10,10))):
            data={'atop':recording};assess(data)
            self.assertEqual([],data['network_review']['cards'])
        data={'atop':history()};data['atop']['samples'][3]['since_boot']=True;assess(data)
        self.assertEqual([],data['network_review']['cards'])
        data={'atop':{'state':'unavailable','samples':[]}};assess(data)
        self.assertEqual('unavailable',data['network_review']['state'])
        self.assertEqual('Unknown',data['network_review']['attack_assessment'])
