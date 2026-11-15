"""Invented firewall reports only; never query or modify live firewall policy."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import CommandRunner, Result
from faultlens.firewall import packet_context
from faultlens.incidents import diagnose
from tests.test_incidents import BOOT, record
from tests.test_ssh_analysis import SshRunner

TCP = '[UFW BLOCK] IN=synthetic0 OUT= MAC=aa:bb SRC=192.0.2.7 DST=198.51.100.8 LEN=60 PROTO=TCP SPT=1234 DPT=22 SYN'
UDP = '[UFW ALLOW] IN= OUT=synthetic0 SRC=2001:db8::7 DST=2001:db8::8 LEN=70 PROTO=UDP SPT=0 DPT=53 LEN=30'
ICMP = '[UFW AUDIT] IN=synthetic0 OUT= SRC=192.0.2.7 DST=198.51.100.8 PROTO=ICMP TYPE=8 CODE=0'


class FirewallRunner(SshRunner):
    def __init__(self, rows=(), **kwargs):
        super().__init__(**kwargs)
        self.firewall_result = Result('completed', '\n'.join(json.dumps(row) for row in rows), 0)
        self.firewall_calls = []

    def read_firewall_candidates(self, boot_id, **options):
        self.firewall_calls.append((boot_id,options))
        return self.firewall_result


class FirewallTests(unittest.TestCase):
    def test_tcp_udp_and_icmp_reports_preserve_addresses_interfaces_ports_and_originals(self):
        rows = [record(message, monotonic=index) for index,message in enumerate((TCP,UDP,ICMP))]
        data = diagnose(FirewallRunner(rows), search_firewall=True)['firewall_analysis']
        self.assertEqual({'ALLOW':1,'AUDIT':1,'BLOCK':1},data['reported_label_counts'])
        self.assertEqual(TCP,data['records'][0]['message'])
        tcp = data['findings'][0]['evidence'][0]['packet']
        self.assertEqual('synthetic0',tcp['input_interface'])
        self.assertEqual('192.0.2.7',tcp['source_address'])
        self.assertEqual(22,tcp['numeric_fields']['DPT'])
        udp = data['findings'][1]['evidence'][0]['packet']
        self.assertEqual(0,udp['numeric_fields']['SPT'])
        self.assertEqual(['70','30'],[value for name,value in udp['packet_fields'] if name=='LEN'])
        self.assertEqual('Unknown',data['packet_verdict'])
        self.assertEqual('Unknown',data['attack_assessment'])
        self.assertTrue(all(value['confidence']=='Confirmed' and value['cause_confidence']=='Unknown' for value in data['findings']))

    def test_all_known_prefixes_and_ipv6_icmp_are_narrow_report_labels(self):
        for label in ('BLOCK','ALLOW','AUDIT','AUDIT INVALID','LIMIT BLOCK'):
            value = packet_context(TCP.replace('[UFW BLOCK]', '[UFW '+label+']'))
            self.assertEqual(label,value['reported_label'])
            self.assertEqual('Unknown',value['packet_verdict'])
        value = packet_context(ICMP.replace('192.0.2.7','2001:db8::7').replace('198.51.100.8','2001:db8::8').replace('PROTO=ICMP','PROTO=ICMPv6'))
        self.assertEqual(8,value['numeric_fields']['TYPE'])

    def test_ambiguous_or_invalid_fields_do_not_classify_but_stay_visible(self):
        for text in (TCP+' SRC=192.0.2.9',TCP+' DPT=80',TCP.replace('192.0.2.7','999.0.0.1'),
                     TCP.replace('198.51.100.8','2001:db8::8'),TCP.replace('1234','65536'),
                     TCP.replace('PROTO=TCP','PROTO=OTHER'),TCP.replace(' DPT=22',''),
                     'example '+TCP,TCP+'\n'+ICMP,TCP.replace('[UFW BLOCK]','[CUSTOM DROP]'),
                     TCP.replace('synthetic0','bad\x1bname'),ICMP.replace('TYPE=8','TYPE=256')):
            self.assertIsNone(packet_context(text))
            data = diagnose(FirewallRunner([record(text)]),search_firewall=True)['firewall_analysis']
            self.assertEqual([],data['findings'])
            self.assertEqual(text,data['records'][0]['message'])
            self.assertEqual(1,data['unclassified_candidates'])

    def test_user_text_spoof_or_invalid_sentinel_rejects_source(self):
        for rows in ([record(TCP,_TRANSPORT='syslog')],
                     [record(TCP,_TRANSPORT='stdout',monotonic=0)]+[record(TCP,monotonic=i+1) for i in range(500)]):
            data = diagnose(FirewallRunner(rows),search_firewall=True)['firewall_analysis']
            self.assertEqual('invalid',data['parse_state'])
            self.assertEqual([],data['records'])

    def test_boot_scope_and_receipt_bounds_apply_to_every_candidate(self):
        runner = FirewallRunner([record(TCP,realtime=1500)])
        data = diagnose(runner,boot_id=BOOT,system_journal=True,since_us=1000,until_us=2000,search_firewall=True)
        self.assertEqual([(BOOT,{'system':True,'since_us':1000,'until_us':2000})],runner.firewall_calls)
        self.assertEqual(1,len(data['firewall_analysis']['findings']))
        for row in (record(TCP,realtime=999),record(TCP,realtime=2001),record(TCP,realtime=1500,_BOOT_ID='c'*32)):
            data = diagnose(FirewallRunner([row]),since_us=1000,until_us=2000,search_firewall=True)['firewall_analysis']
            self.assertEqual('invalid',data['parse_state'])

    def test_unresolved_boot_does_not_query_or_fall_back(self):
        runner = FirewallRunner()
        runner.boot_result = Result('missing')
        data = diagnose(runner,search_firewall=True)
        self.assertEqual('boot_scope_unresolved',data['firewall_analysis']['reason'])
        self.assertEqual([],runner.firewall_calls)
        with self.assertRaises(ValueError):
            diagnose(FirewallRunner(),search_firewall=1)

    def test_query_failures_empty_and_unrelated_kernel_logs_do_not_assert_security(self):
        for response in (Result('timeout'),Result('output_limit'),Result('completed','private error',1),Result('completed','',0)):
            runner = FirewallRunner()
            runner.firewall_result = response
            data = diagnose(runner,search_firewall=True)['firewall_analysis']
            self.assertEqual([],data['findings'])
            self.assertEqual('Unknown',data['attack_assessment'])
            self.assertNotIn('private error',json.dumps(data))
        data = diagnose(FirewallRunner([record('Unrelated synthetic kernel warning')]),search_firewall=True)['firewall_analysis']
        self.assertEqual(1,data['unclassified_candidates'])

    def test_caps_and_separate_timelines_never_become_distinct_attack_counts(self):
        data = diagnose(FirewallRunner([record(TCP,monotonic=i) for i in range(501)]),search_firewall=True)
        firewall=data['firewall_analysis']
        self.assertEqual(500,firewall['candidates_examined'])
        self.assertTrue(firewall['record_limit_reached'])
        self.assertEqual({'BLOCK':500},firewall['reported_label_counts'])
        self.assertEqual([],data['findings'])
        self.assertEqual('Unknown',data['root_cause'])

    def test_native_query_has_fixed_kernel_filter_no_priority_exclusion_or_shell_patterns(self):
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/journalctl'),patch(
                'faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().read_firewall_candidates(BOOT,system=True,since_us=1000,until_us=2000)
        args=capture.call_args.args[0]
        for value in ('--system','_TRANSPORT=kernel','--boot='+BOOT,'--since=@0.001000','--until=@0.002000','--lines=501'):
            self.assertIn(value,args)
        self.assertFalse(any('grep' in value or 'priority=' in value for value in args))

    def test_cli_is_opt_in_and_does_not_modify_policy_or_execute_terminal_controls(self):
        runner=FirewallRunner()
        self.assertNotIn('firewall_analysis',diagnose(runner))
        self.assertEqual([],runner.firewall_calls)
        for command in ('status','network','security','history','incidents'):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main([command,'--search-firewall'])
        output=io.StringIO()
        message=TCP+'\x1b]52;c;synthetic\x07'
        with patch('socket.socket',side_effect=AssertionError('no packets')),patch('subprocess.Popen',side_effect=AssertionError('no commands')):
            main(['diagnose','--search-firewall'],runner=FirewallRunner([record(message)]),stdout=output)
        self.assertNotIn('\x1b',output.getvalue())
        self.assertIn('\\u001b',output.getvalue())
        self.assertIn('192.0.2.7',output.getvalue())
