"""Synthetic firewall state, qualified attribution and bounded source failures."""
import io
import json
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from faultlens.commands import CATALOG,Command,CommandRunner,Result
from faultlens.firewall_state import collect
from faultlens import firewall_rules,firewall_history,_firewall_log
from faultlens.firewall_presentation import view,render,table,source_detail
from faultlens.cli import main
from tests.firewall_state_fixtures import Runner,START,nft_snapshot,jail_status,log_reply


def report(runner=None,**options):return collect(runner or Runner(),window='period',since_us=START,until_us=START+86400000000,**options)


class FirewallStateTests(unittest.TestCase):
    def test_independent_sources_keep_actual_rules_policies_sets_bans_settings_and_logs(self):
        data=report();self.assertEqual('available',data['state'])
        self.assertEqual('Unknown',data['packet_verdict']);self.assertEqual('Unknown',data['human_initiator'])
        self.assertEqual('drop',data['sources']['nftables']['data']['chains'][0]['policy'])
        self.assertEqual(1,len(data['correspondences']));item=data['correspondences'][0]
        self.assertEqual({'nftables','iptables4'},{ref['source'] for ref in item['matches']})
        self.assertIn('Unverified',item['enforcement']);self.assertEqual(3,len(data['records']))
        detail=table('firewall_jails',data)[2][0].detail
        self.assertIn('maxretry 3',detail['Current trigger settings']);self.assertIn('600 seconds',detail['Current trigger settings'])
        self.assertIn('overlaps native',source_detail('iptables4_backend',data['sources']['iptables4_backend'])['Backend'])

    def test_a_name_alone_never_establishes_ownership_or_enforcement(self):
        runner=Runner();raw=json.loads(nft_snapshot());raw['nftables'][-1]['rule']['expr']=[{'log':{'prefix':'f2b-sshd BLOCK'}},{'accept':None}]
        runner.results[Command.NFT_RULESET]=Result('completed',json.dumps(raw),0)
        runner.results[Command.IPTABLES_SAVE]=Result('completed','*filter\n:f2b-sshd - [0:0]\nCOMMIT\n',0)
        data=report(runner);self.assertEqual([],data['correspondences'][0]['matches'])
        self.assertEqual('Unknown',data['correspondences'][0]['human_initiator'])
        self.assertIn('No supported correspondence',data['correspondences'][0]['assessment'])

    def test_large_shared_sets_keep_original_rules_and_bound_the_correspondence_preview(self):
        raw=json.loads(nft_snapshot(64))
        raw['nftables'][2]['set']['elem']=[prefix+'.'+str(i) for prefix in ('192.0.2','198.51.100','203.0.113') for i in range(1,255)][:512]
        runner=Runner();runner.results[Command.NFT_RULESET]=Result('completed',json.dumps(raw),0)
        data=report(runner)
        self.assertEqual(64,len(data['sources']['nftables']['data']['rules']))
        self.assertEqual(8,len(data['correspondences'][0]['matches']))
        self.assertTrue(data['correspondences'][0]['match_preview_limit_reached'])
        self.assertEqual(512,len(data['sources']['nftables']['data']['sets'][0]['networks']))

    def test_missing_malformed_empty_and_inaccessible_are_distinct(self):
        runner=Runner();runner.results[Command.NFT_RULESET]=Result('completed','bad',0)
        runner.results[Command.IPTABLES_SAVE]=Result('timeout');runner.results[Command.UFW_STATUS]=Result('missing')
        data=report(runner);self.assertEqual('partial',data['state'])
        self.assertEqual('unsupported_or_over_limit_output',data['sources']['nftables']['reason'])
        self.assertEqual('command_unsuccessful',data['sources']['iptables4']['reason'])
        self.assertEqual('available',data['sources']['iptables6']['state'])
        runner.results={command:Result('missing') for command in Command};runner.log_result=Result('completed','',1);runner.journal_result=Result('timeout')
        data=report(runner);self.assertEqual('unavailable',data['state']);self.assertIn('could be assessed',view(data)['Answer'])
        runner.results[Command.NFT_RULESET]=Result('completed','{"nftables":[]}',0)
        self.assertEqual('available',report(runner)['sources']['nftables']['state'])
        self.assertIn('ban count could not be assessed',view(report(runner))['Answer'])

    def test_ipv6_negated_and_prefix_matches_preserve_qualified_semantics(self):
        runner=Runner();runner.jail_result=Result('completed',jail_status(addresses='2001:db8::7 198.51.100.9'),0)
        runner.results[Command.IP6TABLES_SAVE]=Result('completed','*filter\n:INPUT DROP [0:0]\n-A INPUT -s 2001:db8::/64 -j DROP\nCOMMIT\n',0)
        data=report(runner)
        self.assertEqual('ip6',data['sources']['iptables6']['data']['rules'][0]['family'])
        self.assertEqual('iptables6',data['correspondences'][0]['matches'][0]['source'])
        self.assertEqual('nftables',data['correspondences'][1]['matches'][0]['source'])
        parsed=firewall_rules.iptables('*filter\n:INPUT DROP [0:0]\n-A INPUT ! -s 192.0.2.7 -j DROP\nCOMMIT\n','ip')
        self.assertEqual([],parsed['rules'][0]['source_networks'])

    def test_unsupported_objects_expressions_and_malformed_snapshots_never_become_packet_verdicts(self):
        raw=json.loads(nft_snapshot());raw['nftables'].append({'map':{'name':'synthetic_map'}})
        parsed=firewall_rules.nft(json.dumps(raw));self.assertEqual(1,len(parsed['unsupported_objects']))
        for raw in ('{}','{"nftables":{}}','{"nftables":[],"nftables":[]}','{"nftables":[{"rule":{"family":"ip"}}]}'):
            with self.assertRaises((ValueError,KeyError,TypeError)):firewall_rules.nft(raw)
        with self.assertRaises(ValueError):firewall_rules.iptables('*filter\n:INPUT DROP [0:0]\n','ip')
        with self.assertRaises(ValueError):firewall_rules.fail2ban_status(jail_status('other'),'sshd')

    def test_file_history_is_unfiltered_context_with_unverified_time_and_boot(self):
        value=firewall_history.log_tail(log_reply().stdout);record=value['records'][0]
        self.assertIsNone(record['reference']['realtime_us']);self.assertIsNone(record['reference']['boot_id'])
        self.assertIn('unfiltered',value['scope']);self.assertEqual('2026-01-01 00:00:01,123',record['reported_local_time'])
        self.assertEqual('Unknown',record['observation']['human_initiator'])
        raw=json.loads(log_reply().stdout);raw['path']='/tmp/arbitrary'
        with self.assertRaises(ValueError):firewall_history.log_tail(json.dumps(raw))

    def test_action_errors_are_reported_without_inventing_an_address_or_current_cause(self):
        value=firewall_history.observation({'message':"Synthetic Failed to execute ban jail 'sshd' action 'example-action' info 'synthetic': command failed"})
        self.assertEqual('sshd',value['jail']);self.assertIsNone(value['address'])
        self.assertIn('association with a particular current ban',value['meaning'])
        found=firewall_history.observation({'message':'Synthetic [sshd] Found 192.0.2.7'})
        self.assertIn('not another distinct authentication failure',found['meaning'])

    def test_file_reader_rejects_nonregular_writable_untrusted_and_hardlinked_files(self):
        for changes in ({'st_uid':1000},{'st_mode':stat.S_IFIFO|0o640},{'st_mode':stat.S_IFREG|0o660},{'st_nlink':2}):
            opened=[];closed=[]
            def opening(*args,**kwargs):opened.append(args);return len(opened)
            def metadata(fd):
                values=dict(st_uid=0,st_mode=(stat.S_IFREG|0o640) if fd==4 else (stat.S_IFDIR|0o775),st_nlink=1,st_size=10,st_mtime_ns=1)
                if fd==4:values.update(changes)
                return SimpleNamespace(**values)
            with patch('faultlens._firewall_log.os.open',side_effect=opening),patch('faultlens._firewall_log.os.fstat',side_effect=metadata),patch('faultlens._firewall_log.os.read') as reading,patch('faultlens._firewall_log.os.close',side_effect=closed.append):
                with self.assertRaises(ValueError):_firewall_log.read()
                reading.assert_not_called();self.assertEqual([4,3,2,1],closed)
        raw=json.loads(log_reply().stdout);raw['content']='tampered'
        with self.assertRaises(ValueError):firewall_history.log_tail(json.dumps(raw))

    def test_time_jail_ban_and_capture_bounds_are_explicit(self):
        with patch('faultlens.firewall_state.MAX_SECONDS',0):
            runner=Runner();data=report(runner);self.assertEqual([],runner.calls)
            self.assertTrue(all(value['command_state']=='time_limit' for value in data['sources'].values()))
        runner=Runner();runner.results[Command.FAIL2BAN_STATUS]=Result('completed','Jail list: one, two\n',0)
        with patch('faultlens.firewall_state.MAX_JAILS',1):self.assertTrue(report(runner)['jail_limit_reached'])
        with patch('faultlens.firewall_state.MAX_BANS',0):self.assertTrue(report()['ban_preview_limit_reached'])
        with self.assertRaises(ValueError):firewall_rules.nft('x'*131073)

    def test_commands_only_inspect_fixed_tools_and_literal_jails(self):
        for command in (Command.NFT_RULESET,Command.IPTABLES_SAVE,Command.IP6TABLES_SAVE,Command.UFW_STATUS,Command.FAIL2BAN_STATUS):
            self.assertFalse(set(CATALOG[command][1])&{'add','delete','flush','reset','ban','unban','enable','disable'})
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/fail2ban-client'),patch('faultlens.commands._capture',return_value=Result('missing')) as capture:
            CommandRunner().read_fail2ban('sshd','status');CommandRunner().read_fail2ban('sshd','maxretry')
            self.assertEqual(['/usr/bin/fail2ban-client','status','sshd'],capture.call_args_list[0].args[0])
            self.assertEqual(['/usr/bin/fail2ban-client','get','sshd','maxretry'],capture.call_args_list[1].args[0])
        with patch('faultlens.commands.trusted_tool') as trusted:
            for jail,query in (('--all','status'),('sshd;id','status'),('sshd','banip'),('sshd','actionban')):
                with self.assertRaises(ValueError):CommandRunner().read_fail2ban(jail,query)
            trusted.assert_not_called()
        with patch('faultlens.commands._capture',return_value=Result('completed','{"reader_state":"file_missing"}',0)):
            self.assertEqual('file_missing',CommandRunner().read_fail2ban_log().state)

    def test_fixed_file_reader_uses_nofollow_nonblocking_regular_root_owned_single_link_file(self):
        opened=[];closed=[];content=b'Synthetic log tail\n'
        def opening(path,flags,**options):opened.append((path,flags,options));return len(opened)
        def metadata(fd):return SimpleNamespace(st_uid=0,st_mode=(stat.S_IFREG|0o640) if fd==4 else (stat.S_IFDIR|0o775),st_nlink=1,st_size=len(content),st_mtime_ns=1)
        with patch('faultlens._firewall_log.os.open',side_effect=opening),patch('faultlens._firewall_log.os.fstat',side_effect=metadata),patch('faultlens._firewall_log.os.lseek'),patch('faultlens._firewall_log.os.read',return_value=content),patch('faultlens._firewall_log.os.close',side_effect=closed.append):
            value=_firewall_log.read();self.assertEqual('/var/log/fail2ban.log',value['path'])
        self.assertEqual([4,3,2,1],closed)
        import os
        self.assertTrue(opened[-1][1]&os.O_NOFOLLOW);self.assertTrue(opened[-1][1]&os.O_NONBLOCK)

    def test_cli_original_evidence_and_readable_output_remain_literal(self):
        for flags in ([],['--details'],['--show-evidence'],['--json']):
            out=io.StringIO();main(['firewall','--since-us',str(START),'--until-us',str(START+86400000000),*flags],runner=Runner(),stdout=out)
            if flags==['--json']:self.assertEqual('firewall',json.loads(out.getvalue())['command'])
            else:self.assertIn('192.0.2.7',out.getvalue());self.assertIn('Unknown',out.getvalue())
