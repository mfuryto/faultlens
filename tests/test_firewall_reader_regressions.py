"""Native multicall dispatch and the reported nftables snapshot-size regression."""
import json
import sys
import unittest
from unittest.mock import patch
from faultlens.commands import Command,CommandRunner,Result,CATALOG,_capture
from faultlens import firewall_rules
from faultlens.firewall_state import collect
from faultlens.firewall_presentation import source_detail
from faultlens.ports import collect as ports
from tests.firewall_state_fixtures import Runner,nft_snapshot,START


class FirewallReaderRegressions(unittest.TestCase):
    def test_valid_419_rule_snapshot_above_128_kib_is_retained_in_both_readers(self):
        raw=nft_snapshot(419);self.assertGreater(len(raw.encode()),131072);self.assertLess(len(raw.encode()),196608)
        runner=Runner();runner.results[Command.NFT_RULESET]=Result('completed',raw,0)
        for data in (collect(runner,window='period',since_us=START,until_us=START+1000000),ports(runner)):
            source=data['sources']['nftables'];self.assertEqual('available',source['state']);self.assertEqual(419,len(source['data']['rules']))
            self.assertEqual(json.loads(raw),source['data']['original'])

    def test_excessive_input_reports_actual_limit_without_retaining_partial_policy(self):
        raw='{"nftables":[]}'+(' '*firewall_rules.MAX_NFT_BYTES)
        runner=Runner();runner.results[Command.NFT_RULESET]=Result('completed',raw,0)
        for data in (collect(runner,window='day'),ports(runner)):
            source=data['sources']['nftables'];self.assertEqual('input_limit_exceeded',source['reason']);self.assertIsNone(source['data'])
            self.assertEqual({'unit':'bytes','actual':len(raw),'limit':196608},source['input_limit'])
            self.assertIn('196608',source_detail('nftables',source)['What it means'])
        with self.assertRaises(ValueError):firewall_rules.iptables(' '*131073,'ip')

    def test_all_four_xtables_names_preserve_dispatch_without_executing_a_symlink(self):
        commands=(Command.IPTABLES_SAVE,Command.IP6TABLES_SAVE,Command.IPTABLES_VERSION,Command.IP6TABLES_VERSION)
        for resolved in ('/usr/sbin/xtables-nft-multi','/usr/sbin/xtables-legacy-multi'):
            for command in commands:
                name,args=CATALOG[command]
                with patch('faultlens.commands.trusted_tool',return_value=resolved),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
                    CommandRunner().run(command)
                    capture.assert_called_once_with([resolved,*args],invocation_name=name)
        for name in ('iptables','ip6tables','iptables-save','ip6tables-save'):
            result=_capture(['/bin/sh','-c','printf "%s" "$0"'],invocation_name=name)
            self.assertEqual(0,result.returncode);self.assertEqual(name,result.stdout)
        with patch('faultlens.commands.subprocess.Popen') as spawn:
            for name in ('iptables-restore','iptables -F','../iptables'):
                with self.assertRaises(ValueError):_capture(['/bin/sh'],invocation_name=name)
            spawn.assert_not_called()

    def test_command_errors_remain_bounded_original_administrator_evidence(self):
        result=_capture([sys.executable,'-c','import sys; print("Synthetic error: permission check",file=sys.stderr); raise SystemExit(1)'])
        self.assertEqual('completed',result.state);self.assertEqual(1,result.returncode);self.assertIn('Synthetic error',result.stderr)
        runner=Runner();runner.results[Command.IPTABLES_VERSION]=result
        data=collect(runner);source=data['sources']['iptables4_backend']
        self.assertEqual(result.stderr,source['stderr']);self.assertIn('Synthetic error',str(source_detail('iptables4_backend',source)))
        result=_capture([sys.executable,'-c','import sys; sys.stderr.write("x"*10000)'],limit=100)
        self.assertEqual('output_limit',result.state);self.assertEqual('',result.stderr)

    def test_unrecognized_match_negation_cannot_invert_a_later_source_predicate(self):
        rows=firewall_rules.iptables('*filter\n:INPUT DROP [0:0]\n-A INPUT ! --unsupported-match value -s 192.0.2.7/32 -j ACCEPT\nCOMMIT\n','ip')['rules']
        self.assertEqual(['192.0.2.7/32'],rows[0]['source_networks'])
        self.assertIn('! --unsupported-match',rows[0]['unsupported'])
