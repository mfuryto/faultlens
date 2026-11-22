"""Port evidence never promotes a local observation into verified external access."""
import copy
import io
import json
import unittest
from unittest.mock import patch
from faultlens.commands import Command,CommandRunner,CATALOG,Result
from faultlens.cli import main
from faultlens.ports import collect,listeners,address_kind,binding
from faultlens.port_rules import index,references,port_values
from faultlens.port_presentation import view,table,external_check,render
from tests.port_fixtures import Runner


class PortTests(unittest.TestCase):
    def test_dual_stack_bindings_owners_services_and_policy_references(self):
        data=collect(Runner());self.assertEqual('available',data['state']);self.assertEqual(4,len(data['ports']))
        tcp,loop,udp,v6=data['ports']
        self.assertEqual('wildcard',tcp['binding']['kind']);self.assertEqual('loopback',loop['binding']['kind'])
        self.assertEqual('example-worker.service',tcp['owners'][0]['service'])
        self.assertEqual('private/shared/special-use; upstream mapping unverified',udp['binding']['kind'])
        self.assertIn('V6ONLY',v6['binding']['ipv4_via_ipv6'])
        self.assertTrue(any(r['source']=='nftables' for r in tcp['policy_references']))
        self.assertFalse(any(r['source']=='nftables' for r in udp['policy_references']))
        policy_rows=table('ports_policy',data,{'refs':udp['policy_references'],'family':4})[2]
        self.assertTrue(any('destination port 22' in str(row.detail.get('Direct incoming rule context')) for row in policy_rows))
        self.assertEqual('Unknown',data['external_access']);self.assertEqual('not_performed',data['external_verification']['state'])
        self.assertTrue(all(row['external_access']=='Unknown' for row in data['ports']))

    def test_absent_denied_invalid_and_empty_readers_are_distinct(self):
        runner=Runner()
        for command in runner.results:runner.results[command]=Result('missing')
        data=collect(runner);self.assertEqual('unavailable',data['state']);self.assertIn('could not be assessed',view(data)['Answer'])
        runner.results[Command.LISTENERS4]=Result('completed','',0)
        data=collect(runner);self.assertEqual('partial',data['state']);self.assertIn('0 listener',view(data)['Answer']);self.assertIn('unavailable',view(data)['Answer'])
        runner.results[Command.LISTENERS4]=Result('completed','tcp ESTAB 0 0 192.0.2.1:22 198.51.100.1:1\n',0)
        data=collect(runner);self.assertEqual('unsupported_or_over_limit_output',data['sources']['listeners4']['reason'])
        runner.results[Command.LISTENERS4]=Result('completed','',1)
        data=collect(runner);self.assertEqual('command_unsuccessful',data['sources']['listeners4']['reason'])

    def test_listener_family_state_scope_and_hostile_rows_fail_as_a_whole(self):
        good='tcp LISTEN 0 128 *:22 *:*\n'
        self.assertEqual(6,listeners(good,6)['rows'][0]['family'])
        for raw,family in [(good+'invalid',4),('tcp LISTEN 0 0 [::]:22 [::]:*',4),
            ('udp ESTAB 0 0 192.0.2.1:53 198.51.100.1:53',4),(good*513,4),
            ('tcp LISTEN 0 0 0.0.0.0:0 *:*',4),(good+'\x1b]52;bad',4)]:
            with self.subTest(raw=raw[:50]):
                with self.assertRaises(ValueError):listeners(raw,family)

    def test_addresses_link_flags_zone_and_scope_never_imply_connectivity(self):
        data=collect(Runner());row=copy.deepcopy(data['ports'][3]['socket']);row['local']['address']='fe80::1%net0'
        addresses=[{'ifindex':1,'ifname':'net0','operstate':'DOWN','flags':['UP'],
            'addr_info':[{'family':'inet6','local':'fe80::1','prefixlen':64,'flags':['tentative'],'dadfailed':True}]}]
        value=binding(row,addresses);self.assertEqual('link-local',value['kind']);self.assertTrue(value['addresses'][0]['dadfailed'])
        row['local']['address']='fe80::1%net9';self.assertEqual([],binding(row,addresses)['addresses'])
        self.assertEqual('loopback',address_kind('::1'));self.assertEqual('multicast',address_kind('ff02::1'))
        with patch('ipaddress.IPv4Address.is_global',new_callable=unittest.mock.PropertyMock,return_value=True):
            self.assertIn('reachability unverified',address_kind('192.0.2.1'))

    def test_port_ranges_negation_protocol_and_other_family_selection(self):
        self.assertEqual([(20,23)],port_values({'range':[20,23]}));self.assertIsNone(port_values('@dynamic'))
        runner=Runner();runner.results[Command.IPTABLES_SAVE]=Result('completed','*filter\n:INPUT DROP [0:0]\n'
            '-A INPUT -p udp --dport 22 -j ACCEPT\n-A INPUT -p tcp ! --dport 22 -j DROP\n'
            '-A INPUT -p tcp -m multiport --dports 20:23,80 -s 198.51.100.0/24 -j ACCEPT\nCOMMIT\n',0)
        data=collect(runner);refs=[r for r in data['ports'][0]['policy_references'] if r['source']=='iptables4']
        self.assertEqual([2],[r['rule_index'] for r in refs])
        self.assertFalse(any(r['source']=='iptables4' for r in data['ports'][3]['policy_references']))
        rows=table('ports_policy',data,{'refs':refs,'family':4})[2]
        self.assertIn('source 198.51.100.0/24',str(rows[0].detail));self.assertIn('not a',view(data)['Evidence limits'][3])

    def test_nat_is_retained_without_host_listener_and_never_proves_a_container(self):
        runner=Runner();runner.results[Command.LISTENERS4]=Result('completed','',0);runner.results[Command.LISTENERS6]=Result('completed','',0)
        data=collect(runner);self.assertFalse(data['ports']);self.assertEqual(1,len(data['translations']))
        nat=data['translations'][0];self.assertEqual('192.0.2.10',nat['target_address']);self.assertEqual(80,nat['target_port'])
        self.assertEqual([[(8080,8080)]],[v[0] for v in nat['published_port_predicates']]);self.assertEqual('Unknown',nat['external_access'])
        self.assertIn('namespace',table('ports_translations',data)[2][0].detail['What it means'])
        runner.results[Command.IPTABLES_SAVE]=Result('completed','*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 8443 -j DNAT --to-destination 192.0.2.10:443\nCOMMIT\n',0)
        nat=collect(runner)['translations'];self.assertEqual(2,len(nat));self.assertTrue(any(r['target_port']==443 for r in nat))

    def test_dynamic_translation_and_cyclic_chain_ancestry_stay_unresolved(self):
        runner=Runner();raw=json.loads(runner.results[Command.NFT_RULESET].stdout)
        raw['nftables'][-1]['rule']['expr'][-1]={'dnat':{'addr':{'map':{'key':{'meta':{'key':'mark'}},'data':'@targets'}}}}
        raw['nftables']+=[{'chain':{'family':'inet','table':'example_filter','name':name}} for name in ('a','b')]
        for name,target in (('a','b'),('b','a')):raw['nftables'].append({'rule':{'family':'inet','table':'example_filter','chain':name,'expr':[{'jump':{'target':target}}]}})
        runner.results[Command.NFT_RULESET]=Result('completed',json.dumps(raw),0);data=collect(runner)
        self.assertIsNone(data['translations'][0]['target_address']);self.assertEqual('Unknown',data['external_access'])
        self.assertTrue(any(not r['hooks'] for r in data['ports'][0]['policy_references']))

    def test_forwarding_opens_target_policy_and_observed_target_socket_separately(self):
        runner=Runner();runner.results[Command.LISTENERS4]=Result('completed','tcp LISTEN 0 128 192.0.2.10:80 *:*\n',0)
        raw=json.loads(runner.results[Command.NFT_RULESET].stdout)
        raw['nftables'].append({'rule':{'family':'inet','table':'example_filter','chain':'example_forward','handle':901,
            'expr':[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':80}},{'accept':None}]}})
        runner.results[Command.NFT_RULESET]=Result('completed',json.dumps(raw),0);data=collect(runner);translation=data['translations'][0]
        self.assertEqual([0],translation['target_socket_indices']);self.assertEqual('Unknown',translation['external_access'])
        rows=table('ports_policy',data,{'refs':translation['policy_references']})[2]
        self.assertTrue(any(row.original.get('handle')==901 for row in rows))
        selected=table('ports_listeners',data,{'port_indices':translation['target_socket_indices']})[2]
        self.assertEqual(1,len(selected));self.assertEqual(80,selected[0].original['port'])

    def test_ipv6_translation_and_redirect_preserve_literal_and_unresolved_targets(self):
        runner=Runner();runner.results[Command.IP6TABLES_SAVE]=Result('completed','*nat\n:PREROUTING ACCEPT [0:0]\n'
            '-A PREROUTING -p tcp --dport 8443 -j DNAT --to-destination [2001:db8::10]:443\n'
            '-A PREROUTING -p udp --dport 5353 -j REDIRECT --to-ports 53\nCOMMIT\n',0)
        data=collect(runner);rows=[row for row in data['translations'] if row['source']=='iptables6']
        self.assertEqual('2001:db8::10',rows[0]['target_address']);self.assertEqual(443,rows[0]['target_port'])
        self.assertIsNone(rows[1]['target_address']);self.assertEqual(53,rows[1]['target_port'])
        self.assertEqual('redirect',rows[1]['kind'])

    def test_malformed_metadata_becomes_independent_source_failure(self):
        for value in ({'hook':[]},{'policy':{}},{'prio':[]}):
            runner=Runner();raw=json.loads(runner.results[Command.NFT_RULESET].stdout);raw['nftables'][1]['chain'].update(value)
            runner.results[Command.NFT_RULESET]=Result('completed',json.dumps(raw),0)
            data=collect(runner);self.assertEqual('unavailable',data['sources']['nftables']['state']);self.assertTrue(data['ports'])

    def test_caps_keep_full_source_and_flag_partial_previews(self):
        data=collect(Runner(maximum=True));self.assertEqual(128,len(data['ports']));self.assertTrue(data['port_preview_capped'])
        self.assertEqual(128,len(data['sources']['listeners4']['data']['rows']));self.assertEqual(257,len(data['sources']['nftables']['data']['rules']))
        runner=Runner(maximum=True);runner.results[Command.LISTENERS4]=Result('completed','tcp LISTEN 0 0 0.0.0.0:22 *:*\n',0)
        data=collect(runner);self.assertEqual(32,len(data['ports'][0]['policy_references']));self.assertTrue(data['ports'][0]['policy_preview_capped'])
        data=collect(Runner(),monotonic=iter([0]+[21]*20).__next__);self.assertEqual('unavailable',data['state'])
        self.assertTrue(all(s['command_state']=='time_limit' for s in data['sources'].values()))

    def test_only_fixed_read_only_native_commands_and_no_external_operations(self):
        for command,family in ((Command.LISTENERS4,'-4'),(Command.LISTENERS6,'-6')):
            tool,argv=CATALOG[command];self.assertEqual('ss',tool);self.assertEqual(('-H','-n','-O',family,'-l','-t','-u','-p'),argv)
            with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/ss'),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
                CommandRunner().run(command);self.assertEqual(['/usr/bin/ss',*argv],capture.call_args.args[0])
        runner=Runner();collect(runner);self.assertFalse(any(isinstance(c,tuple) and c[0] in {'file','journal','sshd','sshd-session'} for c in runner.calls))

    def test_cli_originals_controls_and_protocol_specific_external_guidance(self):
        runner=Runner();out=io.StringIO();self.assertEqual(0,main(['ports','--json'],runner=runner,stdout=out))
        data=json.loads(out.getvalue());self.assertEqual('ports',data['command']);self.assertEqual('not_performed',data['external_verification']['state'])
        out=io.StringIO();render(data,out,details=True);self.assertIn('0.0.0.0:22',out.getvalue());self.assertIn('192.0.2.10',out.getvalue())
        self.assertIn('TCP connection',external_check(data['ports'][0])['TCP check']);self.assertIn('silence',external_check(data['ports'][2])['UDP check'])
        for args in (['ports','--window','day'],['ports','--system-journal'],['ports','--boot','0'],['ports','--since-us','1']):
            with contextlib_redirect():
                with self.assertRaises(SystemExit):main(args,runner=runner)


def contextlib_redirect():
    from contextlib import redirect_stderr
    return redirect_stderr(io.StringIO())
