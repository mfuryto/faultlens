"""Synthetic new-flow INPUT decisions, separate from Internet accessibility."""
import copy
import json
import unittest
from faultlens.commands import Command,Result
from faultlens.ports import collect
from faultlens.port_policy import InputPolicy
from tests.port_fixtures import Runner


def match(field,value,protocol='tcp',op='=='):
    return {'match':{'op':op,'left':{'payload':{'protocol':protocol,'field':field}},'right':value}}


def runner(expressions=(),policy='drop',extra=()):
    r=Runner();objects=[{'table':{'family':'inet','name':'example'}},
        {'chain':{'family':'inet','table':'example','name':'input','hook':'input','prio':0,'policy':policy}}]
    for i,expr in enumerate(expressions):objects.append({'rule':{'family':'inet','table':'example','chain':'input','handle':i+1,'expr':expr}})
    objects.extend(extra);r.results[Command.NFT_RULESET]=Result('completed',json.dumps({'nftables':objects}),0)
    r.results[Command.IPTABLES_SAVE]=Result('missing');r.results[Command.IP6TABLES_SAVE]=Result('missing')
    return r


def rule(chain,expr):return {'rule':{'family':'inet','table':'example','chain':chain,'expr':expr}}


class InputPolicyTests(unittest.TestCase):
    def test_rule_order_and_defaults_produce_allowed_and_blocked_ports(self):
        data=collect(runner([[match('dport',22),{'accept':None}]]))
        self.assertEqual(['Allowed','Blocked','Blocked','Allowed'],[p['firewall']['summary'] for p in data['ports']])
        data=collect(runner([[match('dport',22),{'drop':None}],[{'accept':None}]]))
        self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])
        data=collect(runner([[{'accept':None}],[{'unsupported':None}]]))
        self.assertEqual('Allowed',data['ports'][0]['firewall']['summary'])
        self.assertEqual('Unknown',data['external_access'])

    def test_source_prefix_and_set_restrictions_do_not_become_unconditional_open(self):
        data=collect(runner([[match('dport',22),match('saddr','198.51.100.0/24','ip'),{'accept':None}]]))
        p=data['ports'][0];self.assertEqual('Source dependent',p['firewall']['summary'])
        self.assertEqual(['accept','drop'],p['firewall']['backends'][0]['flows'][0]['outcomes'])
        for elements,expected in ((['192.0.2.7'],'Source dependent'),([], 'Blocked'),(['0.0.0.0/0'],'Allowed')):
            obj={'set':{'family':'inet','table':'example','name':'peers','elem':elements}}
            data=collect(runner([[match('saddr','@peers','ip'),{'accept':None}]],extra=[obj]))
            self.assertEqual(expected,data['ports'][0]['firewall']['summary'])

    def test_jump_returns_continue_but_goto_return_ends_the_base_chain(self):
        child={'chain':{'family':'inet','table':'example','name':'child'}}
        for action,expected in (('jump','Allowed'),('goto','Blocked')):
            data=collect(runner([[{action:{'target':'child'}}],[{'accept':None}]],extra=[child,rule('child',[{'return':None}])]))
            self.assertEqual(expected,data['ports'][0]['firewall']['summary'])
        data=collect(runner([[{'jump':{'target':'child'}}]],extra=[child,rule('child',[{'jump':{'target':'child'}}])]))
        self.assertEqual('Unresolved',data['ports'][0]['firewall']['summary'])

    def test_established_accept_rule_does_not_open_a_new_flow(self):
        state={'match':{'op':'==','left':{'ct':{'key':'state'}},'right':{'set':['established','related']}}}
        data=collect(runner([[state,{'accept':None}]]))
        self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])
        state['match']['right']='new';data=collect(runner([[state,{'accept':None}]]))
        self.assertEqual('Allowed',data['ports'][0]['firewall']['summary'])

    def test_numeric_protocol_family_and_conntrack_forms_are_not_misread(self):
        for left,right,expected in (({'meta':{'key':'l4proto'}},{'set':[6,17]},'Allowed'),
            ({'meta':{'key':'nfproto'}},2,'Allowed'),({'ct':{'key':'state'}},8,'Allowed'),
            ({'ct':{'key':'state'}},6,'Blocked'),({'ct':{'key':'state'}},2,'Blocked'),({'ct':{'key':'state'}},'unsupported-state','Unresolved')):
            data=collect(runner([[{'match':{'op':'==','left':left,'right':right}},{'accept':None}]]))
            self.assertEqual(expected,data['ports'][0]['firewall']['summary'])

    def test_unrelated_icmp_reports_do_not_make_tcp_udp_ports_open_or_unresolved(self):
        expr=[{'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':'icmp'}},
            match('type',8,'icmp'),{'accept':None}]
        data=collect(runner([expr,[match('dport',22),{'accept':None}]]))
        self.assertEqual('Allowed',data['ports'][0]['firewall']['summary']);self.assertEqual('Blocked',data['ports'][2]['firewall']['summary'])

    def test_accept_in_one_base_chain_does_not_override_a_later_drop(self):
        later={'chain':{'family':'inet','table':'example','name':'later','hook':'input','prio':10,'policy':'drop'}}
        data=collect(runner([[{'accept':None}]],extra=[later]))
        self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])

    def test_loopback_accept_is_not_mistaken_for_external_wildcard_access(self):
        lo={'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'lo'}}
        r=runner([[lo,{'accept':None}]])
        values=json.loads(r.results[Command.NETWORK_ADDRESSES].stdout)
        values.append({'ifindex':2,'ifname':'lo','operstate':'UNKNOWN','flags':['UP','LOOPBACK'],
            'addr_info':[{'family':'inet','local':'127.0.0.1','prefixlen':8,'scope':'host'}]})
        r.results[Command.NETWORK_ADDRESSES]=Result('completed',json.dumps(values),0)
        data=collect(r);self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])
        self.assertEqual('Allowed',data['ports'][1]['firewall']['summary'])

    def test_known_interface_or_destination_differences_are_visible(self):
        predicate={'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'net0'}}
        r=runner([[predicate,{'accept':None}]]);values=json.loads(r.results[Command.NETWORK_ADDRESSES].stdout)
        values.append({'ifindex':2,'ifname':'net1','operstate':'UP','flags':['UP'],
            'addr_info':[{'family':'inet','local':'198.51.100.1','prefixlen':24,'scope':'global'}]})
        r.results[Command.NETWORK_ADDRESSES]=Result('completed',json.dumps(values),0)
        data=collect(r);p=data['ports'][0]
        self.assertEqual('Interface dependent',p['firewall']['summary'])
        self.assertTrue(all(f['candidate_ingress_interfaces']==['net0','net1'] for f in p['firewall']['backends'][0]['flows']))
        data=collect(runner([[match('daddr','192.0.2.1','ip'),{'accept':None}]]))
        self.assertEqual('Allowed',data['ports'][0]['firewall']['summary'])
        self.assertEqual('Blocked',data['ports'][3]['firewall']['summary'])

    def test_an_address_on_loopback_does_not_prove_external_ingress_uses_loopback(self):
        lo={'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'lo'}}
        r=runner([[lo,{'accept':None}]])
        values=json.loads(r.results[Command.NETWORK_ADDRESSES].stdout)
        values.append({'ifindex':2,'ifname':'lo','operstate':'UNKNOWN','flags':['UP','LOOPBACK'],
            'addr_info':[{'family':'inet','local':'198.51.100.10','prefixlen':32,'scope':'global'}]})
        r.results[Command.NETWORK_ADDRESSES]=Result('completed',json.dumps(values),0)
        data=collect(r);self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])
        flows=data['ports'][0]['firewall']['backends'][0]['flows']
        self.assertTrue(any(f['destination']=='198.51.100.10' for f in flows))
        self.assertTrue(all(f['candidate_ingress_interfaces']==['net0'] for f in flows))

    def test_unsupported_actions_and_rate_conditions_remain_unresolved(self):
        for expr in ([{'vmap':{'key':{'meta':{'key':'mark'}},'data':'@choices'}}],
                     [{'dnat':{'addr':'192.0.2.10','port':80}}],
                     [{'limit':{'rate':3,'per':'minute'}},{'accept':None}]):
            data=collect(runner([expr]));self.assertEqual('Unresolved',data['ports'][0]['firewall']['summary'])
        data=collect(runner([[{'limit':{'rate':3,'per':'minute'}},{'drop':None}]]))
        self.assertEqual('Blocked',data['ports'][0]['firewall']['summary'])

    def test_iptables_protocol_negation_conntrack_and_uppercase_policy(self):
        r=runner();r.results[Command.NFT_RULESET]=Result('missing')
        r.results[Command.IPTABLES_SAVE]=Result('completed','*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A INPUT ! -p tcp -j DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n',0)
        data=collect(r);self.assertEqual('Allowed',data['ports'][0]['firewall']['summary']);self.assertEqual('Blocked',data['ports'][2]['firewall']['summary'])
        r.results[Command.IPTABLES_SAVE]=Result('completed','*filter\n:INPUT DROP [0:0]\n-A INPUT -m tcp --dport 53 -j ACCEPT\nCOMMIT\n',0)
        self.assertEqual('Blocked',collect(r)['ports'][2]['firewall']['summary'])

    def test_missing_sources_empty_views_and_budget_exhaustion_are_distinct(self):
        r=runner();r.results[Command.NFT_RULESET]=Result('missing')
        data=collect(r);self.assertEqual('Unavailable',data['ports'][0]['firewall']['summary'])
        r.results[Command.NFT_RULESET]=Result('completed','{"nftables":[]}',0)
        data=collect(r);self.assertEqual('No INPUT chains',data['ports'][0]['firewall']['summary'])
        data=collect(runner([[{'accept':None}]]));p=data['ports'][0];engine=InputPolicy(data['sources']);engine.remaining=0
        self.assertEqual('Unresolved',engine.evaluate(p)['summary'])

    def test_context_cache_preserves_work_budget_and_complete_original_policy(self):
        data=collect(runner([[match('dport',22),{'accept':None}]]));original=copy.deepcopy(data['sources'])
        engine=InputPolicy(data['sources']);engine.evaluate(data['ports'][0]);remaining=engine.remaining
        engine.evaluate(data['ports'][0]);self.assertEqual(remaining,engine.remaining);self.assertEqual(original,data['sources'])
