"""Invented port, rule and translation evidence using reserved example addresses."""
import json
from faultlens.commands import Command,Result
from tests.firewall_state_fixtures import Runner as FirewallRunner,nft_snapshot
from tests.network_context_fixtures import reply
from tests.system_resource_fixtures import process_report


class Runner(FirewallRunner):
    def __init__(self,maximum=False):
        super().__init__(maximum)
        for command in (Command.NETWORK_ADDRESSES,Command.NETWORK_ROUTES4,Command.NETWORK_ROUTES6):self.results[command]=reply(command)
        self.results[Command.LISTENERS4]=Result('completed',
            ''.join('tcp LISTEN 0 128 0.0.0.0:'+str(22)+' 0.0.0.0:* users:(("synthetic-worker",pid=42,fd='+str(i+3)+'))\n' for i in range(128)) if maximum else
            'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("synthetic-worker",pid=42,fd=3))\n'
            'tcp LISTEN 0 32 127.0.0.1:5432 0.0.0.0:*\n'
            'udp UNCONN 0 0 192.0.2.1:53 0.0.0.0:* users:(("synthetic-dns",pid=43,fd=4))\n',0)
        self.results[Command.LISTENERS6]=Result('completed','tcp LISTEN 0 128 [::]:22 [::]:*\n',0)
        objects=json.loads(nft_snapshot(256 if maximum else 1))['nftables']
        objects.extend([{'chain':{'family':'inet','table':'example_filter','name':'example_nat','type':'nat','hook':'prerouting','prio':-100,'policy':'accept'}},
            {'chain':{'family':'inet','table':'example_filter','name':'example_forward','type':'filter','hook':'forward','prio':0,'policy':'drop'}},
            {'rule':{'family':'inet','table':'example_filter','chain':'example_nat','handle':900,
                'expr':[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':8080}},
                        {'dnat':{'addr':'192.0.2.10','port':80}}]}}])
        self.results[Command.NFT_RULESET]=Result('completed',json.dumps({'nftables':objects}),0)
    def read_system_resources(self,kind,seconds):
        self.calls.append(('resources',kind,seconds));return Result('completed',json.dumps(process_report()),0)
