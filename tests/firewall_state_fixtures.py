"""Invented firewall policy and Fail2ban state; never real rules or log files."""
import hashlib
import json
from faultlens.commands import Command,Result
from tests.test_incidents import record

START=1767225600000000


def nft_snapshot(count=1):
    objects=[{'table':{'family':'inet','name':'example_filter'}},
        {'chain':{'family':'inet','table':'example_filter','name':'example_input','type':'filter','hook':'input','prio':0,'policy':'drop'}},
        {'set':{'family':'inet','table':'example_filter','name':'example_bans','type':'ipv4_addr',
                'elem':['192.0.2.7',{'prefix':{'addr':'198.51.100.0','len':24}}]}}]
    for index in range(count):
        objects.append({'rule':{'family':'inet','table':'example_filter','chain':'example_input','handle':index+10,
            'expr':[{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':22}},
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@example_bans'}},
                {'counter':{'packets':5,'bytes':300}},{'reject':{'type':'tcp reset'}}]}})
    return json.dumps({'nftables':objects})


def jail_status(name='sshd',addresses='192.0.2.7'):
    return f'''Status for the jail: {name}
|- Filter
|  |- Currently failed: 2
|  `- Total failed: 10
`- Actions
   |- Currently banned: {len(addresses.split())}
   |- Total banned: 4
   `- Banned IP list: {addresses}
'''


def log_reply(previous=False):
    text='2026-01-01 00:00:01,123 fail2ban.actions [42]: NOTICE [sshd] Ban 192.0.2.7\n'
    return Result('completed',json.dumps({'path':'/var/log/fail2ban.log'+('.1' if previous else ''),'content':text,
        'sha256':hashlib.sha256(text.encode()).hexdigest(),'tail_omitted_prefix':previous,'changed_during_read':False,'bytes_read':len(text)}),0)


class Runner:
    def __init__(self,maximum=False):
        self.calls=[]
        self.results={command:Result('missing') for command in Command}
        self.results.update({Command.NFT_RULESET:Result('completed',nft_snapshot(419 if maximum else 1),0),
            Command.IPTABLES_SAVE:Result('completed','*filter\n:INPUT DROP [0:0]\n:example-ban - [0:0]\n-A INPUT -p tcp --dport 22 -j example-ban\n[2:120] -A example-ban -s 192.0.2.7/32 -j REJECT\nCOMMIT\n',0),
            Command.IP6TABLES_SAVE:Result('completed','*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n',0),
            Command.IPTABLES_VERSION:Result('completed','iptables v1.8.9 (nf_tables)',0),
            Command.IP6TABLES_VERSION:Result('completed','ip6tables v1.8.9 (nf_tables)',0),
            Command.UFW_STATUS:Result('completed','Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n',0),
            Command.FAIL2BAN_STATUS:Result('completed','Status\n`- Jail list: sshd\n',0)})
        self.jail_result=None;self.journal_result=None;self.log_result=None
    def run(self,command):self.calls.append(command);return self.results[command]
    def read_fail2ban(self,jail,query):
        self.calls.append((jail,query))
        return self.jail_result if self.jail_result is not None else Result('completed',jail_status(jail) if query=='status' else
            {'maxretry':'3','findtime':'600','bantime':'3600','actions':'The jail sshd has the following actions:\nexample-action'}[query],0)
    def read_fail2ban_log(self,previous=False):self.calls.append(('file',previous));return self.log_result or log_reply(previous)
    def read_fail2ban_journal(self,*args,**kwargs):
        self.calls.append(('journal',args,kwargs))
        row=record('Synthetic [sshd] Ban 192.0.2.7',realtime=START+1,__CURSOR='s=synthetic',_UID='0',_PID='42',_COMM='fail2ban-server',_TRANSPORT='stdout',_SYSTEMD_UNIT='fail2ban.service')
        return self.journal_result or Result('completed',json.dumps(row),0)
