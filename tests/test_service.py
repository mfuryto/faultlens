"""Invented service properties/messages; no server logs or native service control."""
import copy
import io
import json
import unittest
from unittest.mock import patch

from faultlens.commands import CommandRunner,Result,SERVICE_PROPERTIES,validate_service_unit
from faultlens import service
from faultlens.cli import main


PARSER_ERROR="AppArmor parser error for /etc/apparmor.d in profile /etc/apparmor.d/usr.sbin.example-database at line 17: Could not open 'local/usr.sbin.example-database'"
SCRIPT_ERROR='/lib/apparmor/apparmor.systemd: 148: [: Illegal number: yes'


def journal_record(message,index=0,unit='apparmor.service'):
    return {'_BOOT_ID':'b'*32,'__REALTIME_TIMESTAMP':str(1767225600000000+index),
            '__MONOTONIC_TIMESTAMP':str(1000000+index),'__CURSOR':'s=synthetic;i='+str(index),
            '_SYSTEMD_UNIT':unit,'_COMM':'apparmor.systemd','_PID':'123','_UID':'0',
            '_TRANSPORT':'stdout','PRIORITY':'3','MESSAGE':message}


class ServiceRunner:
    def __init__(self,messages=None):
        self.messages=[PARSER_ERROR,SCRIPT_ERROR,'Error: At least one profile failed to load'] if messages is None else messages
        self.calls=[];self.status_result=None;self.journal_result=None

    def read_service_properties(self,unit):
        self.calls.append(('status',unit))
        if self.status_result is not None:return self.status_result
        values=dict.fromkeys(SERVICE_PROPERTIES,'')
        values.update(Id=unit,Description='Synthetic loader description',LoadState='loaded',ActiveState='failed',
            SubState='failed',Result='exit-code',ExecMainCode='1',ExecMainStatus='1',
            StateChangeTimestamp='Thu 2026-01-01 00:00:00 UTC',InvocationID='c'*32)
        return Result('completed','\n'.join(key+'='+value for key,value in values.items())+'\n',0)

    def read_service_journal(self,unit):
        self.calls.append(('journal',unit))
        if self.journal_result is not None:return self.journal_result
        return Result('completed','\n'.join(json.dumps(journal_record(message,index,unit)) for index,message in enumerate(self.messages)),0)


def service_report(unit='apparmor.service'):
    return service.collect(unit,ServiceRunner())


class ServiceTests(unittest.TestCase):
    def test_literal_names_and_native_arguments_fail_before_execution(self):
        bad=('',None,'--all.service','../a.service','a*.service','a?.service','a[bc].service',
             'a.service;id','a.service\n','a.service\x1b','a/b.service','a.socket','a'*250+'.service')
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/unused') as trusted,patch('faultlens.commands._capture') as capture:
            for value in bad:
                for method in (CommandRunner().read_service_properties,CommandRunner().read_service_journal):
                    with self.subTest(value=value),self.assertRaises(ValueError):method(value)
            trusted.assert_not_called();capture.assert_not_called()
        for value in ('apparmor.service','worker@one.service','escaped\\x20name.service'):
            self.assertEqual(value,validate_service_unit(value))
        with patch('faultlens.commands.trusted_tool',side_effect=lambda name:'/usr/bin/'+name),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().read_service_properties('apparmor.service')
            CommandRunner().read_service_journal('apparmor.service')
        status,logs=[call.args[0] for call in capture.call_args_list]
        self.assertIn('show',status);self.assertEqual(['--','apparmor.service'],status[-2:])
        for value in ('--system','--boot=0','--unit=apparmor.service','--lines=201','--output=json'):self.assertIn(value,logs)
        self.assertTrue(all(call.kwargs['utc'] for call in capture.call_args_list))
        self.assertFalse(any(value in {'restart','reset-failed','reload','sudo'} for value in status+logs))

    def test_apparmor_errors_explain_the_message_and_retain_original_evidence(self):
        runner=ServiceRunner();data=service.collect('apparmor.service',runner)
        self.assertEqual([('status','apparmor.service'),('journal','apparmor.service')],runner.calls)
        self.assertEqual('available',data['state']);self.assertEqual('Unknown',data['root_cause'])
        self.assertEqual(2,len(data['explanations']))
        parser,script=data['explanations']
        self.assertIn('could not open',parser['title']);self.assertIn('line 17',parser['meaning'])
        self.assertIn('missing file from access',parser['meaning']);self.assertIn('Do not create an empty',parser['next_step'])
        self.assertIn('nonnumeric input',script['meaning']);self.assertIn('not established',script['meaning'])
        for explanation in data['explanations']:
            record=data['journal_records'][explanation['record_index']]
            self.assertEqual(record['reference'],explanation['reference'])
        before=copy.deepcopy(data);detail=service.view(data)
        self.assertIn('not an error message',str(detail));self.assertIn('No restart',str(detail))
        self.assertEqual(before,data)
        output=io.StringIO();service.render(data,output)
        self.assertIn(PARSER_ERROR,' '.join(output.getvalue().split()));self.assertIn(SCRIPT_ERROR,' '.join(output.getvalue().split()))
        self.assertIn('Error: At least one profile failed to load',' '.join(output.getvalue().split()))

    def test_kernel_truncated_loader_comm_and_parser_comm_are_supported(self):
        for comm in ('apparmor.system','apparmor_parser'):
            row=journal_record(PARSER_ERROR);row['_COMM']=comm
            runner=ServiceRunner();runner.journal_result=Result('completed',json.dumps(row),0)
            data=service.collect('apparmor.service',runner)
            self.assertEqual(1,len(data['explanations']))
            self.assertEqual(PARSER_ERROR,data['journal_records'][0]['message'])

    def test_unavailable_empty_and_independent_sources_are_never_an_all_clear(self):
        for result in (Result('missing'),Result('timeout'),Result('output_limit'),Result('completed','',1),Result('completed','bad json',0)):
            runner=ServiceRunner();runner.journal_result=result
            data=service.collect('apparmor.service',runner)
            self.assertEqual('partial',data['state']);self.assertEqual([],data['journal_records'])
            self.assertIn('logs unavailable',service.view(data)['Journal coverage'])
        runner=ServiceRunner([]);data=service.collect('apparmor.service',runner)
        self.assertEqual('available',data['journal']['state']);self.assertIn('does not rule out a failure',service.view(data)['Journal coverage'])
        runner=ServiceRunner();runner.status_result=Result('unavailable')
        data=service.collect('apparmor.service',runner)
        self.assertEqual('partial',data['state']);self.assertEqual(2,len(data['explanations']))
        runner.journal_result=Result('timeout');self.assertEqual('unavailable',service.collect('apparmor.service',runner)['state'])

    def test_journal_scope_identity_duplicate_fields_and_limits_fail_closed(self):
        for mutation in (lambda row:row.update(_SYSTEMD_UNIT='other.service'),lambda row:row.update(_BOOT_ID='wrong'),
                         lambda row:row.update(__CURSOR='bad cursor'),lambda row:row.update(PRIORITY='99')):
            row=journal_record('Synthetic message');mutation(row)
            with self.assertRaises(ValueError):service.records(json.dumps(row),'apparmor.service')
        row=journal_record('Synthetic manager message');row.pop('_SYSTEMD_UNIT');row.update(UNIT='apparmor.service',_PID='1',_COMM='systemd')
        parsed,limited,_=service.records(json.dumps(row),'apparmor.service');self.assertEqual(1,len(parsed));self.assertFalse(limited)
        for raw in ('{"MESSAGE":"a","MESSAGE":"b"}', 'x'*262145):
            with self.assertRaises(ValueError):service.records(raw,'apparmor.service')
        raw='\n'.join(json.dumps(journal_record('Synthetic message',i)) for i in range(201))
        parsed,limited,_=service.records(raw,'apparmor.service');self.assertEqual(200,len(parsed));self.assertTrue(limited)
        self.assertEqual('s=synthetic;i=1',parsed[0]['reference']['cursor'])
        with self.assertRaises(ValueError):service.records(raw+'\n'+json.dumps(journal_record('Synthetic message',201)),'apparmor.service')
        first=journal_record('Synthetic first');second=journal_record('Synthetic second',1);second['_BOOT_ID']='d'*32
        with self.assertRaises(ValueError):service.records(json.dumps(first)+'\n'+json.dumps(second),'apparmor.service')

    def test_property_identity_and_incomplete_or_duplicate_output_are_rejected(self):
        text=ServiceRunner().read_service_properties('apparmor.service').stdout
        for raw in (text.replace('Id=apparmor.service','Id=other.service'),text+'Id=apparmor.service\n',text.replace('Result=exit-code\n',''),text.replace('ExecMainStatus=1','ExecMainStatus=bad')):
            with self.assertRaises(ValueError):service.properties(raw,'apparmor.service')

    def test_unknown_messages_and_terminal_controls_remain_literal(self):
        original='[bold]Synthetic unknown failure[/]\x1b]52;c;synthetic\x07\u202e'
        data=service.collect('example.service',ServiceRunner([original]))
        self.assertEqual([],data['explanations']);self.assertEqual(original,data['journal_records'][0]['message'])
        output=io.StringIO();service.render(data,output)
        self.assertNotIn('\x1b',output.getvalue());self.assertNotIn('\u202e',output.getvalue())
        self.assertIn('[bold]',output.getvalue());self.assertIn('not a no-error result',output.getvalue())
        data=service.collect('example.service',ServiceRunner([PARSER_ERROR]))
        self.assertEqual([],data['explanations'])

    def test_cli_readable_details_json_and_required_unit(self):
        for flags in ([],['--details'],['--json'],['--show-evidence']):
            output=io.StringIO();self.assertEqual(0,main(['service','--unit','apparmor.service',*flags],runner=ServiceRunner(),stdout=output))
            if flags==['--json']:
                data=json.loads(output.getvalue());self.assertEqual('service',data['command']);self.assertEqual('apparmor.service',data['unit'])
            else:self.assertIn('could not open',output.getvalue());self.assertIn(PARSER_ERROR,' '.join(output.getvalue().split()))
        for args in (['service'],['health','--unit','apparmor.service'],['service','--unit','--all.service']):
            with self.assertRaises(SystemExit):main(args,runner=ServiceRunner(),stderr=io.StringIO())
