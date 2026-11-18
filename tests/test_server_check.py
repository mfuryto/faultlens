"""Invented server-check outcomes; never run live collection or recursive suites."""
import argparse
import contextlib
import io
import json
import subprocess
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from faultlens.commands import Result
from faultlens.models import Observation
from faultlens.server_check import REPOSITORY, WORKERS, check_server, exit_code, live_probe, observation_rows, row, source_row, worker_argv
from scripts.server_check import main


def success(argv, **kwargs):
    name=argv[argv.index('--worker')+1]
    return Result('completed','ok' if name in REPOSITORY else json.dumps({'checks':[row(name,'PASS','Adapter responded.')]}),0)


def collect(execute=success, **kwargs):
    return check_server(execute=execute,terminal=lambda:[],uid=1000,owner=1000,**kwargs)


class ServerCheckTests(unittest.TestCase):
    def test_fixed_dispatch_bounds_and_pass_summary(self):
        calls=[]
        def execute(argv,**kwargs):
            calls.append((argv,kwargs))
            return success(argv,**kwargs)
        data=collect(execute)
        self.assertEqual('PASS',data['overall'])
        self.assertEqual(len(WORKERS),data['counts']['PASS'])
        self.assertEqual(0,exit_code(data))
        self.assertEqual(set(WORKERS),{argv[argv.index('--worker')+1] for argv,_ in calls})
        self.assertTrue(all(argv[1:3]==['-I','-B'] and options['limit']==4194304 for argv,options in calls))
        self.assertEqual({60,120},{options['timeout'] for _,options in calls})

    def test_root_owner_mismatch_and_live_only_skip_repository_checks(self):
        for kwargs in ({'uid':0,'owner':1000},{'uid':1001,'owner':1000},{'uid':1000,'owner':1000,'live_only':True}):
            calls=[]
            def execute(argv,**options):
                self.assertNotIn(argv[argv.index('--worker')+1],REPOSITORY)
                calls.append(argv)
                return success(argv,**options)
            data=check_server(execute=execute,terminal=lambda:[],**kwargs)
            self.assertEqual(4,data['counts']['SKIP'])
            self.assertEqual(len(WORKERS)-4,len(calls))

    def test_missing_evidence_and_host_warnings_are_not_program_failures(self):
        observations=[Observation('cpu',10,'percent','proc'),Observation('missing',None,'','source','unavailable'),
                      Observation('disk',96,'percent','source','critical'),Observation('recording',False,'','source','unknown'),
                      Observation('unspecified_config',None,'','source','unknown')]
        values=observation_rows('host',observations)
        self.assertEqual(['PASS','MISSING','WARN','WARN','MISSING'],[v['state'] for v in values])
        def execute(argv,**options):
            return Result('completed',json.dumps({'checks':values}),0)
        data=collect(execute,live_only=True)
        self.assertEqual('ATTENTION',data['overall'])
        self.assertEqual(0,exit_code(data))
        self.assertEqual('MISSING',source_row('journal',{'state':'unavailable','reason':'scope_unavailable'})['state'])
        self.assertEqual('SKIP',source_row('atop',{'state':'not_requested'})['state'])

    def test_failures_do_not_stop_other_probes_and_details_are_opt_in(self):
        def execute(argv,**options):
            name=argv[argv.index('--worker')+1]
            if name=='unit': return Result('completed','invented failure\x1b'+'x'*7000,1)
            if name=='network': return Result('timeout')
            return success(argv,**options)
        data=collect(execute,details=True)
        self.assertEqual('FAIL',data['overall'])
        self.assertEqual(1,exit_code(data))
        self.assertEqual(1,data['counts']['FAIL'])
        self.assertEqual(1,data['counts']['WARN'])
        failure=next(v for v in data['checks'] if v['key']=='repository.unit')
        self.assertEqual(6000,len(failure['details']))
        self.assertTrue(failure['details_truncated'])
        self.assertNotIn('details',collect(execute)['checks'][0])
        self.assertTrue(any(v['key']=='compare' for v in data['checks']))

    def test_exception_and_invalid_worker_output_have_safe_explanations(self):
        def denied(argv,**options): raise PermissionError('private-error-content')
        data=collect(denied)
        self.assertEqual(4,data['counts']['FAIL'])
        self.assertEqual(len(WORKERS)-4,data['counts']['WARN'])
        self.assertNotIn('private-error-content',json.dumps(data))
        for text in ('not json','{}','{"checks":[]}',json.dumps({'checks':[{'state':'PASS'}]})):
            data=collect(lambda *a,**k:Result('completed',text,0),live_only=True)
            self.assertEqual(len(WORKERS)-4,data['counts']['FAIL'])

    def test_missing_development_prerequisites_do_not_masquerade_as_test_bugs(self):
        def without_ui(argv,**options):
            self.assertNotIn(argv[argv.index('--worker')+1],{'unit','benchmark','profiles'})
            return success(argv,**options)
        data=check_server(execute=without_ui,terminal=lambda:[row('tui.textual','MISSING','Not installed.')],uid=1000,owner=1000)
        self.assertEqual(4,data['counts']['MISSING'])
        self.assertEqual(0,data['counts']['FAIL'])
        with patch('faultlens.server_check.shutil.which',return_value=None):
            data=collect()
        self.assertEqual(2,data['counts']['MISSING'])
        self.assertEqual(0,data['counts']['FAIL'])

    def test_argument_validation_precedes_every_probe(self):
        for options in ({'boot':1},{'boot':';id'},{'atop_date':'20260230'}):
            with patch('faultlens.server_check.terminal_rows',side_effect=AssertionError('No probes')):
                with self.assertRaises((ValueError,argparse.ArgumentTypeError)): collect(**options)
        for name in ('shell',';id','--help'):
            with self.assertRaises(ValueError): worker_argv(name)
        argv=worker_argv('diagnose',boot=-1,atop_date='20260101',pstore=True)
        self.assertEqual('20260101',argv[argv.index('--atop-date')+1])
        self.assertIn('--pstore',argv)

    def test_live_status_uses_existing_adapter_without_emitting_measurements(self):
        with patch('faultlens.collectors.status',return_value=[Observation('cpu.busy',12.345,'percent','proc')]), patch('faultlens.sessions.collect',return_value={'state':'available','rows':[{'username':'private-user'}]}):
            data=live_probe('status')
        self.assertEqual('PASS',data[0]['state'])
        self.assertNotIn('12.345',json.dumps(data))
        self.assertNotIn('private-user',json.dumps(data))
        self.assertEqual('sessions.source',data[-1]['key'])
        self.assertIn('status.cpu.busy',json.dumps(data))

    def test_primary_flows_separate_empty_unavailable_and_partial_evidence(self):
        calls=[]
        def investigate(runner, **options):
            calls.append(options)
            return {'state':'partial', 'selection_state':'not_required', 'current':{},
                'query_coverage':{'tail':{'state':'available','records_retained':0,'record_limit_reached':False},
                                  'kernel':{'state':'unavailable','records_retained':0,'record_limit_reached':False}}}
        with patch('faultlens.workflows.collect',side_effect=investigate):
            values=live_probe('investigate',boot=-7,atop_date='20260101',pstore=True)
        self.assertEqual(6,len(calls))
        self.assertEqual({'now','period','before-restart'},{call['mode'] for call in calls})
        for call in calls:
            self.assertNotIn('boot_index',call)
            self.assertNotIn('pstore',call)
            self.assertNotIn('atop_date',call)
            if call['mode']=='period':
                self.assertEqual(900_000_000,call['until_us']-call['since_us'])
            else:
                self.assertNotIn('since_us',call)
        self.assertEqual({'MISSING'},{v['state'] for v in values if v['key'].endswith('.evidence')})
        self.assertEqual({'WARN'},{v['state'] for v in values if v['key'].count('.')==2})
        self.assertTrue(all(v['state']=='MISSING' for v in values if v['key'].endswith('.kernel')))

    def test_previous_boot_resolution_caps_and_current_sources_remain_visible(self):
        def investigate(runner, **options):
            return {'state':'unavailable', 'selection_state':'unavailable',
                'current':{'health':{'failed_services':{'state':'unavailable'}},
                           'network':{'state':'available'}},
                'query_coverage':{'tail':{'state':'available','records_retained':500,'record_limit_reached':True}}}
        with patch('faultlens.workflows.collect',side_effect=investigate):
            values=live_probe('investigate')
        by_key={v['key']:v for v in values}
        self.assertEqual('MISSING',by_key['investigate.visible.before-restart.selection']['state'])
        self.assertEqual('WARN',by_key['investigate.visible.now.tail.limit']['state'])
        self.assertEqual('MISSING',by_key['investigate.system.now.current.failed_services']['state'])
        self.assertEqual('PASS',by_key['investigate.system.now.current.network']['state'])

    def test_live_health_reports_failed_units_as_attention_not_a_software_failure(self):
        source={'state':'available','rows':[{'unit':'example.service'}]}
        with patch('faultlens.collectors.check',return_value=[]),patch('faultlens.preservation.assess',return_value=[]),             patch('faultlens.health.failed_services',return_value=source):
            values=live_probe('health')
        self.assertEqual(['PASS','WARN'],[item['state'] for item in values])
        self.assertNotIn('example.service',json.dumps(values))
        self.assertIn('faultlens health',values[-1]['advice'])

    def test_diagnosis_probes_both_scopes_and_reports_real_signature_coverage(self):
        from tests.support import SyntheticPhase3Runner
        with patch('faultlens.commands.CommandRunner',return_value=SyntheticPhase3Runner()):
            values=live_probe('diagnose',boot=-1,atop_date='20260101')
        self.assertEqual(4,sum(value['key'].endswith('.signatures') for value in values))
        self.assertTrue(all(value['state']=='PASS' for value in values if value['key'].endswith('.signatures')))
        self.assertEqual(2,sum(value['key'].endswith('.traffic_baseline') and value['state']=='PASS' for value in values))
        self.assertTrue(any(value['key']=='pstore' and value['state']=='SKIP' for value in values))

    def test_opt_in_crash_readers_distinguish_empty_and_unavailable_sources(self):
        from tests.support import SyntheticPhase3Runner
        with (patch('faultlens.commands.CommandRunner',return_value=SyntheticPhase3Runner()),
                patch('faultlens.pstore.analyze',return_value={'state':'available','records':[]}) as live,
                patch('faultlens.pstore_archive.analyze',return_value={'state':'unavailable','reason':'access_unavailable'}) as archive):
            values=live_probe('diagnose',boot=-1,pstore=True)
        live.assert_called_once()
        archive.assert_called_once()
        by_key={value['key']:value for value in values}
        self.assertEqual('PASS',by_key['pstore.live']['state'])
        self.assertEqual('MISSING',by_key['pstore.live.records']['state'])
        self.assertEqual('MISSING',by_key['pstore.archive']['state'])

    def test_cli_summary_json_and_terminal_escaping(self):
        data=collect()
        data['checks'][0]['message']='invented\x1b]52;payload\x07\u202e'
        for options in ([],['--json'],['--details']):
            out=io.StringIO()
            with patch('scripts.server_check.check_server',return_value=data),contextlib.redirect_stdout(out):
                self.assertEqual(0,main(options))
            self.assertNotIn('\x1b',out.getvalue())
            self.assertNotIn('\u202e',out.getvalue())
            if '--json' in options:
                self.assertEqual(data,json.loads(out.getvalue()))
            if '--details' in options:
                self.assertIn('Technical details',out.getvalue())
                self.assertIn('\\u001b',out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit): main(['--boot','1'])

    def test_worker_timeout_allows_nested_child_cleanup(self):
        from faultlens.server_check import capture_worker
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'pid'
            code = """import os,signal,subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'],start_new_session=True)
Path(sys.argv[1]).write_text(str(child.pid))
try:
 time.sleep(30)
finally:
 os.killpg(child.pid,signal.SIGKILL)
 child.wait(timeout=1)
"""
            result=capture_worker([sys.executable,'-I','-c',code,str(marker)],timeout=1,limit=4096)
            self.assertEqual('timeout',result.state)
            child=int(marker.read_text())
            try:
                with self.assertRaises(ProcessLookupError): os.kill(child,0)
            finally:
                try: os.killpg(child,9)
                except ProcessLookupError: pass

    def test_repository_worker_dispatch_is_fixed_and_process_local(self):
        from faultlens.server_check import run_worker
        with patch('faultlens.server_check.os.chdir') as change,patch('faultlens.server_check.runpy.run_path') as run,patch('sys.argv',[]),patch('sys.stderr',io.StringIO()):
            run_worker('benchmark')
            change.assert_called_once()
            self.assertTrue(run.call_args.args[0].endswith('/scripts/benchmark.py'))
        with self.assertRaises(ValueError): run_worker('shell')
