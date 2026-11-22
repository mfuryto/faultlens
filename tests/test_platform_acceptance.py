"""Invented platform replies validate qualification boundaries without Docker/native reads."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from faultlens.commands import Result
from scripts import platform_acceptance as check


def reply(argv,**limits):
    command=argv[4]
    if '--json' not in argv:return Result('completed','Journal could not be assessed.',0)
    data={'schema_version':1,'command':command,'state':'unavailable' if command in {'history','diagnose','investigate'} else 'available'}
    if command in {'status','health'}:data['observations']=[{'key':'memory.used','value':40}]
    if command=='status':data['login_sessions']={'state':'unavailable','rows':[]}
    if command=='health':data['failed_services']={'state':'unavailable','rows':[]}
    if command=='service':data.update(unit='systemd-journald.service',status={'state':'unavailable'},journal={'state':'unavailable'},journal_records=[],assessment={'code':'unavailable'},invocation_summary={})
    if command=='network':data['sockets']={'state':'unavailable','rows':[]}
    if command=='investigate':data.update(mode='period',current={},boot_filter={'requested':None},
        requested_window={'since_realtime_us':0,'until_realtime_us':1},query_coverage={'tail':{'state':'unavailable'}})
    return Result('completed',json.dumps(data),0)


def native(**options):
    defaults=dict(execute=reply,os_info=lambda:{'ID':'debian','VERSION_ID':'12'},ui_version=lambda:None,python=(3,11,18),architecture='x86_64')
    return check.native('debian-12',**{**defaults,**options})


class PlatformAcceptanceTests(unittest.TestCase):
    def test_absent_optional_sources_are_successful_contracts_not_host_health(self):
        data=native()
        self.assertEqual(7,len(data['checks']))
        self.assertTrue(all(row['contract']=='PASS' for row in data['checks']))
        self.assertEqual('unavailable',data['checks'][-1]['source_state'])
        self.assertEqual('pending',data['operator_acceptance'])
        self.assertIn('not booted-server',data['scope'])
        self.assertNotIn('healthy',json.dumps(data))

    def test_wrong_target_runtime_or_frontend_fails_before_native_collection(self):
        for options in ({'os_info':lambda:{'ID':'ubuntu','VERSION_ID':'24.04'}},
                        {'python':(3,10,0)},{'architecture':'aarch64'},{'ui_version':lambda:'8.2.8'},
                        {'frontend':True,'ui_version':lambda:'unreviewed'}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                native(execute=lambda *a,**k:self.fail('No collection for incompatible setup'),**options)
        data=native(frontend=True,ui_version=lambda:'8.2.8')
        self.assertEqual('reviewed',data['frontend'])

    def test_failed_malformed_or_empty_resource_data_cannot_pass(self):
        for result in (Result('timeout'),Result('completed','',1),Result('completed','not JSON',0),
                       Result('completed','{}',0),Result('completed',json.dumps({'schema_version':1,'command':'status','observations':[]}),0)):
            with self.subTest(result=result),self.assertRaises(ValueError):native(execute=lambda *a,**k:result)

    def test_missing_source_contracts_do_not_pass_as_generic_success(self):
        for command,field in (('status','login_sessions'),('health','failed_services'),('network','sockets'),('diagnose','state'),('investigate','state'),('service','journal'),('service','assessment'),('service','invocation_summary')):
            def execute(argv,**limits):
                result=reply(argv,**limits)
                if argv[4]==command and '--json' in argv:
                    data=json.loads(result.stdout);data.pop(field,None)
                    return Result('completed',json.dumps(data),0)
                return result
            with self.subTest(command=command),self.assertRaises(ValueError):native(execute=execute)

    def test_unavailable_journal_no_match_regression_fails_qualification(self):
        def execute(argv,**limits):
            if '--json' not in argv:return Result('completed','No supported journal pattern matched.',0)
            return reply(argv,**limits)
        with self.assertRaises(ValueError):native(execute=execute)

    def test_native_output_is_a_status_summary_without_original_data(self):
        def execute(argv,**limits):
            self.assertEqual(30,limits['timeout']);self.assertEqual(4194304,limits['limit'])
            result=reply(argv,**limits)
            if '--json' in argv:
                data=json.loads(result.stdout);data['original']='synthetic-host-evidence'
                result=Result('completed',json.dumps(data),0)
            return result
        self.assertNotIn('synthetic-host-evidence',json.dumps(native(execute=execute)))

    def test_container_is_digest_pinned_nonroot_offline_readonly_and_bounded(self):
        argv=check.container_argv('/tmp/synthetic-container-id',uid=1000,gid=1000)
        for value in ('--pull=never','--read-only','no-new-privileges','--rm'):self.assertIn(value,argv)
        for flag,value in (('--network','none'),('--cap-drop','ALL'),('--pids-limit','128'),('--memory','512m'),('--cpus','1'),('--user','1000:1000')):
            self.assertEqual(value,argv[argv.index(flag)+1])
        self.assertIn('@sha256:',check.IMAGE);self.assertIn(check.IMAGE,argv)
        self.assertTrue(all(argv[i+1].endswith(':ro') for i,value in enumerate(argv) if value=='--volume'))
        self.assertNotIn('docker.sock',' '.join(argv));self.assertNotIn('--privileged',argv)
        self.assertIn('--no-index',check.CONTAINER_SCRIPT);self.assertIn('--require-hashes',check.CONTAINER_SCRIPT)
        with self.assertRaises(ValueError):check.container_argv('/tmp/invented',uid=0,gid=0)

    def test_failure_summary_exposes_test_identity_without_assertion_or_subtest_values(self):
        output="""Traceback: synthetic-native-evidence
FAIL: test_example (invented.Example.test_example) (value='synthetic-secret')
AssertionError: synthetic-native-evidence
Ran 2 tests in 1.234s
FAILED (failures=1)
Platform qualification failed: synthetic-native-evidence
"""
        lines=check.failure_summary(output)
        self.assertIn('FAIL: invented.Example.test_example',lines)
        self.assertIn('FAILED (failures=1)',lines)
        self.assertNotIn('synthetic-native-evidence',' '.join(lines))
        self.assertNotIn('synthetic-secret',' '.join(lines))
        self.assertEqual(12,len(check.failure_summary(('OK\n')*100)))

    def test_resource_failure_details_exclude_worker_stderr_and_original_payloads(self):
        from types import SimpleNamespace
        from tests.resource_diagnostics import emit
        value={'commands':{'tui-status':{'within_regression_budget':False,'cpu_max_seconds':1.1,'startup_wall_max_seconds':1.2,'peak_rss_max_mib':60,'original':'synthetic-secret'}}}
        output=io.StringIO()
        with contextlib.redirect_stdout(output):emit(SimpleNamespace(returncode=1,stdout=json.dumps(value),stderr='synthetic-secret'))
        lines=check.failure_summary(output.getvalue())
        self.assertIn('cpu=1.1',' '.join(lines));self.assertNotIn('synthetic-secret',' '.join(lines))
        output=io.StringIO()
        with contextlib.redirect_stdout(output):emit(SimpleNamespace(returncode=1,stdout='',stderr="Command ['python', '--worker', 'tui-health'] failed: synthetic-secret"))
        self.assertEqual(['Resource worker failed: tui-health'],check.failure_summary(output.getvalue()))
        import subprocess
        from tests.resource_diagnostics import capture
        output=io.StringIO()
        with patch('tests.resource_diagnostics.subprocess.run',side_effect=subprocess.TimeoutExpired('synthetic',25,output='synthetic-secret')),contextlib.redirect_stdout(output),self.assertRaises(subprocess.TimeoutExpired):
            capture(['python','-I','/invented/benchmark.py'],timeout=25)
        self.assertEqual(['Resource suite timed out: benchmark after=25'],check.failure_summary(output.getvalue()))

    def test_timeout_cleans_only_the_container_id_created_by_this_invocation(self):
        calls=[]
        def execute(argv,**limits):
            calls.append(argv)
            if argv[1]=='run':
                Path(argv[argv.index('--cidfile')+1]).write_text('a'*64)
                return Result('timeout')
            return Result('completed','',0)
        with tempfile.TemporaryDirectory() as folder,patch.object(check,'WHEELS',Path(folder)),patch.object(check,'_capture',side_effect=execute),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1,check.main(['--target','debian-12','--container']))
        self.assertEqual(['docker','rm','--force','a'*64],calls[-1])
