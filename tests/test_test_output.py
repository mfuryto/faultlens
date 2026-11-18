"""Invented check summaries; no real server output is used as a fixture."""
import copy
import io
import unittest

from faultlens.server_check import row
from faultlens.test_output import render_server, render_benchmark, render_profiles, render_comparison


def report(rows):
    counts={state:sum(r['state']==state for r in rows) for state in ('PASS','WARN','MISSING','SKIP','FAIL')}
    return {'checks':rows,'counts':counts,'limitations':['Invented source scope.'],
            'overall':'FAIL' if counts['FAIL'] else 'ATTENTION' if counts['MISSING'] or counts['WARN'] else 'PASS'}


def example():
    rows=[row('repository.'+name,'PASS','Completed.') for name in ('unit','policy','benchmark','profiles')]
    rows += [row('status.cpu.busy','PASS','Collected.'),row('network.sockets','PASS','Available.'),
             row('history.visible','PASS','Available.'),row('tui.current_terminal','PASS','Loaded.')]
    rows += [row('health.journal.config.'+key,'MISSING','Source/value unavailable.',
                 'No explicit assignment observed; no compiled default value is assumed.')
             for key in ('storage','system_max_use','system_keep_free','runtime_max_use','runtime_keep_free','max_retention')]
    rows += [row(key,'MISSING','Unavailable.') for key in ('history.system','history.system.previous_boots',
                 'diagnose.system','diagnose.system.ssh_analysis','diagnose.system.firewall_analysis')]
    rows += [row('diagnose.visible.'+source+'.'+field,'MISSING','No classified data.')
             for source in ('ssh_analysis','firewall_analysis') for field in ('coverage','signatures')]
    rows += [row('diagnose.visible.atop','SKIP','Not requested.'),row('diagnose.visible.traffic_baseline','SKIP','No baseline.'),
             row('pstore','SKIP','Not requested.'),row('tui.manual_navigation','SKIP','Manual check needed.')]
    return report(rows)


class TestPresentationTests(unittest.TestCase):
    def test_expected_gaps_are_grouped_without_asserting_server_health_or_denied_access(self):
        data=example()
        original=copy.deepcopy(data)
        out=io.StringIO()
        render_server(data,out)
        text=out.getvalue()
        for heading in ('What worked','What could not be tested or verified','What you may need to do'):
            self.assertIn(heading,text)
        self.assertIn('No check failures were reported.',text)
        self.assertIn('6 journald settings',text)
        self.assertEqual(1,text.count('No explicit values were found'))
        self.assertNotIn('health.journal.config.storage',text)
        self.assertNotIn('Permission denied',text)
        self.assertIn('may be the reason',text)
        self.assertIn('No immediate installation or configuration change',text)
        self.assertIn('Optional:',text)
        self.assertIn('do not prove a healthy or attack-free server',text)
        self.assertEqual(original,data)

    def test_primary_flow_summary_never_turns_unavailable_or_empty_into_no_faults(self):
        data=report([row('investigate.system.now','MISSING','Unavailable.'),
                     row('investigate.visible.period','PASS','Readable.'),
                     row('investigate.visible.period.tail.evidence','MISSING','No records.'),
                     row('sessions.source','PASS','Readable.')])
        out=io.StringIO()
        render_server(data,out)
        text=' '.join(out.getvalue().split())
        self.assertIn('no absence of faults can be established',text)
        self.assertIn('automatic recent 15-minute test window',text)
        self.assertIn('Readable empty queries do not verify incident detection',text)
        self.assertIn('logged-in session source was readable',text)
        self.assertNotIn('System measurements collected',text)

    def test_details_retain_every_original_check_advice_and_failure_excerpt(self):
        data=example()
        data['checks'].append(dict(row('repository.extra','FAIL','Invented failure.','Inspect this check.'),
                                   details='hostile\x1b]52;payload\x07\u202e',details_truncated=False))
        data=report(data['checks'])
        out=io.StringIO()
        render_server(data,out,details=True)
        text=out.getvalue()
        self.assertIn('Technical details',text)
        for item in data['checks']:
            self.assertIn('['+item['state']+'] '+item['key']+': '+item['message'],text)
            if item['advice']: self.assertIn(item['advice'],text)
        self.assertIn('Failure excerpt',text)
        self.assertNotIn('\x1b',text)
        self.assertNotIn('\u202e',text)
        self.assertIn('Some checks failed',text)
        self.assertNotIn('No immediate installation',text)

    def test_actual_warnings_are_visible_and_not_relabelled_as_harmless_gaps(self):
        data=report([row('network.counter_growth','WARN','Error counters increased.'),
                     row('repository.unit','FAIL','Test process exited with an error.')])
        out=io.StringIO()
        render_server(data,out)
        text=out.getvalue()
        self.assertIn('Error counters increased.',text)
        self.assertIn('Test process exited with an error.',text)
        self.assertIn('Review the failed checks with --details',text)
        self.assertNotIn('No immediate installation',text)

    def test_skipped_tests_missing_tools_and_unread_configuration_are_not_claimed_as_passed(self):
        data=report([row('repository.unit','SKIP','Root invocation.'),
                     row('health.dependency.ss','MISSING','Tool unavailable.'),
                     row('health.journal.config','MISSING','Configuration read failed.')])
        out=io.StringIO()
        render_server(data,out)
        text=out.getvalue()
        self.assertNotIn('Automated software tests passed.',text)
        self.assertNotIn('Defaults may apply',text)
        self.assertIn('non-root checkout owner',text)
        self.assertIn('Optional tool ss',text)
        self.assertIn('Configuration read failed.',text)
        self.assertNotIn('No immediate installation',text)

    def test_requested_history_and_empty_crash_evidence_keep_their_uncertainty(self):
        data=report([row('diagnose.visible.atop','PASS','Available.'),
                     row('diagnose.visible.traffic_baseline','MISSING','Insufficient history.'),
                     row('pstore.live','PASS','Available.'),row('pstore.live.records','MISSING','Empty.')])
        out=io.StringIO()
        render_server(data,out)
        self.assertIn('six comparable contiguous',out.getvalue())
        self.assertIn('does not rule out a crash',' '.join(out.getvalue().split()))
        self.assertNotIn('Atop replay was not requested',out.getvalue())

    def test_benchmark_text_distinguishes_passing_and_failing_modes(self):
        data={'commands':{'status':{'peak_rss_max_mib':20,'startup_wall_max_seconds':0.2,
              'cpu_median_seconds':0.1,'within_regression_budget':True},
              'diagnose':{'peak_rss_max_mib':51,'startup_wall_max_seconds':0.3,
              'cpu_median_seconds':0.2,'within_regression_budget':False}}}
        for details in (False,True):
            out=io.StringIO()
            render_benchmark(data,out,details=details)
            self.assertIn('1 outside',out.getvalue())
            self.assertIn('51.00 MiB',out.getvalue())
            self.assertIn('diagnose',out.getvalue())
            if details: self.assertIn('Median CPU',out.getvalue())

    def test_profile_worker_failure_has_no_fabricated_measurements(self):
        data={'profiles':[{'mode':'status','memory_mib':128,'passed':False,'reason':'constrained_worker_failed'}]}
        out=io.StringIO()
        render_profiles(data,out,details=True)
        self.assertIn('1 failed',out.getvalue())
        self.assertIn('n/a',out.getvalue())
        self.assertIn('not a real small-VPS',out.getvalue())

    def test_reference_comparison_uses_plain_names_without_hiding_mismatch(self):
        data={'comparisons':[{'key':'memory.total','state':'pass'}, {'key':'memory.used','state':'mismatch'},
                             {'key':'swap.total','state':'unavailable'}], 'limitations':['Invented tolerances.']}
        out=io.StringIO()
        render_comparison(data,out)
        text=out.getvalue()
        self.assertIn('Total RAM: matched',text)
        self.assertIn('RAM usage: different',text)
        self.assertIn('Total swap: not checked',text)
        self.assertNotIn('memory.total:',text)
        out=io.StringIO()
        render_comparison(data,out,details=True)
        self.assertIn('memory.total: PASS',out.getvalue())
        self.assertIn('Invented tolerances.',out.getvalue())
