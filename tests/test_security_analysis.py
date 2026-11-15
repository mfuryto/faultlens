"""Invented rate histories and log patterns; no actual attacks or host evidence."""
import copy
import io
import json
import unittest

from faultlens.cli import main
from faultlens.incidents import diagnose
from faultlens.security_analysis import assess
from tests.test_incidents import record
from tests.test_firewall import FirewallRunner, TCP, UDP
from tests.test_ssh_analysis import FAILED, ssh_record


def history(counts=(10, 10, 10, 10, 10, 10000), interval=10):
    samples = []
    for i, count in enumerate(counts):
        samples.append({'sample_index': i, 'timestamp_s': 1767225600 + (i+1)*interval,
            'interval_s': interval, 'since_boot': False, 'extended': {'state': 'available',
                'interfaces': [{'interface': 'synthetic0', 'received_bytes': count * 1000,
                                'received_packets': count, 'receive_errors': 0, 'receive_drops': 0}],
                'network_protocols': {'tcp_in_segments': count, 'udp_in_datagrams': count,
                                     'tcp_active_opens': count, 'tcp_passive_opens': count}}})
    return {'state': 'available', 'output_sha256': 'a'*64, 'samples': samples}


def rates(atop):
    data = {'atop': atop}
    assess(data)
    return data['security_analysis']


class SecurityAnalysisTests(unittest.TestCase):
    def test_historical_rate_spike_is_possible_with_traceable_baseline(self):
        result = rates(history())
        self.assertEqual(8, result['historical_comparison']['compared_series_windows'])
        self.assertEqual(6, len(result['findings']))
        value = result['findings'][0]
        self.assertEqual('Possible', value['confidence'])
        self.assertEqual('Unknown', value['cause_confidence'])
        self.assertEqual([0,1,2,3,4], value['evidence'][0]['baseline_sample_indices'])
        self.assertEqual(5, value['evidence'][0]['sample_index'])
        self.assertEqual(1000000, value['evidence'][0]['observed_per_second'])
        self.assertEqual('Unknown', result['attack_assessment'])
        for finding in result['findings']:
            for key in ('observation','evidence','reasoning','thresholds','limitations','recommendations'):
                self.assertTrue(finding[key])

    def test_no_baseline_or_low_or_steady_rates_do_not_infer_attack(self):
        for values in ((10000,), (10000,)*6, (0,0,0,0,0,1), (10,10,10,10,10,50)):
            self.assertEqual([], rates(history(values))['findings'])
        self.assertEqual('insufficient_comparable_history', rates(history((1,)))['historical_comparison']['state'])

    def test_reset_gap_missing_series_and_non_extended_samples_break_baseline(self):
        for kind in ('reset', 'gap', 'missing', 'unsupported'):
            atop = history()
            row = atop['samples'][3]
            if kind == 'reset': row['since_boot'] = True
            if kind == 'gap': row['timestamp_s'] -= 1
            if kind == 'missing': row['extended'] = {'state':'available','interfaces':[], 'network_protocols':{}}
            if kind == 'unsupported': row.pop('extended')
            self.assertEqual([], rates(atop)['findings'], kind)

    def test_missing_interface_does_not_erase_independent_protocol_history(self):
        atop = history()
        atop['samples'][3]['extended']['interfaces'] = []
        values = rates(atop)['findings']
        self.assertEqual(4,len(values))
        self.assertTrue(all(value['evidence'][0]['series'][0]=='protocol' for value in values))

    def test_windows_do_not_join_protocols_destinations_or_boots(self):
        rows = [record(TCP.replace('DPT=22',f'DPT={1000+i}'),monotonic=i,__CURSOR='i='+str(i)) for i in range(9)]
        rows += [record(TCP.replace('DPT=22','DPT=2000').replace('198.51.100.8','198.51.100.9'),monotonic=10,__CURSOR='i=10')]
        result = diagnose(FirewallRunner(rows),search_firewall=True)['security_analysis']
        self.assertEqual([],result['findings'])
        # Unavailable sources are never interpreted even if a caller retains stale findings.
        data = diagnose(FirewallRunner(rows[:9]),search_firewall=True)
        refs = data['firewall_analysis']['findings']
        clone = copy.deepcopy(refs[0])
        clone['evidence'][0]['boot_id'] = 'c'*32
        clone['evidence'][0]['packet']['numeric_fields']['DPT'] = 999
        data['firewall_analysis']['findings'].append(clone)
        assess(data)
        self.assertEqual([],data['security_analysis']['findings'])
        data['firewall_analysis']['state'] = 'unavailable'
        assess(data)
        self.assertEqual('unavailable',data['security_analysis']['state'])

    def test_interval_normalization_prevents_false_spike_from_longer_interval(self):
        atop = history((1000,)*6)
        atop['samples'][-1]['interval_s'] = 100
        atop['samples'][-1]['timestamp_s'] += 90
        for row in atop['samples'][-1]['extended']['interfaces']:
            row['received_packets'] *= 10
            row['received_bytes'] *= 10
        for key in atop['samples'][-1]['extended']['network_protocols']:
            atop['samples'][-1]['extended']['network_protocols'][key] *= 10
        self.assertEqual([], rates(atop)['findings'])

    def test_zero_baseline_still_requires_absolute_floor_and_strict_multiplier(self):
        self.assertEqual([], rates(history((0,0,0,0,0,9), interval=1))['findings'])
        self.assertTrue(rates(history((0,0,0,0,0,100), interval=1))['findings'])
        self.assertEqual([], rates(history((100,100,100,100,100,500), interval=1))['findings'])

    def test_ssh_burst_uses_failures_only_and_inclusive_monotonic_window(self):
        rows = [ssh_record(FAILED, monotonic=i*30_000_000, __CURSOR='i='+str(i)) for i in range(11)]
        data = diagnose(FirewallRunner(ssh=rows), search_ssh=True)
        values = data['security_analysis']['findings']
        self.assertEqual(1, len(values))
        self.assertEqual('security.ssh_failure_burst', values[0]['rule_id'])
        self.assertEqual(11, values[0]['evidence'][0]['report_count'])
        self.assertEqual(11, len(data['ssh_analysis']['records']))
        self.assertIn('192.0.2.7', json.dumps(values))
        self.assertEqual([], diagnose(FirewallRunner(ssh=rows[:9]), search_ssh=True)['security_analysis']['findings'])
        far = [ssh_record(FAILED, monotonic=i*301_000_000, __CURSOR='i='+str(i)) for i in range(11)]
        self.assertEqual([], diagnose(FirewallRunner(ssh=far), search_ssh=True)['security_analysis']['findings'])

    def test_ssh_window_boundary_is_inclusive_without_counting_older_reports(self):
        for final_time, expected in ((300_000_000,1),(300_000_001,0)):
            times = list(range(9)) + [final_time]
            rows = [ssh_record(FAILED,monotonic=t,__CURSOR='i='+str(i)) for i,t in enumerate(times)]
            result = diagnose(FirewallRunner(ssh=rows),search_ssh=True)['security_analysis']
            self.assertEqual(expected,len(result['findings']))

    def test_ssh_success_invalid_users_and_separate_peers_not_combined(self):
        rows = [ssh_record(FAILED.replace('192.0.2.7', f'192.0.2.{i+1}'), monotonic=i, __CURSOR='i='+str(i)) for i in range(10)]
        self.assertEqual([], diagnose(FirewallRunner(ssh=rows), search_ssh=True)['security_analysis']['findings'])
        rows = [ssh_record(FAILED.replace('Failed password for invalid user','Accepted password for'), monotonic=i, __CURSOR='i='+str(i)) for i in range(10)]
        self.assertEqual([], diagnose(FirewallRunner(ssh=rows), search_ssh=True)['security_analysis']['findings'])

    def test_distinct_port_pattern_and_udp_report_burst(self):
        rows = [record(TCP.replace('DPT=22',f'DPT={1000+i}'), monotonic=i, __CURSOR='i='+str(i)) for i in range(10)]
        data = diagnose(FirewallRunner(rows), search_firewall=True)
        self.assertEqual('security.port_scan_indicator',data['security_analysis']['findings'][0]['rule_id'])
        rows = [record(UDP, monotonic=i, __CURSOR='i='+str(i)) for i in range(100)]
        data = diagnose(FirewallRunner(rows), search_firewall=True)
        self.assertEqual(['security.udp_report_burst'], [v['rule_id'] for v in data['security_analysis']['findings']])
        self.assertEqual('Unknown',data['security_analysis']['attack_assessment'])

    def test_scan_uses_maximum_distinct_window_not_busiest_window(self):
        rows = [record(TCP, monotonic=i, __CURSOR='i='+str(i)) for i in range(20)]
        rows += [record(TCP.replace('DPT=22',f'DPT={1000+i}'), monotonic=120_000_000+i, __CURSOR='j='+str(i)) for i in range(10)]
        data = diagnose(FirewallRunner(rows), search_firewall=True)
        self.assertEqual(10,len(data['security_analysis']['findings'][0]['evidence'][0]['destination_ports']))

    def test_sources_are_independent_and_absent_history_is_explicit(self):
        data = {}
        assess(data)
        self.assertEqual('not_requested',data['security_analysis']['state'])
        data = {'ssh_analysis':{'state':'unavailable'}, 'atop':history()}
        assess(data)
        self.assertEqual('partial',data['security_analysis']['state'])
        self.assertTrue(data['security_analysis']['findings'])
        data = {'atop':{'state':'unavailable','samples':history()['samples']}}
        assess(data)
        self.assertEqual([],data['security_analysis']['findings'])

    def test_cap_is_explicit_and_inputs_are_not_modified(self):
        atop = history(tuple([10]*5+[10000]*1)*12)
        # Alternating large changes followed by quiet baselines produce many indicators.
        original = copy.deepcopy(atop)
        result = rates(atop)
        self.assertEqual(32,len(result['findings']))
        self.assertTrue(result['findings_truncated'])
        self.assertGreater(result['matching_indicators'],32)
        self.assertEqual(original,atop)

    def test_integrated_phase3_acceptance_preserves_sources_and_unknown_cause(self):
        from tests.support import SyntheticPhase3Runner
        data = diagnose(SyntheticPhase3Runner(), atop_date='20260101', atop_extended=True,
                        search_ssh=True, search_firewall=True)
        result = data['security_analysis']
        self.assertEqual('available',result['state'])
        self.assertEqual(32,len(result['findings']))
        self.assertTrue(result['findings_truncated'])
        self.assertEqual(500,len(data['ssh_analysis']['records']))
        self.assertEqual(500,len(data['firewall_analysis']['records']))
        self.assertEqual(6,len(data['atop']['samples']))
        self.assertEqual('Unknown',data['root_cause'])
        self.assertEqual('Unknown',result['attack_assessment'])
        self.assertTrue(all(row['confidence']=='Possible' for row in result['findings']))
        self.assertIn('security.historical_traffic_anomaly',[row['rule_id'] for row in result['findings']])

    def test_failed_ordinary_tail_keeps_independently_collected_log_indicators(self):
        from faultlens.commands import Result
        rows = [ssh_record(FAILED,monotonic=i,__CURSOR='i='+str(i)) for i in range(10)]
        runner = FirewallRunner(ssh=rows)
        runner.read_boot = lambda _: Result('unavailable')
        data = diagnose(runner, search_ssh=True)
        self.assertEqual('unavailable',data['state'])
        self.assertEqual(1,len(data['security_analysis']['findings']))

    def test_cli_text_and_json_include_complete_explanations(self):
        rows = [ssh_record(FAILED,monotonic=i,__CURSOR='i='+str(i)) for i in range(10)]
        for args in (['diagnose','--search-ssh'], ['diagnose','--search-ssh','--json']):
            out = io.StringIO()
            self.assertEqual(0,main(args, runner=FirewallRunner(ssh=rows),stdout=out))
            self.assertIn('security.ssh_failure_burst',out.getvalue())
            self.assertIn('minimum_reports',out.getvalue())
