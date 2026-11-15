"""Measure fresh-process synthetic CLI cost; never collect live host evidence."""
import argparse
import io
import json
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def worker(command: str) -> dict:
    sys.path.insert(0, str(ROOT))
    from faultlens.cli import main
    from tests.support import SyntheticHistoricalRunner, SyntheticSources, SyntheticStallRunner, SyntheticClockRunner, SyntheticSystemRunner, SyntheticEventRunner, SyntheticReviewRunner, SyntheticOverlayRunner, SyntheticJournalLossRunner, SyntheticOverviewRunner, SyntheticExtendedRunner, SyntheticMaximumExtendedRunner, SyntheticNetworkSources, SyntheticSshRunner, SyntheticFirewallRunner, SyntheticSocketRunner, SyntheticPhase3Runner
    output = io.StringIO()
    started = time.monotonic()
    if command in {'tui-status', 'tui-diagnostic'}:
        from faultlens.tui_model import Session
        from faultlens.tui import draw
        from tests.test_tui import Screen
        session = Session(sources=SyntheticNetworkSources(), runner=SyntheticPhase3Runner(),
            pstore_collector=SyntheticSources().pstore_snapshot,
            pstore_archive_collector=SyntheticSources().pstore_snapshot)
        if command == 'tui-diagnostic':
            session.choose_page(4); session.refresh()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='boot_summaries')
            session.open_row(); session.open_row()
            if session.value['Technical details'] is not session.data['summaries'][0]:
                raise RuntimeError('Boot summary navigation copied or lost the original')
            draw(Screen(),session)
            session.choose_page(5)
            for key in ('search_ssh', 'search_firewall', 'pstore', 'pstore_archive'):
                session.update_setting(key)
            session.update_setting('atop_date','20260101')
            session.update_setting('atop_extended')
        session.refresh()
        if command == 'tui-diagnostic' and (len(session.data['journal_records']) != 500 or
                len(session.data['security_analysis']['findings']) != 32):
            raise RuntimeError('Synthetic TUI evidence collection failed')
        draw(Screen(),session)
        if command=='tui-diagnostic':
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='crash_source')
            session.open_row()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='crash_records')
            session.open_row(); session.open_row()
            if session.value['Technical details'] is not session.data['pstore']['records'][0]:
                raise RuntimeError('Crash interpretation copied or lost the fragment')
            draw(Screen(),session)
            session.choose_page(5)
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='recording')
            session.open_row()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='recording_samples')
            session.open_row(); session.open_row()
            if session.value['Technical details'] is not session.data['atop']['samples'][0]:
                raise RuntimeError('Recording interpretation copied or lost the sample')
            draw(Screen(),session)
            session.choose_page(5)
            session.selected=next(i for i,row in enumerate(session.rows()) if row.value is session.data['ssh_analysis'])
            session.open_row()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='timeline')
            session.open_row(); session.open_row()
            if session.value['Technical details'] is not session.data['ssh_analysis']['findings'][0]:
                raise RuntimeError('Timeline navigation changed the finding source')
            draw(Screen(),session)
            session.choose_page(5)
            session.selected=next(i for i,row in enumerate(session.rows()) if row.value is session.data['security_analysis'])
            session.open_row()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='findings')
            session.open_row(); session.open_row()
            session.selected=next(i for i,row in enumerate(session.rows()) if row.label=='Referenced source evidence')
            session.open_row()
            if not any(ref['Retained source evidence'] for ref in session.value['References']):
                raise RuntimeError('Synthetic finding references did not resolve')
            draw(Screen(),session)
        session.choose_page(6)
        session.selected = 1
        session.open_row()
        if session.value is not session.data:
            raise RuntimeError('Evidence navigation copied or lost the report')
        for size in ((24,100),(10,40)):
            draw(Screen(size=size), session)
        session.find('collected_at')
        session.open_row()
        session.find('2026',width=38)
        session.find(width=38)
        draw(Screen(size=(10,40)),session)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return {'collection_wall_seconds': time.monotonic()-started,
                'cpu_seconds': usage.ru_utime+usage.ru_stime, 'peak_rss_mib': usage.ru_maxrss/1024}
    arguments = ['diagnose', '--atop-date', '20260101', '--json'] if command == 'diagnose-atop' else [command, '--json']
    if command in {'diagnose-stalls', 'diagnose-clock', 'diagnose-overlay', 'diagnose-journal-loss'}:
        arguments = ['diagnose', '--json']
    if command in {'diagnose-events', 'diagnose-review', 'diagnose-integrated'}:
        arguments = ['diagnose', '--system-journal', '--search-events', '--json']
    if command == 'phase3-security':
        arguments = ['diagnose', '--search-ssh', '--search-firewall', '--atop-date', '20260101', '--atop-extended', '--json']
    if command == 'diagnose-firewall':
        arguments = ['diagnose', '--system-journal', '--search-events', '--search-ssh', '--search-firewall', '--show-evidence', '--json']
    if command == 'diagnose-ssh':
        arguments = ['diagnose', '--system-journal', '--search-events', '--search-ssh', '--show-evidence', '--json']
    if command == 'diagnose-extended':
        arguments = ['diagnose', '--atop-date', '20260101', '--atop-extended', '--json']
    if command == 'diagnose-integrated':
        arguments.extend(['--boot-id', 'a' * 32, '--since-us', '1767225600000000',
                          '--until-us', '1767225600000500', '--atop-date', '20260101',
                          '--atop-extended', '--pstore', '--pstore-archive'])
    if command == 'incidents':
        arguments = ['incidents', '--boot-count', '7', '--json']
    if command == 'diagnose-system':
        arguments = ['diagnose', '--system-journal', '--boot-id', 'a' * 32, '--since-us', '1767225600000000', '--until-us', '1767225600000500', '--json']
    if command == 'check-history':
        arguments = ['check', '--history', '--json']
    if command == 'diagnose-pstore-archive':
        arguments = ['diagnose', '--pstore-archive', '--json']
    if command == 'diagnose-pstore':
        arguments = ['diagnose', '--pstore', '--json']
    runner = (SyntheticFirewallRunner() if command == 'diagnose-firewall' else
              SyntheticSshRunner() if command == 'diagnose-ssh' else
              SyntheticMaximumExtendedRunner() if command == 'diagnose-extended' else
              SyntheticExtendedRunner() if command == 'diagnose-integrated' else
              SyntheticOverviewRunner() if command == 'incidents' else
              SyntheticJournalLossRunner() if command == 'diagnose-journal-loss' else
              SyntheticOverlayRunner() if command == 'diagnose-overlay' else
              SyntheticReviewRunner() if command == 'diagnose-review' else
              SyntheticEventRunner() if command in {'diagnose-events', 'diagnose-integrated'} else
              SyntheticSystemRunner() if command == 'diagnose-system' else
              SyntheticClockRunner() if command == 'diagnose-clock' else
              SyntheticStallRunner() if command == 'diagnose-stalls' else SyntheticHistoricalRunner())
    if command == 'phase3-security':
        runner = SyntheticPhase3Runner()
    if command in {'network', 'security', 'network-sockets'}:
        arguments.extend(['--sample-seconds', '0.05'])
    if command == 'network-sockets':
        arguments = ['network', '--sockets', '--sample-seconds', '0.05', '--json']
        runner = SyntheticSocketRunner()
    sources = SyntheticNetworkSources() if command in {'network', 'security', 'network-sockets'} else SyntheticSources()
    code = main(arguments, sources=sources, runner=runner, stdout=output,
                pstore_collector=SyntheticSources().pstore_snapshot,
                pstore_archive_collector=SyntheticSources().pstore_snapshot)
    payload = json.loads(output.getvalue())
    if code != 0 or payload.get('state') == 'unavailable' or not (payload.get('observations') or payload.get('boots')):
        raise RuntimeError('Synthetic collection failed')
    if command in {'network', 'security', 'network-sockets'}:
        if (len(payload['observations'][0]['value']) != 128 or len(payload['findings']) != 3
                or payload['attack_assessment'] != 'Unknown'):
            raise RuntimeError('Synthetic network/security sampling failed')
    if command == 'phase3-security':
        analysis = payload['security_analysis']
        if analysis['state'] != 'available' or len(analysis['findings']) != 32 or not analysis['findings_truncated']:
            raise RuntimeError('Integrated security analysis failed')
    if command == 'network-sockets' and len(payload['sockets']['rows']) != 512:
        raise RuntimeError('Synthetic socket snapshot failed')
    if command=='network-sockets':
        from faultlens.presentation import render
        from faultlens.tui_model import Session
        from faultlens.tui import draw
        from tests.test_tui import Screen
        render(payload,io.StringIO())
        session=Session(); session.data=payload; session.choose_page(2)
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='observation' and row.value['key']=='network.interfaces')
        session.open_row()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='interface_samples')
        session.open_row(); session.open_row(); draw(Screen(),session)
        session.choose_page(2)
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='socket_snapshot')
        session.open_row()
        session.selected=next(i for i,row in enumerate(session.rows()) if row.action=='socket_rows')
        session.open_row(); session.open_row()
        if session.value['Technical details'] is not payload['sockets']['rows'][0]:
            raise RuntimeError('Socket explanation copied or lost the original row')
        draw(Screen(),session)
    if command=='diagnose-atop':
        from faultlens.presentation import render
        render(payload,io.StringIO())
    if command in {'diagnose-pstore', 'diagnose-pstore-archive'}:
        key = 'pstore_archive' if command == 'diagnose-pstore-archive' else 'pstore'
        if (payload[key]['state'] != 'available' or len(payload[key]['records']) != 8
                or payload[key]['records'][0]['relative_path'] != 'dmesg-ramoops-0'
                or not payload[key]['records'][0]['content']['value']):
            raise RuntimeError('Synthetic pstore analysis failed')
    if command == 'incidents':
        if (len(payload['summaries']) != 7 or any(
                value['finding_count'] != 500 or not value['record_limit_reached']
                for value in payload['summaries'])):
            raise RuntimeError('Synthetic multi-boot overview failed')
    if command == 'diagnose-stalls':
        if len(payload['findings']) != 500 or {item['rule_id'] for item in payload['findings']} != {
                'kernel.soft_lockup', 'kernel.hard_lockup', 'kernel.hung_task'}:
            raise RuntimeError('Synthetic stall analysis failed')
    if command == 'diagnose-integrated':
        if (any(payload[key]['state'] != 'available' for key in ('atop', 'pstore', 'pstore_archive', 'event_search'))
                or payload['root_cause'] != 'Unknown' or len(payload['findings']) != 500
                or payload['atop']['samples'][0]['extended']['state'] != 'available'):
            raise RuntimeError('Synthetic integrated historical diagnosis failed')
    if command == 'diagnose-firewall':
        value = payload['firewall_analysis']
        if (len(value['findings']) != 500 or len(value['records']) != 500
                or not value['record_limit_reached'] or value['packet_verdict'] != 'Unknown'
                or len(payload['ssh_analysis']['records']) != 500):
            raise RuntimeError('Synthetic firewall/admin evidence failed')
    if command == 'diagnose-ssh':
        ssh = payload['ssh_analysis']
        if (len(ssh['records']) != 500 or len(ssh['findings']) != 500
                or not ssh['record_limit_reached'] or ssh['attack_assessment'] != 'Unknown'
                or len(payload['journal_records']) != 500
                or any(len(value['records']) != 500 for value in payload['event_search']['queries'])):
            raise RuntimeError('Synthetic SSH/admin evidence views failed')
    if command == 'diagnose-extended':
        value = payload['atop']['samples'][0]['extended']
        if (len(value['disks']) != 32 or len(value['interfaces']) != 32
                or value['processes']['reported_processes'] != 256
                or len(value['process_details']) != 256
                or not payload['atop']['samples'][0]['source_records']
                or value['disks'][0]['device'] != 'disk0'
                or value['process_details'][0]['pid'] != 1):
            raise RuntimeError('Synthetic maximum extended resources failed')
    if command == 'diagnose-atop':
        values = payload['atop']['samples']
        if (len(values) != 256 or any(
                [value[key] for key in ('cpu_execution_percent', 'cpu_idle_percent',
                                        'cpu_iowait_percent', 'cpu_steal_percent')]
                != [20, 80, 0, 0] for value in values)):
            raise RuntimeError('Synthetic historical CPU accounting failed')
    if command == 'diagnose-clock':
        clock = payload['reconstruction']['clock_mapping']
        if (len(payload['findings']) != 500 or clock['significant_adjacent_change_count'] != 499
                or len(clock['change_examples']) != 16 or not clock['change_examples_truncated']):
            raise RuntimeError('Synthetic clock reconstruction failed')
    if command == 'diagnose-system':
        scope = payload['journal_scope']
        if scope['requested'] != 'system' or scope['kernel_records_examined'] != 500 or scope['completeness'] != 'unknown' or payload['boot_selection']['method'] != 'id' or payload['journal_window']['until_realtime_us'] != 1767225600000500 or payload['journal_window']['since_realtime_us'] != 1767225600000000:
            raise RuntimeError('Synthetic system journal scope failed')
    if command == 'diagnose-events':
        queries = payload['event_search']['queries']
        if (payload['event_search']['state'] != 'available' or len(payload['findings']) != 500
                or any(query['candidates_examined'] != 500 or len(query['findings']) != 500
                       or not query['record_limit_reached'] for query in queries)):
            raise RuntimeError('Synthetic targeted event search failed')
    if command == 'diagnose-review':
        review = payload['event_search']['queries'][0]['candidate_review']
        if (review['retained_candidates'] != 500 or review['unclassified_candidates'] != 500
                or len(review['unclassified_examples']) != 20 or not review['unclassified_examples_truncated']):
            raise RuntimeError('Synthetic unclassified candidate review failed')
    if command == 'diagnose-journal-loss':
        if (len(payload['findings']) != 500 or not payload['record_limit_reached']
                or {item['rule_id'] for item in payload['findings']} != {
                    'journal.messages_suppressed', 'journal.kernel_messages_missed'}):
            raise RuntimeError('Synthetic journal-driver loss analysis failed')
    if command == 'diagnose-overlay':
        if len(payload['findings']) != 500 or any(item['rule_id'] != 'kernel.overlay_layer_reuse' for item in payload['findings']):
            raise RuntimeError('Synthetic OverlayFS analysis failed')
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {'collection_wall_seconds': time.monotonic() - started,
            'cpu_seconds': usage.ru_utime + usage.ru_stime,
            'peak_rss_mib': usage.ru_maxrss / 1024}


def positive_iterations(value):
    parsed = int(value)
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError('Iterations must be from 1 to 100.')
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Emit all measurements as JSON for automation.')
    parser.add_argument('--details', action='store_true', help='Show the per-mode measurement table.')
    parser.add_argument('--iterations', type=positive_iterations, default=10)
    parser.add_argument('--worker', choices=('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss', 'incidents', 'diagnose-integrated', 'diagnose-extended', 'network', 'security', 'diagnose-ssh', 'diagnose-firewall', 'network-sockets', 'phase3-security', 'tui-status', 'tui-diagnostic'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux is required for RSS units and the application.')
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    summary = {'synthetic': True, 'python': sys.version.split()[0], 'iterations': args.iterations, 'commands': {}}
    passed = True
    for command in ('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss', 'incidents', 'diagnose-integrated', 'diagnose-extended', 'network', 'security', 'diagnose-ssh', 'diagnose-firewall', 'network-sockets', 'phase3-security', 'tui-status', 'tui-diagnostic'):
        samples, wall = [], []
        for _ in range(args.iterations):
            started = time.monotonic()
            result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--worker', command],
                                    check=True, capture_output=True, text=True, timeout=10)
            wall.append(time.monotonic() - started)
            samples.append(json.loads(result.stdout))
        values = {'startup_wall_median_seconds': round(statistics.median(wall), 4),
                  'startup_wall_max_seconds': round(max(wall), 4),
                  'cpu_median_seconds': round(statistics.median(s['cpu_seconds'] for s in samples), 4),
                  'peak_rss_max_mib': round(max(s['peak_rss_mib'] for s in samples), 2)}
        # Tolerant regression limits, not promised production performance.
        values['within_regression_budget'] = (values['peak_rss_max_mib'] < 50
                                              and max(s['cpu_seconds'] for s in samples) < 1
                                              and max(wall) < 2)
        passed = passed and values['within_regression_budget']
        summary['commands'][command] = values
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        sys.path.insert(0,str(ROOT))
        from faultlens.test_output import render_benchmark
        render_benchmark(summary,sys.stdout,details=args.details)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
