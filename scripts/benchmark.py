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
    from tests.support import SyntheticHistoricalRunner, SyntheticSources, SyntheticStallRunner, SyntheticClockRunner, SyntheticSystemRunner, SyntheticEventRunner, SyntheticReviewRunner, SyntheticOverlayRunner, SyntheticJournalLossRunner
    output = io.StringIO()
    started = time.monotonic()
    arguments = ['diagnose', '--atop-date', '20260101', '--json'] if command == 'diagnose-atop' else [command, '--json']
    if command in {'diagnose-stalls', 'diagnose-clock', 'diagnose-overlay', 'diagnose-journal-loss'}:
        arguments = ['diagnose', '--json']
    if command in {'diagnose-events', 'diagnose-review'}:
        arguments = ['diagnose', '--system-journal', '--search-events', '--json']
    if command == 'diagnose-system':
        arguments = ['diagnose', '--system-journal', '--boot-id', 'a' * 32, '--since-us', '1767225600000000', '--until-us', '1767225600000500', '--json']
    if command == 'check-history':
        arguments = ['check', '--history', '--json']
    if command == 'diagnose-pstore-archive':
        arguments = ['diagnose', '--pstore-archive', '--json']
    if command == 'diagnose-pstore':
        arguments = ['diagnose', '--pstore', '--json']
    runner = (SyntheticJournalLossRunner() if command == 'diagnose-journal-loss' else
              SyntheticOverlayRunner() if command == 'diagnose-overlay' else
              SyntheticReviewRunner() if command == 'diagnose-review' else
              SyntheticEventRunner() if command == 'diagnose-events' else
              SyntheticSystemRunner() if command == 'diagnose-system' else
              SyntheticClockRunner() if command == 'diagnose-clock' else
              SyntheticStallRunner() if command == 'diagnose-stalls' else SyntheticHistoricalRunner())
    code = main(arguments, sources=SyntheticSources(), runner=runner, stdout=output,
                pstore_collector=SyntheticSources().pstore_snapshot,
                pstore_archive_collector=SyntheticSources().pstore_snapshot)
    payload = json.loads(output.getvalue())
    if code != 0 or payload.get('state') == 'unavailable' or not (payload.get('observations') or payload.get('boots')):
        raise RuntimeError('Synthetic collection failed')
    if command in {'diagnose-pstore', 'diagnose-pstore-archive'}:
        key = 'pstore_archive' if command == 'diagnose-pstore-archive' else 'pstore'
        if payload[key]['state'] != 'available' or len(payload[key]['records']) != 8:
            raise RuntimeError('Synthetic pstore analysis failed')
    if command == 'diagnose-stalls':
        if len(payload['findings']) != 500 or {item['rule_id'] for item in payload['findings']} != {
                'kernel.soft_lockup', 'kernel.hard_lockup', 'kernel.hung_task'}:
            raise RuntimeError('Synthetic stall analysis failed')
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
    parser.add_argument('--iterations', type=positive_iterations, default=10)
    parser.add_argument('--worker', choices=('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux is required for RSS units and the application.')
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    summary = {'synthetic': True, 'python': sys.version.split()[0], 'iterations': args.iterations, 'commands': {}}
    passed = True
    for command in ('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss'):
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
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
