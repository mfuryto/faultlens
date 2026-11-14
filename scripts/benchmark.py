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
    from tests.support import SyntheticHistoricalRunner, SyntheticSources
    output = io.StringIO()
    started = time.monotonic()
    arguments = ['diagnose', '--atop-date', '20260101', '--json'] if command == 'diagnose-atop' else [command, '--json']
    if command == 'check-history':
        arguments = ['check', '--history', '--json']
    if command == 'diagnose-pstore-archive':
        arguments = ['diagnose', '--pstore-archive', '--json']
    if command == 'diagnose-pstore':
        arguments = ['diagnose', '--pstore', '--json']
    code = main(arguments, sources=SyntheticSources(), runner=SyntheticHistoricalRunner(), stdout=output,
                pstore_collector=SyntheticSources().pstore_snapshot,
                pstore_archive_collector=SyntheticSources().pstore_snapshot)
    payload = json.loads(output.getvalue())
    if code != 0 or payload.get('state') == 'unavailable' or not (payload.get('observations') or payload.get('boots')):
        raise RuntimeError('Synthetic collection failed')
    if command in {'diagnose-pstore', 'diagnose-pstore-archive'}:
        key = 'pstore_archive' if command == 'diagnose-pstore-archive' else 'pstore'
        if payload[key]['state'] != 'available' or len(payload[key]['records']) != 8:
            raise RuntimeError('Synthetic pstore analysis failed')
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
    parser.add_argument('--worker', choices=('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux is required for RSS units and the application.')
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    summary = {'synthetic': True, 'python': sys.version.split()[0], 'iterations': args.iterations, 'commands': {}}
    passed = True
    for command in ('status', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive'):
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
