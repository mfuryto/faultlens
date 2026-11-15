"""Run synthetic acceptance under one-CPU/limited-address-space Linux profiles.

These are process constraints on the current host, not booted VPS images or a
claim of deployment acceptance. Never collect live host diagnostics here.
"""
import argparse
import json
from pathlib import Path
import os
import resource
import subprocess
import sys
import time

sys.dont_write_bytecode = True
MODES = ('status', 'check', 'phase3-security', 'tui-status', 'tui-diagnostic')
PROFILES = (128, 256, 512)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, choices=range(1, 4), default=1)
    parser.add_argument('--worker', choices=MODES, help=argparse.SUPPRESS)
    parser.add_argument('--memory-mib', type=int, choices=PROFILES, default=128, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux resource limits and CPU affinity are required')
    if args.worker:
        resource.setrlimit(resource.RLIMIT_AS, (args.memory_mib*1024*1024,)*2)
        resource.setrlimit(resource.RLIMIT_CPU, (3, 4))
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from benchmark import worker
        value = worker(args.worker)
        value.update(address_space_limit_mib=args.memory_mib, cpu_affinity_count=len(os.sched_getaffinity(0)))
        print(json.dumps(value))
        return 0
    output = {'synthetic': True, 'deployment_test': False,
              'scope': 'One-CPU process affinity and virtual-address-space ceilings; not VM RAM quotas.',
              'profiles': [], 'passed': True}
    for memory in PROFILES:
        for mode in MODES:
            for _ in range(args.iterations):
                started = time.monotonic()
                child = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()),
                    '--worker', mode, '--memory-mib', str(memory)], capture_output=True, text=True, timeout=10)
                if child.returncode:
                    output['profiles'].append({'memory_mib':memory, 'mode':mode, 'passed':False,
                                               'reason':'constrained_worker_failed'})
                    output['passed'] = False
                    continue
                result = json.loads(child.stdout)
                elapsed = time.monotonic()-started
                passed = (result['cpu_affinity_count'] == 1 and result['peak_rss_mib'] < 50
                          and result['cpu_seconds'] < 1 and elapsed < 2)
                output['profiles'].append(dict(result, mode=mode, wall_seconds=round(elapsed,4), passed=passed))
                output['passed'] &= passed
    print(json.dumps(output, indent=2))
    return 0 if output['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
