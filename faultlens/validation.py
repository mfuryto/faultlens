"""Optional local comparisons; reports contain states, never raw measurements."""
import math
import os
import time

from .collectors import status
from .commands import Command, CommandRunner
from .parsers import counters


def memory_reference(text: str) -> dict:
    rows = [line.split() for line in text.splitlines()]
    memory = [row for row in rows if row and row[0] == 'Mem:']
    swap = [row for row in rows if row and row[0] == 'Swap:']
    if len(memory) != 1 or len(swap) != 1 or len(memory[0]) != 7 or len(swap[0]) != 4:
        raise ValueError('Unsupported free layout')
    values, swap_values = counters(memory[0][1:]), counters(swap[0][1:])
    total, available = values[0], values[-1]
    if total <= 0 or available > total or swap_values[1] + swap_values[2] != swap_values[0]:
        raise ValueError('Inconsistent reference memory')
    return {'memory.total': total, 'memory.used': 100 * (total - available) / total,
            'swap.total': swap_values[0]}


def filesystem_reference(text: str) -> dict:
    rows = [line.split() for line in text.splitlines() if line.strip()]
    if len(rows) != 2 or len(rows[1]) != 4 or not rows[1][3].endswith('%'):
        raise ValueError('Unsupported df layout')
    total, used, available, percent = counters(rows[1][:3] + [rows[1][3][:-1]])
    if total <= 0 or used > total or available > total - used:
        raise ValueError('Inconsistent reference filesystem')
    return {'filesystem.root.total': total, 'filesystem.root.used': 100 * used / total,
            'filesystem.root.user_used': percent}


def compare(observations, references: dict) -> list[dict]:
    tolerances = {'memory.total': 0, 'memory.used': 2, 'swap.total': 0,
                  'filesystem.root.total': 0, 'filesystem.root.used': 1,
                  'filesystem.root.user_used': 1.01, 'system.kernel_release': 0}
    measured = {item.key: item for item in observations}
    results = []
    for key, tolerance in tolerances.items():
        item = measured.get(key)
        expected = references.get(key)
        if item is None or item.value is None or expected is None:
            state = 'unavailable'
        elif isinstance(expected, str):
            state = 'pass' if item.value == expected else 'mismatch'
        elif (type(item.value) in (int, float) and math.isfinite(item.value)
              and type(expected) in (int, float) and math.isfinite(expected)):
            state = 'pass' if abs(item.value - expected) <= tolerance else 'mismatch'
        else:
            state = 'mismatch'
        results.append({'key': key, 'state': state})
    return results


def validate(*, sources=None, runner=None, kernel=None):
    runner = runner or CommandRunner()
    references = {}
    for command, parser in ((Command.REFERENCE_MEMORY, memory_reference),
                            (Command.REFERENCE_FILESYSTEM, filesystem_reference)):
        result = runner.run(command)
        if result.state == 'completed' and result.returncode == 0:
            try:
                references.update(parser(result.stdout))
            except (ValueError, IndexError):
                pass
    try:
        references['system.kernel_release'] = kernel if kernel is not None else os.uname().release
    except OSError:
        pass
    started = time.monotonic()
    observations = status(sources=sources, runner=runner)
    results = compare(observations, references)
    # A separate kernel clock, without relying on /proc/uptime's parser.
    try:
        uptime = time.clock_gettime(time.CLOCK_BOOTTIME)
        observed = next(item.value for item in observations if item.key == 'system.uptime')
        state = ('unavailable' if observed is None else
                 'pass' if abs(uptime - observed) <= time.monotonic() - started + 0.1 else 'mismatch')
    except (OSError, AttributeError, StopIteration):
        state = 'unavailable'
    results.append({'key': 'system.uptime', 'state': state})
    return {'comparisons': results,
            'limitations': ['Different collection times can cause differences on a busy system.',
                            'Memory tolerance is 2 percentage points; filesystem tolerance is 1 point (1.01 for df rounding).',
                            'CPU intervals, load, process counts, network/I/O counters and journal history are not independently compared.',
                            'A match is consistency evidence, not proof of host health or correctness of the underlying kernel.']}


def exit_code(result: dict) -> int:
    states = {item['state'] for item in result['comparisons']}
    if 'mismatch' in states:
        return 1
    return 2 if 'unavailable' in states else 0
