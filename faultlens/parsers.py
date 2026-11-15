"""Pure parsers for documented Linux counters. Invalid evidence fails closed."""
import math
import re


NAME = re.compile(r"[A-Za-z0-9_.:@!-]{1,64}\Z")


def number(text: str) -> float:
    value = float(text)
    if not math.isfinite(value) or value < 0:
        raise ValueError("Invalid nonnegative measurement")
    return value


def counters(parts: list[str]) -> list[int]:
    if not all(p.isascii() and p.isdecimal() and len(p) <= 20 for p in parts):
        raise ValueError("Invalid counters")
    return [int(p) for p in parts]


def cpu(text: str) -> tuple[int, ...]:
    lines = text.splitlines()
    fields = lines[0].split() if lines else []
    if len(fields) < 9 or fields[0] != "cpu":
        raise ValueError("Incomplete aggregate CPU counters")
    # guest and guest_nice are already included in user and nice.
    return tuple(counters(fields[1:9]))


def cpu_percent(before: tuple[int, ...], after: tuple[int, ...]) -> float:
    changes = [b - a for a, b in zip(before, after)]
    if len(changes) != 8 or any(c < 0 for c in changes) or sum(changes) == 0:
        raise ValueError("CPU counters reset or did not advance")
    return round(100 * (sum(changes) - changes[3] - changes[4]) / sum(changes), 2)


def memory(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in {"MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"}:
            if len(fields) != 3 or fields[2] != "kB" or fields[0][:-1] in result:
                raise ValueError("Invalid memory fields")
            result[fields[0][:-1]] = counters([fields[1]])[0] * 1024
    return result


def network(text: str) -> list[dict]:
    result = []
    seen = set()
    lines = text.splitlines()
    if (len(text.encode()) > 262144 or len(lines) < 2
            or ' '.join(lines[0].split()) != 'Inter-| Receive | Transmit'
            or ' '.join(lines[1].split()) != 'face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed'):
        raise ValueError("Missing network header")
    for line in lines[2:]:
        name, separator, tail = line.rpartition(":")
        name = name.strip()
        values = tail.split()
        if not separator or not NAME.fullmatch(name) or name in seen or len(values) != 16:
            raise ValueError("Invalid network counters")
        seen.add(name)
        values = counters(values)
        result.append({"interface": name, "received_bytes": values[0], "sent_bytes": values[8],
                       "received_packets": values[1], "sent_packets": values[9],
                       "receive_errors": values[2], "receive_drops": values[3],
                       "send_errors": values[10], "send_drops": values[11]})
        if len(result) > 128:
            raise ValueError("Too many interfaces")
    return result


def disk_io(text: str) -> list[dict]:
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 14 or not NAME.fullmatch(fields[2]):
            raise ValueError("Invalid disk counters")
        counters(fields[:2])
        values = counters(fields[3:])
        result.append({"device": fields[2], "read_bytes": values[2] * 512,
                       "written_bytes": values[6] * 512, "io_time_ms": values[9]})
        if len(result) > 128:
            raise ValueError("Too many disk devices")
    return result


def boot_count(text: str) -> int:
    from .journal import boots
    return sum(boot.index < 0 for boot in boots(text))
