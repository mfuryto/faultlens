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
    fields = text.splitlines()[0].split()
    if fields[0] != "cpu" or len(fields) < 9:
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
    lines = text.splitlines()
    if len(lines) < 2 or "Inter-" not in lines[0] or "Receive" not in lines[0]:
        raise ValueError("Missing network header")
    for line in lines[2:]:
        name, separator, tail = line.rpartition(":")
        name = name.strip()
        values = tail.split()
        if not separator or not NAME.fullmatch(name) or len(values) != 16:
            raise ValueError("Invalid network counters")
        values = counters(values)
        result.append({"interface": name, "received_bytes": values[0], "sent_bytes": values[8],
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
    previous = 0
    seen = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if (len(fields) < 3 or not re.fullmatch(r"-?[0-9]{1,6}", fields[0])
                or not re.fullmatch(r"[a-f0-9]{32}", fields[1]) or fields[0] in seen):
            raise ValueError("Unexpected boot listing")
        seen.add(fields[0])
        previous += int(fields[0]) < 0
    return previous
