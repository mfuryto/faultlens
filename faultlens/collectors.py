"""Read-only observations from Linux interfaces, with explicit evidence gaps."""
import time

from .commands import Command, CommandRunner, TOOLS
from .linux import LinuxSources
from .models import Observation, unavailable
from . import parsers


HOST_SCOPE = ("Kernel counters may describe the host rather than container resource limits.",)


def percentage(key: str, used: int, total: int, source: str, limitations=()) -> Observation:
    if total <= 0 or not 0 <= used <= total:
        raise ValueError("Inconsistent capacity")
    value = round(100 * used / total, 2)
    state = "critical" if value >= 95 else "warning" if value >= 90 else "normal"
    return Observation(key, value, "percent", source, state,
                       explanation="Capacity usage only; this does not establish a failure or cause.",
                       limitations=limitations, thresholds={"warning": 90, "critical": 95})


def _attempt(items: list, key: str, source: str, collect):
    try:
        result = collect()
        items.extend(result if isinstance(result, list) else [result])
    except (OSError, ValueError, KeyError, IndexError, StopIteration, OverflowError, UnicodeError):
        items.append(unavailable(key, source, "Source is missing, inaccessible, malformed, or exceeds limits."))


def status(sources=None, runner=None, sample_seconds=0.1, sleep=time.sleep) -> list[Observation]:
    sources = sources or LinuxSources()
    runner = runner or CommandRunner()
    items = []

    def collect_cpu():
        before = parsers.cpu(sources.read("/proc/stat"))
        sleep(sample_seconds)
        after = parsers.cpu(sources.read("/proc/stat"))
        return Observation("cpu.busy", parsers.cpu_percent(before, after), "percent", "/proc/stat",
                           limitations=HOST_SCOPE + ("Short sample; idle and iowait excluded, steal included. Not per-process CPU.",))
    _attempt(items, "cpu.busy", "/proc/stat", collect_cpu)

    def collect_boot():
        text = sources.read("/proc/stat")
        fields = next(line.split()[1:] for line in text.splitlines() if line.startswith("btime "))
        if len(fields) != 1:
            raise ValueError("Invalid boot time")
        return Observation("system.boot_time", parsers.counters(fields)[0], "Unix seconds", "/proc/stat",
                           limitations=HOST_SCOPE + ("Wall-clock adjustments can affect event correlation.",))
    _attempt(items, "system.boot_time", "/proc/stat", collect_boot)

    def collect_kernel():
        value = sources.read("/proc/sys/kernel/osrelease", limit=256).strip()
        if not value or len(value) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-" for c in value):
            raise ValueError("Invalid kernel release")
        return Observation("system.kernel_release", value, "", "/proc/sys/kernel/osrelease")
    _attempt(items, "system.kernel_release", "/proc/sys/kernel/osrelease", collect_kernel)

    def collect_load():
        values = sources.read("/proc/loadavg").split()
        if len(values) != 5:
            raise ValueError("Invalid load average")
        return Observation("cpu.load_average", [parsers.number(v) for v in values[:3]],
                           "1/5/15 minutes", "/proc/loadavg", limitations=HOST_SCOPE +
                           ("Runnable and uninterruptible tasks; not CPU utilization or proof of overload.",))
    _attempt(items, "cpu.load_average", "/proc/loadavg", collect_load)

    def collect_memory():
        values = parsers.memory(sources.read("/proc/meminfo"))
        return [Observation("memory.total", values["MemTotal"], "bytes", "/proc/meminfo", limitations=HOST_SCOPE),
                percentage("memory.used", values["MemTotal"] - values["MemAvailable"],
                           values["MemTotal"], "/proc/meminfo", HOST_SCOPE + ("MemAvailable is a kernel estimate.",))]
    _attempt(items, "memory.used", "/proc/meminfo", collect_memory)

    def collect_swap():
        values = parsers.memory(sources.read("/proc/meminfo"))
        total, free = values["SwapTotal"], values["SwapFree"]
        if free > total:
            raise ValueError("Invalid swap capacity")
        return [Observation("swap.total", total, "bytes", "/proc/meminfo", limitations=HOST_SCOPE),
                Observation("swap.used", total - free, "bytes", "/proc/meminfo", limitations=HOST_SCOPE)]
    _attempt(items, "swap.used", "/proc/meminfo", collect_swap)

    def collect_uptime():
        fields = sources.read("/proc/uptime").split()
        if len(fields) != 2:
            raise ValueError("Invalid uptime")
        return Observation("system.uptime", parsers.number(fields[0]), "seconds", "/proc/uptime", limitations=HOST_SCOPE)
    _attempt(items, "system.uptime", "/proc/uptime", collect_uptime)

    def collect_disk():
        data = sources.filesystem()
        total, free = data.f_blocks * data.f_frsize, data.f_bfree * data.f_frsize
        if not 0 <= data.f_bavail <= data.f_bfree <= data.f_blocks or data.f_frsize <= 0:
            raise ValueError("Invalid filesystem capacity")
        return [Observation("filesystem.root.total", total, "bytes", "statvfs(/)"),
                Observation("filesystem.root.available", data.f_bavail * data.f_frsize, "bytes", "statvfs(/)"),
                percentage("filesystem.root.used", total - free, total, "statvfs(/)",
                           ("Root filesystem only; reserved blocks affect unprivileged availability. Not a filesystem integrity check.",))]
    _attempt(items, "filesystem.root.used", "statvfs(/)", collect_disk)
    _attempt(items, "storage.io_counters", "/proc/diskstats",
             lambda: Observation("storage.io_counters", parsers.disk_io(sources.read("/proc/diskstats")),
                                 "cumulative bytes/ms", "/proc/diskstats", limitations=HOST_SCOPE +
                                 ("Per-device counters can overlap for partitions and virtual devices; do not sum them. No rate or health inference.",)))
    _attempt(items, "network.counters", "/proc/net/dev",
             lambda: Observation("network.counters", parsers.network(sources.read("/proc/net/dev")),
                                 "cumulative bytes/events", "/proc/net/dev",
                                 limitations=("Current network namespace; no addresses, packet capture, rate or attack inference.",)))
    _attempt(items, "processes.visible", "/proc",
             lambda: Observation("processes.visible", sources.process_count(), "processes", "/proc",
                                 limitations=("Visible PID directories only; processes can exit during collection. No command lines collected.",)))
    result = runner.run(Command.SYSTEM_STATE)
    state = result.stdout.strip()
    known = {"running", "degraded", "starting", "initializing", "maintenance", "stopping", "offline"}
    if result.state == "completed" and state in known and result.returncode in {0, 1}:
        items.append(Observation("services.system_state", state, "", "systemctl is-system-running",
                                 "normal" if state == "running" else "warning",
                                 explanation="Reported systemd manager state; service details are not collected."))
    else:
        items.append(unavailable("services.system_state", "systemctl is-system-running",
                                 "Systemd state could not be verified; systemd may be absent or inaccessible."))
    return items


def check(sources=None, runner=None) -> list[Observation]:
    sources = sources or LinuxSources()
    runner = runner or CommandRunner()
    items = []
    for tool in TOOLS:
        available = runner.available(tool)
        items.append(Observation("dependency." + tool, available, "", "trusted system executable directories",
                                 "normal" if available else "unavailable",
                                 explanation="Optional integration availability only; no installation or elevation performed."))
    for key, path in (("journal.persistent_directory", "/var/log/journal"),
                      ("journal.runtime_directory", "/run/log/journal"),
                      ("kernel.pstore_directory", "/sys/fs/pstore")):
        _attempt(items, key, path, lambda key=key, path=path: Observation(
            key, sources.directory(path), "", path, "unknown", "Unknown",
            "Directory presence only; not proof of active recording, retention or usable evidence."))
    result = runner.run(Command.JOURNAL_BOOTS)
    if result.state == "completed" and result.returncode == 0:
        _attempt(items, "journal.previous_boots", "journalctl --list-boots",
                 lambda: Observation("journal.previous_boots", parsers.boot_count(result.stdout), "boots",
                                     "journalctl --list-boots", "unknown" if not result.stdout.strip() else "normal",
                                     explanation="Counts previous boots visible to this user; no raw journal entries are displayed.",
                                     limitations=("Zero visible boots does not prove disabled persistence. Permissions, rotation and incomplete records limit history.",)))
    else:
        items.append(unavailable("journal.previous_boots", "journalctl --list-boots",
                                 "Boot history unavailable; verify journal access and persistence manually."))
    for key, command in (("journal.service_active", Command.JOURNAL_SERVICE),
                         ("atop.service_active", Command.ATOP_SERVICE)):
        result = runner.run(command)
        value = result.stdout.strip()
        if result.state == "completed" and result.returncode in {0, 3} and value in {"active", "inactive", "failed"}:
            items.append(Observation(key, value, "", "systemctl is-active", "normal" if value == "active" else "warning",
                                     explanation="Service state only; does not verify recording interval, retention or evidence integrity."))
        else:
            items.append(unavailable(key, "systemctl is-active", "Service state could not be verified."))
    return items
