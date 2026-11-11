"""CLI presentation only; collectors never write reports or configuration."""
import argparse
import json
import math
import sys
import unicodedata

from . import __version__
from .collectors import check, status
from .models import report


def safe_text(value: str) -> str:
    # Include C1 controls and bidi format characters, not just ANSI ESC.
    return "".join(c if not unicodedata.category(c).startswith("C") else "?" for c in value)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(safe_text(message))


def interval(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Sample must be a number from 0.05 to 1 second.") from exc
    if not math.isfinite(parsed) or not 0.05 <= parsed <= 1:
        raise argparse.ArgumentTypeError("Sample must be a number from 0.05 to 1 second.")
    return parsed


def boot_index(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Boot index must be an integer from -128 to 0.") from exc
    if not -128 <= parsed <= 0:
        raise argparse.ArgumentTypeError("Boot index must be an integer from -128 to 0.")
    return parsed


def render_history(data, stdout):
    print("Faultlens — read-only " + data['command'] + ": " + data['state'], file=stdout)
    for boot in data['boots']:
        print(f"Boot {boot['index']}: {boot['boot_id']}", file=stdout)
    if data['command'] == 'diagnose':
        if data['selected_boot']:
            print("Selected boot: " + json.dumps(data['selected_boot'], ensure_ascii=True), file=stdout)
        print(f"Records examined: {data['records_examined']} (bounded tail)", file=stdout)
        if data['last_record']:
            print("Last visible record reference: " + json.dumps(data['last_record'], ensure_ascii=True), file=stdout)
        print("Root cause: Unknown. Shutdown: " + data['shutdown_assessment'], file=stdout)
        for finding in data['findings']:
            print(f"[{finding['severity'].upper()}] {finding['title']} ({finding['confidence']} event; cause Unknown)", file=stdout)
            print("  Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
            print("  Reasoning: " + finding['reasoning'], file=stdout)
            for text in finding['limitations'] + finding['recommendations']:
                print("  " + text, file=stdout)
    for text in data['limitations']:
        print("Limitation: " + text, file=stdout)


def main(argv=None, *, sources=None, runner=None, platform=None, stdout=None, stderr=None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = SafeArgumentParser(prog="faultlens", description="Local read-only Linux system observations.")
    parser.add_argument("--version", action="version", version="Faultlens " + __version__)
    parser.add_argument("command", nargs="?", choices=("status", "check", "history", "diagnose"), default="status")
    parser.add_argument("--json", action="store_true", help="Emit structured observations to stdout only.")
    parser.add_argument("--sample-seconds", type=interval, default=0.1, help="CPU sample duration (0.05–1; status only).")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--previous-boot", action="store_true", help="Analyze the previous visible boot (diagnose only).")
    scope.add_argument("--boot", type=boot_index, help="Visible boot index from -128 to 0 (diagnose only).")
    args = parser.parse_args(argv)
    if args.command != "diagnose" and (args.previous_boot or args.boot is not None):
        parser.error("Boot selection is supported only with diagnose.")
    if (platform or sys.platform) != "linux":
        print("Faultlens supports Linux only.", file=stderr)
        return 1
    try:
        if args.command in {"history", "diagnose"}:
            from .incidents import history, diagnose
            data = history(runner) if args.command == "history" else diagnose(runner, -1 if args.boot is None else args.boot)
        else:
            items = (status(sources, runner, args.sample_seconds) if args.command == "status"
                     else check(sources, runner))
            data = report(args.command, items)
        if args.json:
            print(json.dumps(data, ensure_ascii=True, allow_nan=False), file=stdout)
        elif args.command in {"history", "diagnose"}:
            render_history(data, stdout)
        else:
            print("Faultlens " + __version__ + " — read-only " + args.command, file=stdout)
            for item in items:
                value = "unavailable" if item.value is None else json.dumps(item.value, ensure_ascii=True)
                print(safe_text(f"[{item.state.upper()}] {item.key}: {value} {item.unit}"), file=stdout)
                print(safe_text(f"  Source: {item.source}. {item.explanation}"), file=stdout)
                for limitation in item.limitations:
                    print(safe_text("  Limitation: " + limitation), file=stdout)
            print("Observations are not a root-cause diagnosis. Use --json for confidence and thresholds.", file=stdout)
        return 0
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("Collection interrupted.", file=stderr)
        return 130
    except (OSError, ValueError):
        print("Collection could not complete; no report was saved.", file=stderr)
        return 1
