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


def main(argv=None, *, sources=None, runner=None, platform=None, stdout=None, stderr=None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = SafeArgumentParser(prog="faultlens", description="Local read-only Linux system observations.")
    parser.add_argument("--version", action="version", version="Faultlens " + __version__)
    parser.add_argument("command", nargs="?", choices=("status", "check"), default="status")
    parser.add_argument("--json", action="store_true", help="Emit structured observations to stdout only.")
    parser.add_argument("--sample-seconds", type=interval, default=0.1, help="CPU sample duration (0.05–1; status only).")
    args = parser.parse_args(argv)
    if (platform or sys.platform) != "linux":
        print("Faultlens supports Linux only.", file=stderr)
        return 1
    try:
        items = (status(sources, runner, args.sample_seconds) if args.command == "status"
                 else check(sources, runner))
        data = report(args.command, items)
        if args.json:
            print(json.dumps(data, ensure_ascii=True, allow_nan=False), file=stdout)
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
