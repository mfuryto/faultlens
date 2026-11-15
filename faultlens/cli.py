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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Python 3.14 adds automatic help colors. Keep parser output deterministic
        # and control-free, including when the environment forces terminal color.
        if hasattr(self, 'color'):
            self.color = False

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


def overview_count(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or len(value) > 1 or not 1 <= int(value) <= 7:
        raise argparse.ArgumentTypeError("Boot count must be an integer from 1 to 7.")
    return int(value)


def boot_identity(value: str) -> str:
    from .journal import BOOT_ID
    if not isinstance(value, str) or not BOOT_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("Boot ID must contain exactly 32 lowercase hexadecimal characters.")
    return value


def receipt_boundary(value: str) -> int:
    from .journal import MAX_REALTIME_US
    if not value.isascii() or not value.isdecimal() or len(value) > 18 or int(value) > MAX_REALTIME_US:
        raise argparse.ArgumentTypeError("Time boundary must be nonnegative Unix microseconds through year 9999.")
    return int(value)


def atop_date(value: str) -> str:
    from .recordings import recording_date
    try:
        return recording_date(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Atop date must be a valid YYYYMMDD date from 1970 onward.") from exc


def render_incidents(data, stdout):
    print("Faultlens — read-only incidents: " + data['state'], file=stdout)
    print("Journal scope: " + data['journal_scope']['requested'] + "; completeness unknown; no elevation.", file=stdout)
    print(f"Selected boots: {data['selected_boot_count']}; selection cap reached: {data['selection_limit_reached']}.", file=stdout)
    for summary in data['summaries']:
        boot = summary['boot']
        print(f"Boot {boot['index']}: {boot['boot_id']} — {summary['state']}", file=stdout)
        print(f"  Records: {summary['records_examined']}; tail cap reached: {summary['record_limit_reached']}; findings: {summary['finding_count']} reports.", file=stdout)
        print("  Finding counts: " + json.dumps(summary['finding_counts_by_rule'], ensure_ascii=True), file=stdout)
        print("  Shutdown: " + summary['shutdown_assessment'] + "; root cause Unknown.", file=stdout)
        print("  Collection: " + json.dumps(summary['journal_collection'], ensure_ascii=True), file=stdout)
        print("  Last visible reference: " + json.dumps(summary['last_record'], ensure_ascii=True), file=stdout)
        print("  Details: faultlens diagnose --boot-id " + boot['boot_id'] +
              (" --system-journal" if data['journal_scope']['requested'] == 'system' else "") + " --json", file=stdout)
    for limitation in data['limitations']:
        print("Limitation: " + limitation, file=stdout)


def render_history(data, stdout):
    print("Faultlens — read-only " + data['command'] + ": " + data['state'], file=stdout)
    scope = data['journal_scope']
    print("Journal scope: " + scope['requested'] + "; completeness unknown; no elevation.", file=stdout)
    if scope['kernel_records_examined'] is not None:
        print(f"System evidence in retained tail: kernel records {scope['kernel_records_examined']}; PID 1 systemd records {scope['pid1_systemd_records_examined']}.", file=stdout)
    collection = data.get('journal_collection')
    if collection and (collection['command_state'] != 'completed' or collection['returncode'] != 0 or collection['parse_state'] != 'valid'):
        print("Journal collection: " + json.dumps(collection, ensure_ascii=True), file=stdout)
    listing = data.get('boot_listing')
    if listing and (listing['command_state'] != 'completed' or listing['returncode'] != 0 or listing['parse_state'] != 'valid'):
        print("Boot listing: " + json.dumps(listing, ensure_ascii=True), file=stdout)
    for boot in data['boots']:
        print(f"Boot {boot['index']}: {boot['boot_id']}", file=stdout)
    if data['command'] == 'diagnose':
        print("Journal window: " + json.dumps(data['journal_window'], ensure_ascii=True), file=stdout)
        print("Boot selection: " + json.dumps(data['boot_selection'], ensure_ascii=True), file=stdout)
        if data['selected_boot']:
            print("Selected boot: " + json.dumps(data['selected_boot'], ensure_ascii=True), file=stdout)
        print(f"Records examined: {data['records_examined']} (bounded tail)", file=stdout)
        if data['last_record']:
            print("Last visible record reference: " + json.dumps(data['last_record'], ensure_ascii=True), file=stdout)
        print("Root cause: Unknown. Shutdown: " + data['shutdown_assessment'], file=stdout)
        context = data.get('reconstruction')
        if context and context['state'] == 'available':
            print(f"Observed journal span: {context['monotonic_span_us']} microseconds; whole-boot coverage unknown.", file=stdout)
            interval = context['largest_observed_record_interval']
            if interval:
                print(f"Largest observed record interval: {interval['duration_us']} microseconds; no missing-log or downtime inference.", file=stdout)
            clock = context['clock_mapping']
            print(f"Clock mapping: {clock['assessment']}; wall-clock regressions: {clock['wall_clock_regression_count']}; equal timestamp pairs: {context['equal_monotonic_record_pairs']}.", file=stdout)
            for text in context['limitations']:
                print("  Limitation: " + text, file=stdout)
        for index, finding in enumerate(data['findings']):
            print(f"[{finding['severity'].upper()}] {finding['title']} ({finding['confidence']} report; cause Unknown)", file=stdout)
            position = data['timeline'][index]
            print(f"  Journal position: {position['from_first_visible_record_us']} microseconds from first visible record; {position['before_last_visible_record_us']} before last; {position['relative_order']}.", file=stdout)
            print("  Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
            print("  Reasoning: " + finding['reasoning'], file=stdout)
            if finding["reported_measurements"]:
                print("  Reported measurements: " + json.dumps(finding["reported_measurements"], ensure_ascii=True), file=stdout)
            for text in finding['limitations'] + finding['recommendations']:
                print("  " + text, file=stdout)
        targeted = data.get('event_search')
        if targeted:
            print("Targeted event search: " + targeted['state'] + "; completeness unknown; root cause Unknown.", file=stdout)
            for query in targeted['queries']:
                print(f"  Query {query['query']}: {query['state']}; candidates {query['candidates_examined']}; findings {len(query['findings'])}; cap reached {query['record_limit_reached']}.", file=stdout)
                print("  Collection: " + json.dumps({key: query[key] for key in ('command_state', 'returncode', 'parse_state', 'reason')}, ensure_ascii=True), file=stdout)
                if query['candidate_window']:
                    print(f"  Candidate receipt-time span: {query['candidate_window']['monotonic_candidate_span_us']} microseconds; filtered, not continuous coverage.", file=stdout)
                review = query['candidate_review']
                if review is not None:
                    print(f"  Candidate review: matched {review['matched_candidates']}; unclassified {review['unclassified_candidates']}; examples truncated {review['unclassified_examples_truncated']}.", file=stdout)
                    print("  Recorded priority counts: " + json.dumps(review['reported_priority_counts'], ensure_ascii=True), file=stdout)
                    for example in review['unclassified_examples']:
                        print(f"    Unclassified candidate {example['candidate_index']}: recorded priority {example['reported_priority_label']}; {example['reason']}.", file=stdout)
                        print("      Evidence: " + json.dumps(example['reference'], ensure_ascii=True), file=stdout)
                        print("      Selection: " + example['selection_reason'], file=stdout)
                        print("      Explanation: " + example['explanation'], file=stdout)
                    for text in review['limitations'] + review['recommendations']:
                        print("  " + text, file=stdout)
                for finding in query['findings']:
                    print(f"  [{finding['severity'].upper()}] {finding['title']} ({finding['confidence']} report; cause Unknown)", file=stdout)
                    print("    Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
                    print("    Reasoning: " + finding['reasoning'], file=stdout)
                    if finding["reported_measurements"]:
                        print("    Reported measurements: " + json.dumps(finding["reported_measurements"], ensure_ascii=True), file=stdout)
                    for text in finding['limitations'] + finding['recommendations']:
                        print("    " + text, file=stdout)
            for text in targeted.get('limitations', []):
                print("  Limitation: " + text, file=stdout)
        ssh = data.get('ssh_analysis')
        if ssh:
            print("SSH journal analysis: " + ssh['state'] + "; attack Unknown; completeness unknown.", file=stdout)
            print("  Collection: " + json.dumps({key: ssh[key] for key in ('command_state', 'returncode', 'parse_state', 'reason')}, ensure_ascii=True), file=stdout)
            print(f"  Candidates: {ssh['candidates_examined']}; cap reached: {ssh['record_limit_reached']}; unclassified: {ssh['unclassified_candidates']}.", file=stdout)
            print("  Rule counts: " + json.dumps(ssh['finding_counts_by_rule'], ensure_ascii=True), file=stdout)
            for finding in ssh['findings']:
                print("  [" + finding['severity'].upper() + "] " + finding['title'] + "; Confirmed report; attack Unknown.", file=stdout)
                print("    Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
                print("    Reasoning: " + finding['reasoning'], file=stdout)
            for record in ssh['records']:
                print("  Original SSH evidence: " + json.dumps(record, ensure_ascii=True), file=stdout)
            for text in ssh['limitations']:
                print("  Limitation: " + text, file=stdout)
            print("  Recommendation: Review original evidence locally; no automatic SSH or firewall changes.", file=stdout)
        firewall = data.get('firewall_analysis')
        if firewall:
            print("Firewall journal analysis: " + firewall['state'] + "; packet verdict/attack Unknown.", file=stdout)
            print("  Collection: " + json.dumps({key: firewall[key] for key in ('command_state', 'returncode', 'parse_state', 'reason')}, ensure_ascii=True), file=stdout)
            print(f"  Kernel candidates: {firewall['candidates_examined']}; cap reached: {firewall['record_limit_reached']}; unclassified: {firewall['unclassified_candidates']}.", file=stdout)
            print("  Reported label counts: " + json.dumps(firewall['reported_label_counts'], ensure_ascii=True), file=stdout)
            for finding in firewall['findings']:
                print("  [" + finding['severity'].upper() + "] " + finding['title'], file=stdout)
                print("    Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
                print("    Reasoning: " + finding['reasoning'], file=stdout)
            for record in firewall['records']:
                print("  Original kernel candidate: " + json.dumps(record, ensure_ascii=True), file=stdout)
            for text in firewall['limitations']:
                print("  Limitation: " + text, file=stdout)
            print("  Recommendation: Review original records and local policy; no automatic firewall changes.", file=stdout)
        if 'journal_records' in data:
            print("Retained journal evidence (local administrator view):", file=stdout)
            for record in data['journal_records']:
                print("  " + json.dumps(record, ensure_ascii=True), file=stdout)
        targeted_records = data.get('event_search', {}).get('queries', [])
        for query in targeted_records:
            if 'records' in query:
                print("Original filtered evidence: " + query['query'], file=stdout)
                for record in query['records']:
                    print("  " + json.dumps(record, ensure_ascii=True), file=stdout)
        resources = data.get('atop', {})
        if resources.get('state') != 'not_requested':
            print("Atop: " + resources['state'], file=stdout)
            if 'profile' in resources:
                print("  Profile: " + resources['profile'], file=stdout)
            if resources['state'] == 'available':
                intervals = sorted({value['interval_s'] for value in resources['samples'] if not value['since_boot']})
                print(f"  Samples: {len(resources['samples'])}; observed intervals (seconds): {intervals}", file=stdout)
                coverage = resources["coverage"]
                print(f"  Possible interval gaps: {len(coverage['possible_gaps'])}; overlapping intervals: {coverage['overlapping_intervals']}; complete coverage unverified.", file=stdout)
                for text in coverage["limitations"]:
                    print("  Limitation: " + text, file=stdout)
                print(f"  Possible temporal overlaps: {len(resources['correlations'])}; host/boot unverified; cause Unknown.", file=stdout)
                print("  Use --json or --show-evidence for local sample identities and original replay records.", file=stdout)
                if 'journal_records' in data:
                    for sample in resources['samples']:
                        print("  Atop sample evidence: " + json.dumps(sample, ensure_ascii=True), file=stdout)
            else:
                print("  Reason: " + resources.get('reason', 'unavailable'), file=stdout)
            for limitation in resources.get('limitations', []):
                print("  Limitation: " + limitation, file=stdout)
        for key, label in (('pstore', 'Pstore'), ('pstore_archive', 'Pstore archive')):
            if key not in data:
                continue
            crash = data[key]
            print(label + ": " + crash['state'] + "; " + crash['reason'], file=stdout)
            print("  Source root: " + crash['source_root'], file=stdout)
            print("  Boot identity: unverified. Root cause: Unknown.", file=stdout)
            print("  Signature analysis: " + crash['analysis_state'], file=stdout)
            for item in crash['records']:
                visible = item if 'journal_records' in data else {key: value for key, value in item.items() if key != 'content'}
                print("  Evidence: " + json.dumps(visible, ensure_ascii=True), file=stdout)
            if crash['records'] and 'journal_records' not in data:
                print("  Original record content is available with --json or --show-evidence.", file=stdout)
            for text in crash['limitations'] + crash['recommendations']:
                print("  " + text, file=stdout)
    for text in data['limitations']:
        print("Limitation: " + text, file=stdout)


def main(argv=None, *, sources=None, runner=None, platform=None, stdout=None, stderr=None, pstore_collector=None, pstore_archive_collector=None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = SafeArgumentParser(prog="faultlens", description="Local read-only Linux system observations.")
    parser.add_argument("--version", action="version", version="Faultlens " + __version__)
    parser.add_argument("command", nargs="?", choices=("status", "check", "history", "diagnose", "incidents", "network", "security"), default="status")
    parser.add_argument("--json", action="store_true", help="Emit structured observations to stdout only.")
    parser.add_argument("--sockets", action="store_true", help="Include current TCP/UDP endpoints with network/security; no remote probes.")
    parser.add_argument("--sample-seconds", type=interval, default=0.1, help="Sample duration (0.05–1; status/network/security).")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--previous-boot", action="store_true", help="Analyze the previous visible boot (diagnose only).")
    scope.add_argument("--boot", type=boot_index, help="Visible boot index from -128 to 0 (diagnose only).")
    scope.add_argument("--boot-id", type=boot_identity, help="Exact boot ID visible in the selected scope listing (diagnose only).")
    parser.add_argument("--atop-date", type=atop_date, help="Opt-in local atop_YYYYMMDD recording (diagnose only).")
    parser.add_argument("--atop-extended", action="store_true", help="Opt in to disk, network and process resource rows; requires --atop-date with diagnose.")
    parser.add_argument("--history", action="store_true", help="Inspect preservation configuration and metadata (check only).")
    parser.add_argument("--pstore", action="store_true", help="Inspect bounded live pstore crash records (diagnose only; no boot attribution).")
    parser.add_argument("--pstore-archive", action="store_true", help="Inspect bounded raw systemd pstore archive records (diagnose only; no boot attribution).")
    parser.add_argument("--system-journal", action="store_true", help="Select accessible system journal for both boot listing and diagnosis (history/diagnose only; no elevation).")
    parser.add_argument("--search-events", action="store_true", help="Run two bounded candidate searches across the selected boot (diagnose only).")
    parser.add_argument("--search-ssh", action="store_true", help="Inspect bounded supported SSH authentication reports in the selected boot/time scope (diagnose only).")
    parser.add_argument("--until-us", type=receipt_boundary, help="End the ordinary tail at Unix receipt-time microseconds (diagnose only; --search-events unchanged).")
    parser.add_argument("--since-us", type=receipt_boundary, help="Start the ordinary journal window at Unix receipt-time microseconds (diagnose only; --search-events unchanged).")
    parser.add_argument("--boot-count", type=overview_count, help="Summarize 1–7 newest visible previous boots (incidents only; default 3).")
    parser.add_argument("--include-current", action="store_true", help="Include the current visible boot in incidents selection.")
    parser.add_argument("--show-evidence", action="store_true", help="Show retained original journal, Atop and pstore evidence locally (diagnose only).")
    parser.add_argument("--search-firewall", action="store_true", help="Inspect bounded kernel-tail candidates for supported firewall log forms (diagnose only).")
    args = parser.parse_args(argv)
    if args.search_firewall and args.command != 'diagnose':
        parser.error("Firewall journal analysis is supported only with diagnose.")
    if args.show_evidence and args.command != 'diagnose':
        parser.error("Original journal evidence is supported only with diagnose.")
    if args.search_ssh and args.command != 'diagnose':
        parser.error("SSH journal analysis is supported only with diagnose.")
    if args.atop_extended and (args.command != 'diagnose' or args.atop_date is None):
        parser.error("Extended resource context requires diagnose with --atop-date.")
    if (args.boot_count is not None or args.include_current) and args.command != "incidents":
        parser.error("Overview selection is supported only with incidents.")
    if args.since_us is not None and args.until_us is not None and args.since_us > args.until_us:
        parser.error("Journal start boundary must not exceed the end boundary.")
    if args.since_us is not None and args.command != "diagnose":
        parser.error("Journal time boundaries are supported only with diagnose.")
    if args.until_us is not None and args.command != "diagnose":
        parser.error("Journal time boundaries are supported only with diagnose.")
    if args.search_events and args.command != "diagnose":
        parser.error("Targeted event search is supported only with diagnose.")
    if args.system_journal and args.command not in {"history", "diagnose", "incidents"}:
        parser.error("System journal scope is supported only with history, diagnose or incidents.")
    if args.pstore_archive and args.command != "diagnose":
        parser.error("Pstore archive analysis is supported only with diagnose.")
    if args.pstore and args.command != "diagnose":
        parser.error("Pstore analysis is supported only with diagnose.")
    if args.history and args.command != "check":
        parser.error("Preservation assessment is supported only with check.")
    if args.command != "diagnose" and (args.previous_boot or args.boot is not None or args.boot_id is not None or args.atop_date is not None):
        parser.error("Boot selection is supported only with diagnose.")
    if args.sockets and args.command not in {"network", "security"}:
        parser.error("Socket collection is supported only with network or security.")
    if (platform or sys.platform) != "linux":
        print("Faultlens supports Linux only.", file=stderr)
        return 1
    try:
        if args.command in {'network', 'security'}:
            from .network import collect
            data = collect(sources, command=args.command, sample_seconds=args.sample_seconds)
            if args.sockets:
                from .sockets import attach
                attach(data, runner)
        elif args.command == "incidents":
            from .overview import incidents
            data = incidents(runner, boot_count=args.boot_count if args.boot_count is not None else 3,
                             system_journal=args.system_journal, include_current=args.include_current)
        elif args.command in {"history", "diagnose"}:
            from .incidents import history, diagnose
            data = (history(runner, system_journal=args.system_journal) if args.command == "history" else
                    diagnose(runner, args.boot, args.atop_date, system_journal=args.system_journal, search_events=args.search_events, boot_id=args.boot_id, until_us=args.until_us, since_us=args.since_us, atop_extended=args.atop_extended, search_ssh=args.search_ssh, show_evidence=args.show_evidence, search_firewall=args.search_firewall))
            if args.command == "diagnose" and args.pstore:
                from .pstore import analyze
                data["pstore"] = analyze(pstore_collector)
            if args.command == "diagnose" and args.pstore_archive:
                from .pstore_archive import analyze as analyze_archive
                data["pstore_archive"] = analyze_archive(pstore_archive_collector)
        else:
            items = (status(sources, runner, args.sample_seconds) if args.command == "status"
                     else check(sources, runner))
            if args.command == 'check' and args.history:
                from .preservation import assess
                items.extend(assess(sources, runner))
            data = report(args.command, items)
        if args.json:
            print(json.dumps(data, ensure_ascii=True, allow_nan=False), file=stdout)
        elif args.command in {'network', 'security'}:
            print("Faultlens — read-only " + args.command + ": " + data['state'], file=stdout)
            print("Namespace: current; attack assessment Unknown; completeness unknown.", file=stdout)
            print("Sample: " + json.dumps(data['sample'], ensure_ascii=True), file=stdout)
            if "sockets" in data:
                print("Sockets: " + json.dumps(data["sockets"], ensure_ascii=True), file=stdout)
            for observation in data['observations']:
                print(safe_text(observation['key'] + ": " + json.dumps(observation['value'], ensure_ascii=True)), file=stdout)
                if observation['state'] == 'unavailable':
                    print("  Unavailable: " + observation['explanation'], file=stdout)
            for finding in data['findings']:
                print("[WARNING] " + finding['title'] + "; Confirmed counter growth; attack Unknown.", file=stdout)
                print("  Evidence: " + json.dumps(finding['evidence'], ensure_ascii=True), file=stdout)
                print("  Reasoning: " + finding['reasoning'], file=stdout)
                print("  Thresholds: " + json.dumps(finding['thresholds'], ensure_ascii=True), file=stdout)
                for text in finding['limitations'] + finding['recommendations']:
                    print("  " + text, file=stdout)
            for text in data['limitations']:
                print("Limitation: " + text, file=stdout)
        elif args.command == "incidents":
            render_incidents(data, stdout)
        elif args.command in {"history", "diagnose"}:
            render_history(data, stdout)
        else:
            print("Faultlens " + __version__ + " — read-only " + args.command, file=stdout)
            for item in items:
                value = (("unavailable" if item.state == "unavailable" else "unknown")
                         if item.value is None else json.dumps(item.value, ensure_ascii=True))
                print(safe_text(f"[{item.state.upper()}] {item.key}: {value} {item.unit}"), file=stdout)
                print(safe_text(f"  Source: {item.source}. {item.explanation}"), file=stdout)
                for limitation in item.limitations:
                    print(safe_text("  Limitation: " + limitation), file=stdout)
                for recommendation in item.recommendations:
                    print(safe_text("  Recommendation: " + recommendation), file=stdout)
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
