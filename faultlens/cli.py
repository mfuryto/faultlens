"""CLI presentation only; collectors never write reports or configuration."""
import argparse
import json
import math
import sys
import unicodedata

from . import __version__
from .collectors import check, status
from .models import report, Observation


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


def service_unit(value):
    from .commands import validate_service_unit
    try: return validate_service_unit(value)
    except ValueError as exc: raise argparse.ArgumentTypeError(str(exc)) from exc


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


def incident_time(value):
    from .time_window import parse
    try: return parse(value)
    except ValueError as exc: raise argparse.ArgumentTypeError(str(exc)) from exc


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
            print("  Thresholds: " + json.dumps(finding['thresholds'], ensure_ascii=True), file=stdout)
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
        security = data.get('security_analysis')
        if security and security['state'] != 'not_requested':
            print('Security indicators: ' + security['state'] + '; attack/cause Unknown.', file=stdout)
            print('  Sources: ' + json.dumps(security['sources'], ensure_ascii=True), file=stdout)
            print('  Historical comparison: ' + json.dumps(security['historical_comparison'], ensure_ascii=True), file=stdout)
            print(f"  Matching indicators: {security['matching_indicators']}; findings truncated: {security['findings_truncated']}.", file=stdout)
            for finding in security['findings']:
                print('  [' + finding['rule_id'] + '] ' + finding['title'] + ' (Possible; cause Unknown)', file=stdout)
                print('    Observation: ' + finding['observation'], file=stdout)
                print('    Evidence: ' + json.dumps(finding['evidence'], ensure_ascii=True, allow_nan=False), file=stdout)
                print('    Reasoning: ' + finding['reasoning'], file=stdout)
                print('    Thresholds: ' + json.dumps(finding['thresholds'], ensure_ascii=True), file=stdout)
            for text in security['limitations']:
                print('  Limitation: ' + text, file=stdout)
            for text in security['recommendations']:
                print('  Recommendation: ' + text, file=stdout)
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
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ['tui']
    parser = SafeArgumentParser(prog="faultlens", description="Local read-only Linux diagnostics. With no arguments, open the terminal workspace; use explicit commands for scripts.")
    parser.add_argument("--version", action="version", version="Faultlens " + __version__)
    parser.add_argument("command", nargs="?", choices=("status", "check", "history", "diagnose", "incidents", "network", "security", "tui", "health", "investigate", "service", "ssh", "firewall", "ports"), default="status")
    parser.add_argument("--window",choices=("boot","hour","day","period"),help="SSH/firewall log window: boot/hour/day/period; firewall defaults to day, ssh to boot.")
    parser.add_argument('--unit',type=service_unit,help='One literal system .service name to investigate with service; current-boot system logs, no elevation.')
    parser.add_argument("--details", action="store_true", help="Show technical measurements, references and source limitations.")
    parser.add_argument("--json", action="store_true", help="Emit structured observations to stdout only.")
    parser.add_argument("--sockets", action="store_true", help="Include current TCP/UDP endpoints with network/security; no remote probes (investigate: now mode only).")
    parser.add_argument("--sample-seconds", type=interval, default=0.1, help="Sample duration (0.05–1; status/health/network/security or initial TUI setting).")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--previous-boot", action="store_true", help="Analyze the previous visible boot (investigate/diagnose).")
    scope.add_argument("--boot", type=boot_index, help="Visible boot index from -128 to 0 (investigate/diagnose).")
    scope.add_argument("--boot-id", type=boot_identity, help="Optional immutable boot filter with investigate/ssh; selected visible ID with diagnose.")
    parser.add_argument('--mode',choices=('now','period','before-restart'),help='Primary investigate entry; defaults to now, or period when time boundaries are supplied.')
    parser.add_argument("--atop-date", type=atop_date, help="Opt-in local atop_YYYYMMDD recording (investigate/diagnose).")
    parser.add_argument("--atop-extended", action="store_true", help="Opt in to disk, network and process resource rows; requires --atop-date with investigate/diagnose.")
    parser.add_argument("--history", action="store_true", help="Inspect preservation configuration and metadata (check only).")
    parser.add_argument("--pstore", action="store_true", help="Inspect bounded live pstore crash records (investigate/diagnose; no boot attribution).")
    parser.add_argument("--pstore-archive", action="store_true", help="Inspect bounded raw systemd pstore archive records (investigate/diagnose; no boot attribution).")
    parser.add_argument("--network-context",action="store_true",help="Read local addresses/routes, three counter intervals and permitted socket owners; network/security or investigate now only.")
    parser.add_argument("--system-journal", action="store_true", help="Select accessible system journal for both boot listing and diagnosis (history/incidents/investigate/diagnose; no elevation).")
    event_options=parser.add_mutually_exclusive_group()
    event_options.add_argument('--search-events',action='store_true',help='Run bounded kernel/service searches; on by default for investigate.')
    event_options.add_argument('--no-search-events',action='store_true',help='Disable broader kernel/service searches with investigate.')
    parser.add_argument("--search-ssh", action="store_true", help="Inspect supported SSH authentication reports and failure-burst indicators in the selected inquiry/time scope (investigate/diagnose).")
    start=parser.add_mutually_exclusive_group()
    start.add_argument('--since',dest='since_us',type=incident_time,help='Inclusive journal start with explicit timezone, e.g. 2026-11-14T22:20:00Z (investigate/diagnose/ssh).')
    start.add_argument('--since-us',type=receipt_boundary,help='Inclusive start in Unix receipt-time microseconds for all requested journal searches (investigate/diagnose/ssh).')
    end=parser.add_mutually_exclusive_group()
    end.add_argument('--until',dest='until_us',type=incident_time,help='Inclusive journal end with explicit timezone (investigate/diagnose/ssh).')
    end.add_argument('--until-us',type=receipt_boundary,help='Inclusive end in Unix receipt-time microseconds for all requested journal searches (investigate/diagnose/ssh).')
    parser.add_argument("--boot-count", type=overview_count, help="Summarize 1–7 newest visible previous boots (incidents only; default 3).")
    parser.add_argument("--include-current", action="store_true", help="Include the current visible boot in incidents selection.")
    parser.add_argument("--show-evidence", action="store_true", help="Show retained original evidence locally (investigate/diagnose/service/ssh).")
    parser.add_argument("--search-firewall", action="store_true", help="Inspect supported kernel firewall reports and bounded packet-pattern indicators (investigate/diagnose).")
    args = parser.parse_args(argv)
    if args.window is not None and args.command not in {'ssh','firewall'}:parser.error('--window is supported only with ssh or firewall.')
    if args.command in {'ssh','firewall'}:
        args.window=args.window or ('period' if args.since_us is not None or args.until_us is not None else 'day' if args.command=='firewall' else 'boot')
        if args.previous_boot or args.boot is not None:parser.error('SSH/firewall log queries accept an immutable --boot-id, not relative boot selection.')
        if args.window=='period' and (args.since_us is None or args.until_us is None):parser.error('SSH/firewall period requires both time boundaries.')
        if args.window!='period' and (args.since_us is not None or args.until_us is not None):parser.error('SSH/firewall time boundaries require period window.')
        if args.atop_date is not None:parser.error('Atop recordings are not part of SSH/firewall queries.')
    if (args.command=='service')!=(args.unit is not None): parser.error('Use service --unit NAME.service to investigate one service.')
    if args.network_context and not (args.command in {'network','security'} or args.command=='investigate' and args.mode in {None,'now'}):
        parser.error('--network-context requires network, security or investigate now.')
    if args.no_search_events and args.command!='investigate': parser.error('--no-search-events is supported only with investigate.')
    if args.mode is not None and args.command!='investigate': parser.error('--mode is supported only with investigate.')
    if args.command=='investigate':
        args.mode=args.mode or ('before-restart' if args.previous_boot else 'period' if args.since_us is not None or args.until_us is not None else 'now')
        if args.network_context and args.mode!='now':parser.error('Current network context requires now mode.')
        if args.sockets and args.mode!='now': parser.error('Current socket snapshots require now mode.')
        if args.previous_boot and args.mode!='before-restart': parser.error('--previous-boot requires before-restart mode.')
        if args.mode=='period' and (args.since_us is None or args.until_us is None): parser.error('Period mode requires both --since and --until.')
        if args.mode!='period' and (args.since_us is not None or args.until_us is not None): parser.error('Time boundaries require period mode.')
    if args.command == "tui" and (args.json or args.details):
        parser.error("TUI has its own explanation and evidence views; use explicit CLI commands for JSON/details.")
    if args.search_firewall and args.command not in {'diagnose','investigate'}:
        parser.error("Firewall journal analysis is supported only with diagnose.")
    if args.show_evidence and args.command not in {'diagnose','investigate','service','ssh','firewall','ports'}:
        parser.error("Original journal evidence is supported only with investigate, diagnose, service, ssh, firewall or ports.")
    if args.search_ssh and args.command not in {'diagnose','investigate'}:
        parser.error("SSH journal analysis is supported only with diagnose.")
    if args.atop_extended and (args.command not in {'diagnose','investigate'} or args.atop_date is None):
        parser.error("Extended resource context requires diagnose with --atop-date.")
    if (args.boot_count is not None or args.include_current) and args.command != "incidents":
        parser.error("Overview selection is supported only with incidents.")
    if args.since_us is not None and args.until_us is not None and args.since_us > args.until_us:
        parser.error("Journal start boundary must not exceed the end boundary.")
    if args.since_us is not None and args.command not in {"diagnose","investigate","ssh","firewall"}:
        parser.error("Journal time boundaries are supported only with investigate, diagnose, ssh or firewall.")
    if args.until_us is not None and args.command not in {"diagnose","investigate","ssh","firewall"}:
        parser.error("Journal time boundaries are supported only with investigate, diagnose, ssh or firewall.")
    if args.search_events and args.command not in {"diagnose","investigate"}:
        parser.error("Targeted event search is supported only with diagnose.")
    if args.system_journal and args.command not in {"history", "diagnose", "incidents", "investigate", "ssh", "firewall"}:
        parser.error("System journal scope is supported only with history, diagnose, incidents, investigate, ssh or firewall.")
    if args.pstore_archive and args.command not in {"diagnose","investigate"}:
        parser.error("Pstore archive analysis is supported only with diagnose.")
    if args.pstore and args.command not in {"diagnose","investigate"}:
        parser.error("Pstore analysis is supported only with diagnose.")
    if args.history and args.command not in {"check", "health"}:
        parser.error("Preservation assessment is supported only with check or health.")
    if args.command not in {"diagnose","investigate","ssh","firewall"} and (args.previous_boot or args.boot is not None or args.boot_id is not None or args.atop_date is not None):
        parser.error("Boot selection is supported only with diagnose.")
    if args.sockets and args.command not in {"network", "security", "investigate"}:
        parser.error("Socket collection is supported only with network or security.")
    if (platform or sys.platform) != "linux":
        print("Faultlens supports Linux only.", file=stderr)
        return 1
    try:
        if args.command == 'tui':
            from .tui import run
            return run(sources=sources, runner=runner, sample_seconds=args.sample_seconds, stderr=stderr,
                       pstore_collector=pstore_collector, pstore_archive_collector=pstore_archive_collector)
        if args.command=='ports':
            from .ports import collect
            data=collect(runner)
        elif args.command=='firewall':
            from .firewall_state import collect
            data=collect(runner,sources=sources,window=args.window,since_us=args.since_us,until_us=args.until_us,
                boot_id=args.boot_id,system_journal=args.system_journal)
        elif args.command=='ssh':
            from .ssh_statistics import collect
            data=collect(runner,sources=sources,window=args.window,since_us=args.since_us,until_us=args.until_us,
                boot_id=args.boot_id,system_journal=args.system_journal)
        elif args.command=='service':
            from .service import collect
            data=collect(args.unit,runner)
        elif args.command=='investigate':
            from .workflows import collect
            data=collect(runner,sources=sources,mode=args.mode,boot_index=args.boot,boot_id=args.boot_id,
                since_us=args.since_us,until_us=args.until_us,system_journal=args.system_journal,
                search_events=not args.no_search_events,search_ssh=args.search_ssh,search_firewall=args.search_firewall,
                sample_seconds=args.sample_seconds,sockets=args.sockets,network_context=args.network_context,atop_date=args.atop_date,
                atop_extended=args.atop_extended,pstore=args.pstore,pstore_archive=args.pstore_archive,
                pstore_collector=pstore_collector,pstore_archive_collector=pstore_archive_collector)
        elif args.command in {'network', 'security'}:
            from .network import collect
            if args.network_context:
                from .network_sampling import practical
                data=practical(sources,runner,command=args.command,sample_seconds=args.sample_seconds,sockets=args.sockets)
            else:data = collect(sources, command=args.command, sample_seconds=args.sample_seconds)
            if args.sockets and not args.network_context:
                from .sockets import attach
                attach(data, runner)
            if not args.network_context:
                from .network_review import live
                live(data)
        elif args.command == "incidents":
            from .overview import incidents
            data = incidents(runner, boot_count=args.boot_count if args.boot_count is not None else 3,
                             system_journal=args.system_journal, include_current=args.include_current)
        elif args.command in {"history", "diagnose"}:
            from .incidents import history, diagnose
            data = (history(runner, system_journal=args.system_journal) if args.command == "history" else
                    diagnose(runner, args.boot, args.atop_date, system_journal=args.system_journal, search_events=args.search_events, boot_id=args.boot_id, until_us=args.until_us, since_us=args.since_us, atop_extended=args.atop_extended, search_ssh=args.search_ssh, show_evidence=args.show_evidence or (not args.json and not args.details), search_firewall=args.search_firewall))
            if args.command == "diagnose" and args.pstore:
                from .pstore import analyze
                data["pstore"] = analyze(pstore_collector)
            if args.command == "diagnose" and args.pstore_archive:
                from .pstore_archive import analyze as analyze_archive
                data["pstore_archive"] = analyze_archive(pstore_archive_collector)
        elif args.command=='health':
            from .health import collect
            data=collect(sources,runner,sample_seconds=args.sample_seconds,preservation=args.history)
        else:
            items = (status(sources, runner, args.sample_seconds) if args.command == "status"
                     else check(sources, runner))
            if args.command in {'check', 'health'} and args.history:
                from .preservation import assess
                items.extend(assess(sources, runner))
            data = report(args.command, items)
            if args.command=='status':
                from .sessions import attach as attach_sessions
                attach_sessions(data,runner)
                from .system_resources import attach as attach_resources
                attach_resources(data,runner,args.sample_seconds)
        if args.json:
            print(json.dumps(data, ensure_ascii=True, allow_nan=False), file=stdout)
        elif args.command=='ports':
            from .port_presentation import render
            render(data,stdout,details=args.details,evidence=args.show_evidence)
        elif args.command=='firewall':
            from .firewall_presentation import render
            render(data,stdout,details=args.details,evidence=args.show_evidence)
        elif args.command=='ssh':
            from .ssh_presentation import render
            render(data,stdout,details=args.details,evidence=args.show_evidence)
        elif args.command=='service':
            from .service import render
            render(data,stdout,details=args.details)
        elif not (args.details or args.show_evidence):
            from .presentation import render
            render(data,stdout)
        elif args.command in {'network', 'security'}:
            print("Faultlens — read-only " + args.command + ": " + data['state'], file=stdout)
            print("Namespace: current; attack assessment Unknown; completeness unknown.", file=stdout)
            print("Sample: " + json.dumps(data['sample'], ensure_ascii=True), file=stdout)
            for key in ("network_samples","network_context","network_review"):
                if key in data:print(key+": "+json.dumps(data[key],ensure_ascii=True),file=stdout)
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
        elif args.command=="investigate":
            print(json.dumps(data,ensure_ascii=True,allow_nan=False,indent=2),file=stdout)
        elif args.command in {"history", "diagnose"}:
            render_history(data, stdout)
        else:
            print("Faultlens " + __version__ + " — read-only " + args.command, file=stdout)
            if args.command=='health': items=[Observation(**item) for item in data['observations']]
            for item in items:
                value = (("unavailable" if item.state == "unavailable" else "unknown")
                         if item.value is None else json.dumps(item.value, ensure_ascii=True))
                print(safe_text(f"[{item.state.upper()}] {item.key}: {value} {item.unit}"), file=stdout)
                print(safe_text(f"  Source: {item.source}. {item.explanation}"), file=stdout)
                print("  Confidence: " + item.confidence + "; thresholds: " + json.dumps(item.thresholds, ensure_ascii=True), file=stdout)
                for limitation in item.limitations:
                    print(safe_text("  Limitation: " + limitation), file=stdout)
                for recommendation in item.recommendations:
                    print(safe_text("  Recommendation: " + recommendation), file=stdout)
            if 'login_sessions' in data:
                print('Reported login sessions: '+json.dumps(data['login_sessions'],ensure_ascii=True),file=stdout)
            if 'failed_services' in data:
                print('Failed-service source: '+json.dumps(data['failed_services'],ensure_ascii=True),file=stdout)
            for key in ('processes','filesystems'):
                if key in data:print(key.capitalize()+' source: '+json.dumps(data[key],ensure_ascii=True,allow_nan=False),file=stdout)
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
