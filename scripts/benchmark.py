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
    from tests.support import SyntheticHistoricalRunner, SyntheticSources, SyntheticStallRunner, SyntheticClockRunner, SyntheticSystemRunner, SyntheticEventRunner, SyntheticReviewRunner, SyntheticOverlayRunner, SyntheticJournalLossRunner, SyntheticOverviewRunner, SyntheticExtendedRunner, SyntheticMaximumExtendedRunner, SyntheticNetworkSources, SyntheticSshRunner, SyntheticFirewallRunner, SyntheticSocketRunner, SyntheticPhase3Runner
    output = io.StringIO()
    started = time.monotonic()
    if command in {'firewall-state','tui-firewall'}:
        from faultlens.firewall_state import collect
        from faultlens.firewall_presentation import render
        from tests.firewall_state_fixtures import Runner,START
        data=collect(Runner(maximum=True),window='period',since_us=START,until_us=START+86400000000)
        if len(data['sources']['nftables']['data']['rules'])!=256 or not data['correspondences'][0]['matches']:
            raise RuntimeError('Synthetic firewall evidence was not retained')
        render(data,output)
        if command=='tui-firewall':
            import asyncio
            from faultlens.textual_app import FaultlensApp,FirewallDialog,SourceDialog
            async def collector(**options):return data
            async def exercise():
                app=FaultlensApp(initial_collect=False,firewall_collector=collector)
                async with app.run_test(size=(100,30)) as pilot:
                    await pilot.pause(.01);app.push_screen(FirewallDialog());dialog=app.screen
                    async with asyncio.timeout(3):
                        while dialog.report is None:await pilot.pause(.01)
                    await pilot.click('#firewall-bans');await pilot.press('enter');await pilot.click('#firewall-matches')
                    if not isinstance(app.screen,SourceDialog) or not app.screen.entries:
                        raise RuntimeError('Firewall correspondence did not open original rules')
            asyncio.run(exercise())
        usage=resource.getrusage(resource.RUSAGE_SELF)
        return {'collection_wall_seconds':time.monotonic()-started,
            'cpu_seconds':usage.ru_utime+usage.ru_stime,'peak_rss_mib':usage.ru_maxrss/1024}
    if command in {'ssh-statistics','tui-ssh'}:
        from faultlens.ssh_statistics import collect
        from faultlens.ssh_presentation import render
        from tests.ssh_statistics_fixtures import Runner,rows,START
        data=collect(Runner(rows(2000)),window='period',since_us=START,until_us=START+86400000000)
        if data['scan_state']!='exhausted' or data['totals']['failed']!=2000 or len(data['records'])!=2000:
            raise RuntimeError('Synthetic paged SSH aggregation failed')
        render(data,output,details=True)
        if command=='tui-ssh':
            import asyncio
            from faultlens.textual_app import FaultlensApp,SshStatisticsDialog,RecordsDialog
            async def collector(**options):return data
            async def exercise():
                app=FaultlensApp(initial_collect=False,ssh_collector=collector)
                async with app.run_test(size=(100,30)) as pilot:
                    await pilot.pause(.01);app.push_screen(SshStatisticsDialog());dialog=app.screen
                    async with asyncio.timeout(3):
                        while dialog.report is None:await pilot.pause(.01)
                    await pilot.click('#ssh-users');await pilot.press('enter')
                    if not isinstance(app.screen,RecordsDialog) or len(app.screen.records)!=2000:
                        raise RuntimeError('SSH workspace original group did not open')
            asyncio.run(exercise())
        usage=resource.getrusage(resource.RUSAGE_SELF)
        return {'collection_wall_seconds':time.monotonic()-started,
            'cpu_seconds':usage.ru_utime+usage.ru_stime,'peak_rss_mib':usage.ru_maxrss/1024}
    if command in {'tui-status', 'tui-diagnostic','tui-health'}:
        import asyncio
        from faultlens.tui_model import Session
        from tests.support import SyntheticHealthRunner
        from faultlens.textual_app import FaultlensApp
        session=Session(sources=SyntheticNetworkSources(),runner=SyntheticHealthRunner() if command=='tui-health' else SyntheticPhase3Runner(),
            pstore_collector=SyntheticSources().pstore_snapshot,pstore_archive_collector=SyntheticSources().pstore_snapshot)
        page=5 if command=='tui-diagnostic' else 1 if command=='tui-health' else 0
        session.choose_page(page)
        if page==5:
            for key in ('search_ssh','search_firewall','pstore','pstore_archive'): session.update_setting(key)
            session.update_setting('atop_date','20260101'); session.update_setting('atop_extended')
        if command=='tui-status': session.runner.maximum_system_resources=True
        session.refresh()
        app=FaultlensApp(session=session,initial_collect=False); app.snapshots[page]=session.data
        async def exercise():
            async with app.run_test(size=(100,30)) as pilot:
                await pilot.pause(0.01)
                app.select_page(page)
                await pilot.pause(0.01)
                if app.page!=page: raise RuntimeError('Workspace section did not activate')
                if command=='tui-status':
                    from textual.widgets import DataTable
                    app.query_one('#grid-0',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[0]) if row.kind=='processes'))
                if command=='tui-health':
                    from textual.widgets import DataTable
                    app.query_one('#grid-1',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[1]) if row.kind=='failed_services'))
                if command=='tui-diagnostic':
                    from textual.widgets import DataTable
                    app.query_one('#grid-5',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[5]) if row.kind=='finding'))
                app.action_open()
                await pilot.pause(0.01)
                if len(app.screen_stack)!=2: raise RuntimeError('Workspace did not open the selected record')
                if command=='tui-diagnostic':
                    await pilot.click('#references')
                    from faultlens.textual_app import RecordsDialog
                    if not isinstance(app.screen,RecordsDialog): raise RuntimeError('Readable source evidence did not open')
                    if not app.screen.records: raise RuntimeError('Original diagnostic records were not linked')
                    await pilot.press('escape')
                await pilot.press('escape')
        asyncio.run(exercise())
        usage=resource.getrusage(resource.RUSAGE_SELF)
        return {'collection_wall_seconds':time.monotonic()-started,
                'cpu_seconds':usage.ru_utime+usage.ru_stime,'peak_rss_mib':usage.ru_maxrss/1024}
    arguments = ['diagnose', '--atop-date', '20260101', '--json'] if command == 'diagnose-atop' else [command, '--json']
    if command in {'diagnose-stalls', 'diagnose-clock', 'diagnose-overlay', 'diagnose-journal-loss'}:
        arguments = ['diagnose', '--json']
    if command in {'diagnose-events', 'diagnose-review', 'diagnose-integrated'}:
        arguments = ['diagnose', '--system-journal', '--search-events', '--json']
    if command == 'phase3-security':
        arguments = ['diagnose', '--search-ssh', '--search-firewall', '--atop-date', '20260101', '--atop-extended', '--json']
    if command == 'diagnose-firewall':
        arguments = ['diagnose', '--system-journal', '--search-events', '--search-ssh', '--search-firewall', '--show-evidence', '--json']
    if command == 'diagnose-ssh':
        arguments = ['diagnose', '--system-journal', '--search-events', '--search-ssh', '--show-evidence', '--json']
    if command == 'diagnose-extended':
        arguments = ['diagnose', '--atop-date', '20260101', '--atop-extended', '--json']
    if command == 'diagnose-integrated':
        arguments.extend(['--boot-id', 'a' * 32, '--since-us', '1767225600000000',
                          '--until-us', '1767225600000500', '--atop-date', '20260101',
                          '--atop-extended', '--pstore', '--pstore-archive'])
    if command == 'incidents':
        arguments = ['incidents', '--boot-count', '7', '--json']
    if command == 'diagnose-system':
        arguments = ['diagnose', '--system-journal', '--boot-id', 'a' * 32, '--since-us', '1767225600000000', '--until-us', '1767225600000500', '--json']
    if command == 'check-history':
        arguments = ['check', '--history', '--json']
    if command == 'diagnose-pstore-archive':
        arguments = ['diagnose', '--pstore-archive', '--json']
    if command == 'diagnose-pstore':
        arguments = ['diagnose', '--pstore', '--json']
    runner = (SyntheticFirewallRunner() if command == 'diagnose-firewall' else
              SyntheticSshRunner() if command == 'diagnose-ssh' else
              SyntheticMaximumExtendedRunner() if command == 'diagnose-extended' else
              SyntheticExtendedRunner() if command == 'diagnose-integrated' else
              SyntheticOverviewRunner() if command == 'incidents' else
              SyntheticJournalLossRunner() if command == 'diagnose-journal-loss' else
              SyntheticOverlayRunner() if command == 'diagnose-overlay' else
              SyntheticReviewRunner() if command == 'diagnose-review' else
              SyntheticEventRunner() if command in {'diagnose-events', 'diagnose-integrated'} else
              SyntheticSystemRunner() if command == 'diagnose-system' else
              SyntheticClockRunner() if command == 'diagnose-clock' else
              SyntheticStallRunner() if command == 'diagnose-stalls' else SyntheticHistoricalRunner())
    if command == 'phase3-security':
        runner = SyntheticPhase3Runner()
    if command in {'network', 'security', 'network-sockets'}:
        arguments.extend(['--sample-seconds', '0.05'])
    if command == 'network-sockets':
        arguments = ['network', '--sockets', '--network-context', '--sample-seconds', '0.05', '--json']
        runner = SyntheticSocketRunner()
    sources = SyntheticNetworkSources() if command in {'network', 'security', 'network-sockets'} else SyntheticSources()
    if command=='health':
        from tests.support import SyntheticHealthRunner
        runner=SyntheticHealthRunner()
    if command=='status': runner.maximum_system_resources=True
    code = main(arguments, sources=sources, runner=runner, stdout=output,
                pstore_collector=SyntheticSources().pstore_snapshot,
                pstore_archive_collector=SyntheticSources().pstore_snapshot)
    payload = json.loads(output.getvalue())
    if code != 0 or payload.get('state') == 'unavailable' or not (payload.get('observations') or payload.get('boots')):
        raise RuntimeError('Synthetic collection failed')
    if command=='status' and (len(payload['processes']['rows'])!=512 or len(payload['filesystems']['rows'])!=256):
        raise RuntimeError('Maximum synthetic process/filesystem coverage failed')
    if command in {'network', 'security', 'network-sockets'}:
        if (len(payload['observations'][0]['value']) != 128 or len(payload['findings']) != 3
                or payload['attack_assessment'] != 'Unknown'):
            raise RuntimeError('Synthetic network/security sampling failed')
    if command == 'phase3-security':
        analysis = payload['security_analysis']
        if analysis['state'] != 'available' or len(analysis['findings']) != 32 or not analysis['findings_truncated']:
            raise RuntimeError('Integrated security analysis failed')
    if command == 'network-sockets' and len(payload['sockets']['rows']) != 512:
        raise RuntimeError('Synthetic socket snapshot failed')
    if command=='network-sockets':
        from faultlens.presentation import render
        from faultlens.workspace import page_table
        from faultlens.tui_model import Settings
        render(payload,io.StringIO())
        columns,rows=page_table(2,payload,Settings())
        if not rows: raise RuntimeError('Network workspace table is empty')
    if command=='diagnose-atop':
        from faultlens.presentation import render
        render(payload,io.StringIO())
    if command in {'diagnose-pstore', 'diagnose-pstore-archive'}:
        key = 'pstore_archive' if command == 'diagnose-pstore-archive' else 'pstore'
        if (payload[key]['state'] != 'available' or len(payload[key]['records']) != 8
                or payload[key]['records'][0]['relative_path'] != 'dmesg-ramoops-0'
                or not payload[key]['records'][0]['content']['value']):
            raise RuntimeError('Synthetic pstore analysis failed')
    if command == 'incidents':
        if (len(payload['summaries']) != 7 or any(
                value['finding_count'] != 500 or not value['record_limit_reached']
                for value in payload['summaries'])):
            raise RuntimeError('Synthetic multi-boot overview failed')
    if command == 'diagnose-stalls':
        if len(payload['findings']) != 500 or {item['rule_id'] for item in payload['findings']} != {
                'kernel.soft_lockup', 'kernel.hard_lockup', 'kernel.hung_task'}:
            raise RuntimeError('Synthetic stall analysis failed')
    if command == 'diagnose-integrated':
        if (any(payload[key]['state'] != 'available' for key in ('atop', 'pstore', 'pstore_archive', 'event_search'))
                or payload['root_cause'] != 'Unknown' or len(payload['findings']) != 500
                or payload['atop']['samples'][0]['extended']['state'] != 'available'):
            raise RuntimeError('Synthetic integrated historical diagnosis failed')
    if command == 'diagnose-firewall':
        value = payload['firewall_analysis']
        if (len(value['findings']) != 500 or len(value['records']) != 500
                or not value['record_limit_reached'] or value['packet_verdict'] != 'Unknown'
                or len(payload['ssh_analysis']['records']) != 500):
            raise RuntimeError('Synthetic firewall/admin evidence failed')
    if command == 'diagnose-ssh':
        ssh = payload['ssh_analysis']
        if (len(ssh['records']) != 500 or len(ssh['findings']) != 500
                or not ssh['record_limit_reached'] or ssh['attack_assessment'] != 'Unknown'
                or len(payload['journal_records']) != 500
                or any(len(value['records']) != 500 for value in payload['event_search']['queries'])):
            raise RuntimeError('Synthetic SSH/admin evidence views failed')
    if command == 'diagnose-extended':
        value = payload['atop']['samples'][0]['extended']
        if (len(value['disks']) != 32 or len(value['interfaces']) != 32
                or value['processes']['reported_processes'] != 256
                or len(value['process_details']) != 256
                or not payload['atop']['samples'][0]['source_records']
                or value['disks'][0]['device'] != 'disk0'
                or value['process_details'][0]['pid'] != 1):
            raise RuntimeError('Synthetic maximum extended resources failed')
    if command == 'diagnose-atop':
        values = payload['atop']['samples']
        if (len(values) != 256 or any(
                [value[key] for key in ('cpu_execution_percent', 'cpu_idle_percent',
                                        'cpu_iowait_percent', 'cpu_steal_percent')]
                != [20, 80, 0, 0] for value in values)):
            raise RuntimeError('Synthetic historical CPU accounting failed')
    if command == 'diagnose-clock':
        clock = payload['reconstruction']['clock_mapping']
        if (len(payload['findings']) != 500 or clock['significant_adjacent_change_count'] != 499
                or len(clock['change_examples']) != 16 or not clock['change_examples_truncated']):
            raise RuntimeError('Synthetic clock reconstruction failed')
    if command == 'diagnose-system':
        scope = payload['journal_scope']
        if scope['requested'] != 'system' or scope['kernel_records_examined'] != 500 or scope['completeness'] != 'unknown' or payload['boot_selection']['method'] != 'id' or payload['journal_window']['until_realtime_us'] != 1767225600000500 or payload['journal_window']['since_realtime_us'] != 1767225600000000:
            raise RuntimeError('Synthetic system journal scope failed')
    if command == 'diagnose-events':
        queries = payload['event_search']['queries']
        if (payload['event_search']['state'] != 'available' or len(payload['findings']) != 500
                or any(query['candidates_examined'] != 500 or len(query['findings']) != 500
                       or not query['record_limit_reached'] for query in queries)):
            raise RuntimeError('Synthetic targeted event search failed')
    if command == 'diagnose-review':
        review = payload['event_search']['queries'][0]['candidate_review']
        if (review['retained_candidates'] != 500 or review['unclassified_candidates'] != 500
                or len(review['unclassified_examples']) != 20 or not review['unclassified_examples_truncated']):
            raise RuntimeError('Synthetic unclassified candidate review failed')
    if command == 'diagnose-journal-loss':
        if (len(payload['findings']) != 500 or not payload['record_limit_reached']
                or {item['rule_id'] for item in payload['findings']} != {
                    'journal.messages_suppressed', 'journal.kernel_messages_missed'}):
            raise RuntimeError('Synthetic journal-driver loss analysis failed')
    if command == 'diagnose-overlay':
        if len(payload['findings']) != 500 or any(item['rule_id'] != 'kernel.overlay_layer_reuse' for item in payload['findings']):
            raise RuntimeError('Synthetic OverlayFS analysis failed')
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {'collection_wall_seconds': time.monotonic() - started,
            'cpu_seconds': usage.ru_utime + usage.ru_stime,
            'peak_rss_mib': usage.ru_maxrss / 1024}


def positive_iterations(value):
    parsed = int(value)
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError('Iterations must be from 1 to 100.')
    return parsed


def main(runtime=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Emit all measurements as JSON for automation.')
    parser.add_argument('--details', action='store_true', help='Show the per-mode measurement table.')
    parser.add_argument('--iterations', type=positive_iterations, default=10)
    parser.add_argument('--worker', choices=('status','health', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss', 'incidents', 'diagnose-integrated', 'diagnose-extended', 'network', 'security', 'diagnose-ssh', 'diagnose-firewall', 'network-sockets', 'phase3-security', 'ssh-statistics', 'tui-ssh', 'firewall-state', 'tui-firewall', 'tui-status', 'tui-diagnostic','tui-health'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux is required for RSS units and the application.')
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    if runtime is None:
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from resource_runtime import prepared
        with prepared() as runtime:
            return main(runtime)
    summary = {'synthetic': True, 'python': sys.version.split()[0], 'iterations': args.iterations, 'commands': {},
               'runtime': {key:value for key,value in runtime.items() if key!='interpreter_options'}}
    passed = True
    for command in ('status','health', 'check', 'history', 'diagnose', 'diagnose-atop', 'check-history', 'diagnose-pstore', 'diagnose-pstore-archive', 'diagnose-stalls', 'diagnose-clock', 'diagnose-system', 'diagnose-events', 'diagnose-review', 'diagnose-overlay', 'diagnose-journal-loss', 'incidents', 'diagnose-integrated', 'diagnose-extended', 'network', 'security', 'diagnose-ssh', 'diagnose-firewall', 'network-sockets', 'phase3-security', 'ssh-statistics', 'tui-ssh', 'firewall-state', 'tui-firewall', 'tui-status', 'tui-diagnostic','tui-health'):
        samples, wall = [], []
        for _ in range(args.iterations):
            started = time.monotonic()
            result = subprocess.run([sys.executable, '-I', *runtime['interpreter_options'], str(Path(__file__).resolve()), '--worker', command],
                                    check=True, capture_output=True, text=True, timeout=10)
            wall.append(time.monotonic() - started)
            samples.append(json.loads(result.stdout))
        values = {'startup_wall_median_seconds': round(statistics.median(wall), 4),
                  'startup_wall_max_seconds': round(max(wall), 4),
                  'cpu_median_seconds': round(statistics.median(s['cpu_seconds'] for s in samples), 4),
                  'cpu_max_seconds': round(max(s['cpu_seconds'] for s in samples), 4),
                  'peak_rss_max_mib': round(max(s['peak_rss_mib'] for s in samples), 2)}
        # Tolerant regression limits, not promised production performance.
        rss_limit=80 if command.startswith('tui-') else 50
        values['rss_budget_mib']=rss_limit
        values['within_regression_budget'] = (values['peak_rss_max_mib'] < rss_limit
                                              and max(s['cpu_seconds'] for s in samples) < 1
                                              and max(wall) < 2)
        passed = passed and values['within_regression_budget']
        summary['commands'][command] = values
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        sys.path.insert(0,str(ROOT))
        from faultlens.test_output import render_benchmark
        render_benchmark(summary,sys.stdout,details=args.details)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
