"""Explicit synthetic investigation walkthrough; no native collection or preferences."""
import argparse
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from faultlens.commands import Command, Result
from faultlens.incidents import diagnose
from faultlens.journal import validate_window
from faultlens.models import report, unavailable
from faultlens.overview import incidents
from faultlens.tui_model import Session, Settings

BANNER='SYNTHETIC DEMO — invented records only; no host collection or saved preferences.'
BOOT='a'*32
EPOCH_US=1767225600000000
SCENARIOS=('oom','no-match','unavailable')


class DemoRunner:
    """An in-memory adapter with no native runner inheritance or fallback."""
    def __init__(self,scenario):
        if scenario not in SCENARIOS: raise ValueError('Unknown synthetic scenario')
        self.scenario=scenario

    def run(self,command):
        if command not in {Command.JOURNAL_BOOTS,Command.JOURNAL_SYSTEM_BOOTS}:
            raise ValueError('Command is not modeled by the synthetic demo')
        return Result('completed','-1 '+BOOT+' synthetic-demo\n',0)

    def rows(self,identity,since_us=None,until_us=None):
        validate_window(since_us,until_us)
        if identity!=BOOT: raise ValueError('Unknown synthetic boot')
        messages=[(0,'Synthetic demo workload heartbeat'),(61,'Synthetic demo final retained heartbeat')]
        if self.scenario=='oom':
            messages.insert(1,(60,'Out of memory: Killed process 42 (synthetic-demo-worker)'))
        return [{'_BOOT_ID':BOOT,'__REALTIME_TIMESTAMP':str(EPOCH_US+seconds*1000000),
                 '__MONOTONIC_TIMESTAMP':str((seconds+1)*1000000),
                 '__CURSOR':'s=synthetic-demo-'+str(seconds),'_TRANSPORT':'kernel',
                 'PRIORITY':'3' if seconds==60 else '6','MESSAGE':message}
                for seconds,message in messages
                if (since_us is None or EPOCH_US+seconds*1000000>=since_us)
                and (until_us is None or EPOCH_US+seconds*1000000<=until_us)]

    def response(self,identity,*,since_us=None,until_us=None,query=None):
        if self.scenario=='unavailable': return Result('completed','',1)
        rows=self.rows(identity,since_us,until_us)
        if query is not None:
            rows=[row for row in rows if query=='kernel_warnings' and row['PRIORITY']=='3']
        return Result('completed','\n'.join(json.dumps(row) for row in rows),0)

    def read_boot(self,identity): return self.response(identity)
    def read_system_boot(self,identity): return self.response(identity)
    def read_boot_window(self,identity,since_us,*,until_us=None,system=False):
        return self.response(identity,since_us=since_us,until_us=until_us)
    def read_boot_until(self,identity,until_us,*,system=False):
        return self.response(identity,until_us=until_us)
    def read_event_candidates(self,identity,query,*,system=False,since_us=None,until_us=None):
        return self.response(identity,since_us=since_us,until_us=until_us,query=query)
    def read_ssh_candidates(self,identity,*,system=False,since_us=None,until_us=None):
        return self.response(identity,since_us=since_us,until_us=until_us,query='ssh')
    def read_firewall_candidates(self,identity,*,system=False,since_us=None,until_us=None):
        return self.response(identity,since_us=since_us,until_us=until_us,query='firewall')
    def read_atop(self,*args): return Result('missing')
    def read_atop_extended(self,*args): return Result('missing')


def build_report(scenario,page,settings):
    runner=DemoRunner(scenario)
    if page==4:
        data=incidents(runner,boot_count=settings.boot_count,system_journal=settings.system_journal,
                       include_current=settings.include_current)
    elif page==5:
        selector=settings.boot_selector
        data=diagnose(runner,None if len(selector)==32 else int(selector),
            settings.atop_date or None,boot_id=selector if len(selector)==32 else None,
            system_journal=settings.system_journal,search_events=settings.search_events,
            search_ssh=settings.search_ssh,search_firewall=settings.search_firewall,
            atop_extended=settings.atop_extended,show_evidence=True,
            since_us=int(settings.since_us) if settings.since_us else None,
            until_us=int(settings.until_us) if settings.until_us else None)
        for enabled,key in ((settings.pstore,'pstore'),(settings.pstore_archive,'pstore_archive')):
            if enabled:
                data[key]={'state':'unavailable','reason':'synthetic_source_not_modeled','records':[],
                           'root_cause':'Unknown','boot_identity':'unverified','source':key,
                           'analysis_state':'unavailable','limitations':[BANNER]}
    elif type(page) is int and 0<=page<4:
        data=report(('status','health','network','security')[page],[unavailable(
            'demo.source','synthetic-demo','This walkthrough models journal investigations only; no host source was queried.')])
        data.update(state='unavailable',reason='synthetic_source_not_modeled')
        if page in {2,3}:
            data.update(sample={'elapsed_seconds':None},findings=[],attack_assessment='Unknown')
    else: raise ValueError('Not a source page')
    data['limitations'].insert(0,BANNER)
    data['synthetic_demo']={'scenario':scenario,'native_collection':False,'preferences_saved':False}
    return data


def make_app(scenario):
    from rich.text import Text
    from textual.widgets import Static
    from faultlens.textual_app import FaultlensApp

    async def collect(page,settings): return build_report(scenario,page,settings)

    class DemoApp(FaultlensApp):
        TITLE='Faultlens — SYNTHETIC DEMO'
        SUB_TITLE='Invented journal investigation'
        CSS=FaultlensApp.CSS+'\n#demo-banner { height: 2; background: $warning; color: $text; }'

        def compose(self):
            yield Static(Text(BANNER),id='demo-banner',markup=False)
            yield from super().compose()

        def start_workspace(self):
            self.workspace_ready=True
            self.select_page(4)

    session=Session();session.settings=Settings(search_events=True)
    app=DemoApp(session=session,collector=collect,settings_store=None,
                settings_status='Synthetic demo: preferences are session-only.')
    app.snapshots[4]=build_report(scenario,4,session.settings)
    app.snapshot_options[4]=asdict(session.settings)
    return app


def main(argv=None):
    parser=argparse.ArgumentParser(description=BANNER)
    parser.add_argument('--scenario',choices=SCENARIOS,default='oom')
    parser.add_argument('--cli',action='store_true',help='Render the synthetic diagnosis as readable CLI output.')
    args=parser.parse_args(argv)
    if args.cli:
        from faultlens.presentation import render
        print(BANNER)
        render(build_report(args.scenario,5,Settings(search_events=True)),sys.stdout)
        return 0
    try: reviewed=version('textual')=='8.2.8'
    except PackageNotFoundError: reviewed=False
    if not reviewed:
        print('The synthetic workspace requires reviewed Textual 8.2.8 from requirements-tui.txt. Use --cli without it.',file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('The synthetic workspace requires an interactive terminal. Use --cli for readable output.',file=sys.stderr)
        return 2
    app=make_app(args.scenario);app.run()
    return app.return_code or 0


if __name__=='__main__': raise SystemExit(main())
