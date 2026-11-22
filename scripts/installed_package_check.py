"""Isolated, non-root installed-package checks; never print native evidence."""
import argparse
import asyncio
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

HOME = Path('/tmp/faultlens-package-operator')
PREFERENCE = HOME/'.config/faultlens/settings.json'
MARKER = HOME/'synthetic-evidence.txt'


def terminal_check(interrupt=False):
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
    process = subprocess.Popen(['/usr/bin/faultlens'],stdin=slave,stdout=slave,stderr=slave,
                               cwd=HOME,env={**os.environ,'TERM':'xterm-256color'})
    output = bytearray()
    try:
        deadline=time.monotonic()+15
        while b'Faultlens' not in output and time.monotonic()<deadline:
            if select.select([master],[],[],0.1)[0]:
                output.extend(os.read(master,65536))
                if len(output)>2097152: raise ValueError('Installed PTY output limit')
        if b'Faultlens' not in output: raise ValueError('Installed primary workspace did not render')
        os.write(master,b'\x1b[C\x1b[D')
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',10,40,0,0))
        process.send_signal(signal.SIGWINCH)
        os.write(master,b'\x03' if interrupt else b'q')
        deadline=time.monotonic()+15
        while process.poll() is None and time.monotonic()<deadline:
            if select.select([master],[],[],0.05)[0]: os.read(master,65536)
        if process.wait(timeout=2)!=(130 if interrupt else 0): raise ValueError('Installed terminal exit failed')
        if termios.tcgetattr(slave)!=before: raise ValueError('Installed terminal was not restored')
    finally:
        if process.poll() is None: process.kill();process.wait()
        os.close(master);os.close(slave)


async def workspace_check():
    from faultlens.textual_app import FaultlensApp
    app=FaultlensApp()
    async with app.run_test(size=(100,30)) as pilot:
        async with asyncio.timeout(20):
            while app.job is not None or app.collection_states.get(0) not in {'completed','failed'}:
                await pilot.pause(0.02)
        if app.collection_states[0]!='completed': raise ValueError('Installed System collector failed')
        from textual.widgets import DataTable
        from faultlens.textual_app import SourceDialog
        for kind in ('processes','filesystems'):
            app.query_one('#grid-0',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[0]) if row.kind==kind))
            app.action_open();await pilot.pause(0.01)
            if not isinstance(app.screen,SourceDialog):raise ValueError('Installed resource source did not open: '+kind)
            await pilot.press('escape')
        app.select_page(2)
        async with asyncio.timeout(20):
            while app.page!=2 or app.job is not None or app.collection_states.get(2) not in {'completed','failed'}:await pilot.pause(.02)
        if app.collection_states[2]!='completed' or 'network_review' not in app.snapshots[2]:raise ValueError('Installed network investigation failed')
        for kind in ('network_issues','network_context','network_samples'):
            app.query_one('#grid-2',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[2]) if row.kind==kind))
            app.action_open();await pilot.pause(.01)
            if not isinstance(app.screen,SourceDialog):raise ValueError('Installed network source did not open: '+kind)
            await pilot.press('escape')
        app.select_page(5)
        async with asyncio.timeout(20):
            while app.page!=5 or app.job is not None or app.collection_states.get(5) not in {'completed','failed'}:
                await pilot.pause(0.02)
        if app.collection_states[5]!='completed' or app.snapshots[5]['command']!='investigate':
            raise ValueError('Installed investigation collector failed')
        inquiry=app.snapshots[5]
        app.select_page(3);await pilot.pause(.02)
        if app.data(3) is not inquiry or app.job is not None or 3 in app.snapshots:raise ValueError('Installed Signals started a separate source')
        app.query_one('#grid-3',DataTable).move_cursor(row=next(i for i,row in enumerate(app.entries[3]) if row.cells[0]=='Source coverage'))
        app.action_evidence();await pilot.pause(.02)
        if app.data(6) is not inquiry or app.evidence_selection is None:raise ValueError('Installed evidence selection lost inquiry context')
        app.select_page(5);await pilot.pause(.02)
        from faultlens.workspace import Entry
        from faultlens.textual_app import ServiceDialog
        app.open_entry(Entry(('systemd-journald.service',),{'unit':'systemd-journald.service'},kind='service'),app.snapshots[5])
        if not isinstance(app.screen,ServiceDialog):raise ValueError('Installed service dialog did not open')
        screen=app.screen
        async with asyncio.timeout(20):
            while screen.report is None:await pilot.pause(0.02)
        if screen.report is None or screen.report.get('command')!='service':
            raise ValueError('Installed service dialog collection failed')
        await pilot.press('escape')


def resource_checks(capture):
    for driver,timeout in (('benchmark',25),('vps_acceptance',30)):
        wrapper=HOME/(driver+'-installed.py')
        wrapper.write_text("""import sys
sys.dont_write_bytecode=True
from pathlib import Path
sys.path[:0]=['/usr/share/faultlens','/usr/share/faultlens/vendor','/source','/source/scripts']
import faultlens
if not str(Path(faultlens.__file__)).startswith('/usr/share/faultlens/faultlens/'):
    raise ValueError('Installed resource probe loaded source application')
if '--worker' not in sys.argv:
    import resource_runtime
    original=resource_runtime.source_files
    resource_runtime.source_files=lambda:sorted(set(original()) | set(Path('/usr/share/faultlens/faultlens').rglob('*.py')))
import """+driver+""" as driver
driver.__file__=__file__
raise SystemExit(driver.main())
""")
        options=['--iterations','2'] if driver=='benchmark' else []
        result=capture([sys.executable,'-I','-B',str(wrapper),*options,'--json'],timeout=timeout,limit=4194304)
        if result.state!='completed' or result.returncode!=0: raise ValueError('Installed resource gate failed: '+driver+' '+result.state)
        data=json.loads(result.stdout)
        if driver=='benchmark':
            if len(data['commands'])!=30 or not all(row['within_regression_budget'] for row in data['commands'].values()):
                raise ValueError('Installed benchmark coverage/budget failed')
        elif len(data['profiles'])!=27 or not data['passed']:
            raise ValueError('Installed constrained resource coverage/budget failed')
        print('PASS installed '+driver+' with unchanged CPU/wall/memory budgets',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('installed','upgraded','removed'))
    phase=parser.parse_args().phase
    if os.geteuid()==0: raise ValueError('Installed checks must run without root')
    status=Path('/proc/self/status').read_text()
    effective=next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
    if int(effective,16)!=0: raise ValueError('Installed application check has capabilities')
    HOME.mkdir(mode=0o700,exist_ok=True)
    if phase=='removed':
        if Path('/usr/bin/faultlens').exists(): raise ValueError('Launcher survived package removal')
        if not PREFERENCE.exists() or json.loads(PREFERENCE.read_text())['settings']['sample_seconds']!=0.2 or MARKER.read_text()!='synthetic local acceptance marker\n':
            raise ValueError('User files changed during removal')
        print('PASS removal preserves user preferences and synthetic evidence')
        return
    standalone=subprocess.run(['/usr/bin/python3','-I','-c','import importlib.util; assert importlib.util.find_spec("textual") is None'],capture_output=True,timeout=10)
    if standalone.returncode!=0: raise ValueError('Private frontend became globally importable')
    sys.path[:0]=['/usr/share/faultlens','/usr/share/faultlens/vendor']
    from importlib.metadata import version
    from faultlens.commands import _capture
    from faultlens.settings_store import SettingsStore
    from faultlens.tui_model import Settings
    from faultlens.presentation import local_command
    if local_command('./bin/faultlens status')!='faultlens status':
        raise ValueError('Installed command guidance uses checkout paths')
    import faultlens, textual
    if not str(Path(faultlens.__file__)).startswith('/usr/share/faultlens/faultlens/'):
        raise ValueError('Source checkout leaked into installed checks')
    if not str(Path(textual.__file__)).startswith('/usr/share/faultlens/vendor/textual/') or version('textual')!='8.2.8':
        raise ValueError('Private frontend not loaded')
    if phase=='installed':
        store=SettingsStore();settings=Settings.administrator_defaults();settings.sample_seconds=0.2
        store.save(settings)
        MARKER.write_text('synthetic local acceptance marker\n')
    settings,_=SettingsStore().load(Settings.administrator_defaults())
    if settings.sample_seconds!=0.2: raise ValueError('Upgrade lost user preferences')
    poison=HOME/'poison';poison.mkdir(exist_ok=True)
    (poison/'faultlens.py').write_text('raise RuntimeError("Untrusted current-directory module")\n')
    # _capture uses a fixed environment/cwd, while this direct probe tests shebang isolation.
    probe=subprocess.run(['/usr/bin/faultlens','--version'],cwd=poison,
                         env={**os.environ,'PYTHONPATH':str(poison)},capture_output=True,text=True,timeout=10)
    if probe.returncode!=0 or not probe.stdout.startswith('Faultlens '): raise ValueError('Installed launcher isolation failed')
    for options in (('status',),('health',),('network','--sockets','--network-context'),('service','--unit','systemd-journald.service'),('history','--system-journal'),
                    ('diagnose','--boot','0','--system-journal'),
                    ('investigate','--mode','period','--since-us','0','--until-us','1','--system-journal'),('ssh','--window','hour','--system-journal')):
        result=_capture(['/usr/bin/faultlens',*options,'--json'],timeout=30,limit=4194304)
        if result.state!='completed' or result.returncode!=0: raise ValueError('Installed CLI check failed: '+options[0])
        data=json.loads(result.stdout)
        if data.get('schema_version')!=1 or data.get('command')!=options[0]: raise ValueError('Installed CLI schema failed')
        if options[0]=='ssh' and (data.get('state') not in {'available','partial','unavailable'}
                or not isinstance(data.get('totals'),dict) or not isinstance(data.get('records'),list)):
            raise ValueError('Installed SSH statistics contract failed')
        if options[0] in {'status','health'} and any(
                data.get(key,{}).get('state') not in {'available','partial','unavailable'}
                or not isinstance(data.get(key,{}).get('rows'),list) for key in ('processes','filesystems')):
            raise ValueError('Installed process/filesystem source contract failed')
        if options[0]=='network' and (len(data.get('network_samples',[]))!=3
                or not isinstance(data.get('network_review',{}).get('cards'),list)
                or any(data.get('network_context',{}).get('sources',{}).get(key,{}).get('state') not in {'available','unavailable'}
                       for key in ('addresses','routes4','routes6','owners'))):
            raise ValueError('Native network investigation contract was not reported')
        if options[0]=='network' and any(data['network_context']['sources'][key]['state']!='available' for key in ('addresses','routes4','routes6','owners')):
            raise ValueError('Qualification ip/ss source formats could not be assessed')
        if options[0]=='service' and (data.get('unit')!='systemd-journald.service' or not isinstance(data.get('journal_records'),list)
                or not isinstance(data.get('assessment'),dict) or not isinstance(data['assessment'].get('code'),str)
                or not isinstance(data.get('invocation_summary'),dict)):
            raise ValueError('Installed service investigation schema failed')
    from faultlens import ui_collection
    if Path(ui_collection.__file__).resolve().parents[1]!=Path('/usr/share/faultlens'):
        raise ValueError('Installed UI backend used source modules')
    resource_checks(_capture)
    asyncio.run(workspace_check())
    terminal_check();terminal_check(True)
    print('PASS '+phase+' Python '+'.'.join(str(value) for value in sys.version_info[:3])+': eight CLI contracts, private frontend, native UI collectors, no-argument PTY/navigation/resize/quit/interrupt, preferences')


if __name__=='__main__':
    main()
