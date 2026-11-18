"""Optional UserDock-style terminal entrypoint; the CLI never imports Textual."""
import os
from pathlib import Path
import re
import sys


def run(*,sources=None,runner=None,sample_seconds=0.1,stderr=None,
        pstore_collector=None,pstore_archive_collector=None,settings_store=None):
    stderr=stderr or sys.stderr
    if not getattr(sys.stdin,'isatty',lambda:False)() or not getattr(sys.stdout,'isatty',lambda:False)():
        print('TUI requires an interactive input/output terminal. Use status --json for scripts.',file=stderr)
        return 1
    terminal=os.environ.get('TERM','')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}',terminal) or terminal=='dumb':
        print('TUI needs a supported TERM value. Explicit CLI commands remain available.',file=stderr)
        return 1
    # Debug drivers/log destinations must not turn an admin UI into an export channel.
    for key in list(os.environ):
        if key.startswith('TEXTUAL'): os.environ.pop(key,None)
    os.environ.pop('PYTHONASYNCIODEBUG',None)
    try:
        from importlib.metadata import version
        if version('textual')!='8.2.8': raise ImportError('Unreviewed frontend version')
        from .textual_app import FaultlensApp
    except (ImportError,OSError):
        message = ('The bundled frontend is unavailable or unreviewed. Reinstall a verified Faultlens .deb package. Explicit CLI commands remain available.'
                   if Path(__file__).resolve().parents[1] == Path('/usr/share/faultlens') else
                   'The optional frontend requires reviewed Textual 8.2.8. Install requirements-tui.txt in an isolated environment using --require-hashes --only-binary=:all:. The CLI still works.')
        print(message,file=stderr)
        return 1
    from .tui_model import Session,Settings
    session=Session(sources=sources,runner=runner,sample_seconds=sample_seconds,
        pstore_collector=pstore_collector,pstore_archive_collector=pstore_archive_collector)
    session.settings=Settings.administrator_defaults(sample_seconds=sample_seconds)
    collector=None
    injected=sources is not None or runner is not None or pstore_collector is not None or pstore_archive_collector is not None
    settings_status=''
    if not injected or settings_store is not None:
        from .settings_store import SettingsStore
        try:
            settings_store=settings_store or SettingsStore()
            session.settings,settings_status=settings_store.load(session.settings)
        except (OSError,ValueError,RuntimeError):
            settings_store=None; settings_status='Preferences unavailable; changes apply to this session only.'
    if injected:
        # Dependency injection for synthetic acceptance only, never selected by a CLI flag.
        async def collector(page,settings):
            session.settings=settings; session.choose_page(page); session.refresh(); return session.data
    try:
        return FaultlensApp(session=session,collector=collector,settings_store=settings_store,settings_status=settings_status).run() or 0
    except KeyboardInterrupt:
        print('TUI interrupted; terminal restored. No report was saved.',file=stderr)
        return 130
    except Exception:
        print('TUI unavailable; terminal restored. Use explicit CLI commands. No report was saved.',file=stderr)
        return 1
