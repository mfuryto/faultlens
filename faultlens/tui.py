"""On-demand curses frontend; collection and navigation stay independent of curses."""
import argparse
import os
import re
import sys

from . import __version__
from .tui_model import PAGES, Session, escaped, row_preview


def viewport_width(screen):
    height,width=screen.getmaxyx()
    return min(240,max(1,width-(24 if width>=90 and height>=15 else 0)-2))


def put(screen, y, x, text, width, attribute=0):
    import curses
    if width <= 0:
        return
    try:
        screen.addnstr(y, x, text, width, attribute)
    except curses.error:
        # Resizing can invalidate coordinates after getmaxyx; redraw on the next key.
        pass


def draw(screen, session):
    import curses
    height, width = screen.getmaxyx()
    screen.erase()
    if height < 8 or width < 30:
        put(screen, 0, 0, 'Resize terminal; q quits.', max(0, width-1))
        screen.refresh()
        return
    sidebar = 24 if width >= 90 and height >= 15 else 0
    content_width = viewport_width(screen)
    put(screen, 0, 0, 'Faultlens ' + __version__ + ' | READ-ONLY | ' + PAGES[session.page], width-1, curses.A_REVERSE)
    if sidebar:
        for i, title in enumerate(PAGES):
            put(screen, i+2, 0, f'{i+1} {title}', sidebar-1,
                curses.A_REVERSE if i == session.page else 0)
    if session.data:
        data = session.data
        state = data.get('state', 'observations; no overall health verdict')
        scope = 'STALE SETTINGS | ' if session.stale else ''
        header = scope + escaped(data['command']) + ' | ' + escaped(state)
    else:
        header = 'No snapshot in memory. Press r on a source page.'
    put(screen, 1, sidebar, header, content_width)
    path = session.stack[-1][1] if session.stack else ('Session-only collection options; Enter edits/toggles; ? explains' if session.page == 7 else 'Enter: inspect | e: inspect boot metadata | r: replace snapshot')
    if session.data and not session.stack and session.page != 7:
        path = 'Collected: ' + escaped(session.data.get('collected_at')) + ' | Enter inspects'
    put(screen, 2, sidebar, path, content_width)
    lines = height-6
    rows = session.rows()
    if session.stack and not isinstance(session.value, (dict, list)):
        text = escaped(session.value)
        total = max(1, (len(text)+content_width-1)//content_width)
        session.scroll = max(0, min(session.scroll, total-1))
        for index in range(lines):
            offset = (session.scroll+index)*content_width
            put(screen, 3+index, sidebar, text[offset:offset+content_width], content_width)
        position = f'Scalar lines {session.scroll+1}-{min(total,session.scroll+lines)}/{total}; lossless JSON escaping'
    else:
        session.selected = max(0, min(session.selected, len(rows)-1))
        top = (session.selected//lines)*lines
        for i, row in enumerate(rows[top:top+lines]):
            preview=row_preview(row)
            label = row.label + ': ' + preview
            put(screen, 3+i, sidebar, label, content_width,
                curses.A_REVERSE if top+i == session.selected else 0)
        position = f'Item {session.selected+1 if rows else 0}/{len(rows)}'
        if not rows:
            put(screen, 3, sidebar, 'No items in this view. r collects on source pages; 7 explores the latest report.', content_width)
    put(screen, height-3, sidebar, position, content_width)
    put(screen, height-2, 0, session.notice, width-1)
    put(screen, height-1, 0, 'q quit | / search n/N next/prev | ? help | 1-8/Tab pages | r refresh | Enter detail | Left back | t timeline', width-1)
    screen.refresh()


def edit(screen, key, value, *, verb='save'):
    """Bounded ASCII input; no command, filename or report export prompt."""
    import curses
    text = str(value)
    while True:
        height, width = screen.getmaxyx()
        put(screen, max(0, height-2), 0, ' ' * max(0, width-1), width-1)
        put(screen, max(0, height-2), 0, key + ' = ' + text + ' [Enter '+verb+', Esc cancel, Ctrl-U clear]', width-1)
        screen.refresh()
        char = screen.get_wch()
        if char in ('\n', '\r', curses.KEY_ENTER):
            return text
        if char == '\x1b':
            return None
        if char in ('\x7f', '\b', curses.KEY_BACKSPACE):
            text = text[:-1]
        elif char == '\x15':
            text = ''
        elif isinstance(char, str) and len(text) < 64 and 32 <= ord(char) <= 126:
            text += char


def handle(screen, session, key):
    """Process one key. False requests orderly terminal restoration and exit."""
    import curses
    if key in ('q', 'Q', '\x04'):
        return False
    if screen.getmaxyx()[0] < 8 or screen.getmaxyx()[1] < 30:
        return True
    if isinstance(key, str) and key in '12345678':
        session.choose_page(int(key)-1)
    elif key in ('\t', curses.KEY_BTAB):
        session.choose_page((session.page + (-1 if key == curses.KEY_BTAB else 1)) % len(PAGES))
    elif key in (curses.KEY_LEFT, curses.KEY_BACKSPACE, '\x7f', '\b', '\x1b'):
        session.back()
    elif key == '?':
        session.help()
    elif key == 't':
        session.timeline()
    elif key == '/':
        text=edit(screen,'Find literal text',session.search_text,verb='find')
        if text is not None: session.find(text,width=viewport_width(screen))
    elif key in ('n','N'):
        session.find(reverse=key=='N',width=viewport_width(screen))
    elif key == 'r':
        session.notice = 'Collecting read-only evidence... Ctrl-C interrupts; optional sources can take several seconds.'
        draw(screen, session)
        try:
            session.refresh()
        except (OSError, ValueError):
            session.notice = 'Collection unavailable. No snapshot saved; review source access and retry explicitly.'
    elif key in ('\n', '\r', curses.KEY_ENTER, 'e'):
        rows = session.rows()
        if rows and rows[min(session.selected, len(rows)-1)].action == 'setting' and key != 'e':
            row = rows[min(session.selected, len(rows)-1)]
            try:
                text = None if type(row.value) is bool else edit(screen, row.label, row.value)
                if type(row.value) is bool or text is not None:
                    session.update_setting(row.key or row.label, text)
            except (ValueError, argparse.ArgumentTypeError):
                session.notice = 'Invalid setting; previous value retained. See the TUI guide for accepted ranges.'
        else:
            session.open_row(inspect_only=key == 'e')
    elif key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_PPAGE, curses.KEY_NPAGE,
                 curses.KEY_HOME, curses.KEY_END, 'j', 'k'):
        leaf = session.stack and not isinstance(session.value, (dict, list))
        step = max(1, screen.getmaxyx()[0]-6) if key in (curses.KEY_PPAGE, curses.KEY_NPAGE) else 1
        if key in (curses.KEY_UP, curses.KEY_PPAGE, 'k'):
            step = -step
        if leaf:
            if key == curses.KEY_HOME:
                session.scroll = 0
            elif key == curses.KEY_END:
                width = viewport_width(screen)
                session.scroll = len(escaped(session.value))//width
            else:
                session.scroll = max(0, session.scroll+step)
        elif key == curses.KEY_HOME:
            session.selected = 0
        elif key == curses.KEY_END:
            session.selected = max(0, len(session.rows())-1)
        else:
            session.selected = max(0, min(session.selected+step, len(session.rows())-1))
    return True


def loop(screen, session):
    import curses
    screen.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    # No timer, automatic refresh, mouse hooks, shell escape or persistent history.
    while True:
        draw(screen, session)
        if not handle(screen, session, screen.get_wch()):
            return 0


def run(*, sources=None, runner=None, sample_seconds=0.1, stderr=None,
        pstore_collector=None, pstore_archive_collector=None):
    stderr = stderr or sys.stderr
    if not getattr(sys.stdin, 'isatty', lambda: False)() or not getattr(sys.stdout, 'isatty', lambda: False)():
        print('TUI requires an interactive input/output terminal. Use status --json for scripts.', file=stderr)
        return 1
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}', os.environ.get('TERM', '')) or os.environ.get('TERM') == 'dumb':
        print('TUI needs a supported TERM value. Explicit CLI commands remain available.', file=stderr)
        return 1
    try:
        import curses
    except ImportError:
        print('Python curses support is unavailable. Install the distribution Python curses component or use the CLI.', file=stderr)
        return 1
    session = Session(sources=sources, runner=runner, sample_seconds=sample_seconds,
                      pstore_collector=pstore_collector, pstore_archive_collector=pstore_archive_collector)
    try:
        return curses.wrapper(loop, session)
    except KeyboardInterrupt:
        print('TUI interrupted; terminal restored. No report was saved.', file=stderr)
        return 130
    except (curses.error, OSError, ValueError):
        print('TUI could not continue; terminal restored. Use explicit CLI commands.', file=stderr)
        return 1
