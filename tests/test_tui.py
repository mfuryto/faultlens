"""Synthetic full-screen navigation, terminal safety and read-only collection."""
import argparse
import contextlib
import io
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
import unittest
from unittest.mock import patch

from faultlens.cli import main
from faultlens.tui_model import PAGES, Session, brief, children, escaped
from tests.support import SyntheticNetworkSources, SyntheticPhase3Runner, SyntheticSources, SyntheticRunner


class Screen:
    def __init__(self, keys=(), size=(24,100)):
        self.keys, self.size, self.writes = iter(keys), size, []
    def getmaxyx(self): return self.size
    def erase(self): self.writes.clear()
    def refresh(self): pass
    def keypad(self, enabled): pass
    def get_wch(self): return next(self.keys)
    def addnstr(self, y, x, text, width, attribute=0):
        if y < 0 or y >= self.size[0] or x < 0 or x+width > self.size[1]:
            raise AssertionError('Out-of-screen write')
        self.writes.append(text[:width])


class SessionTests(unittest.TestCase):
    def session(self):
        return Session(sources=SyntheticNetworkSources(), runner=SyntheticPhase3Runner(),
            pstore_collector=SyntheticSources().pstore_snapshot,
            pstore_archive_collector=SyntheticSources().pstore_snapshot, sample_seconds=0.05)

    def test_pages_collect_independently_and_evidence_settings_do_not_collect(self):
        session = self.session()
        self.assertEqual(8,len(PAGES))
        with patch('socket.socket',side_effect=AssertionError('No traffic')), patch('builtins.open',side_effect=AssertionError('No file writes')):
            for page, command in enumerate(('status','check','network','security','incidents','diagnose')):
                session.choose_page(page)
                session.refresh()
                self.assertEqual(command,session.data['command'])
                self.assertTrue(session.rows())
            previous = session.data
            for page in (6,7):
                session.choose_page(page)
                session.refresh()
                self.assertIs(previous,session.data)

    def test_settings_are_typed_session_only_and_fail_atomically(self):
        session = self.session()
        for key,value in (('boot_selector','a'*32),('sample_seconds','0.2'),('boot_count','7'),
                          ('since_us','100'),('until_us','200'),('atop_date','20260101')):
            session.update_setting(key,value)
        session.update_setting('atop_extended')
        self.assertTrue(session.settings.atop_extended)
        session.update_setting('atop_date','')
        self.assertFalse(session.settings.atop_extended)
        for key,value in (('unknown','x'),('boot_selector',';id'),('boot_selector','1'),
                          ('sample_seconds','nan'),('boot_count','8'),('until_us','99'),
                          ('since_us','-1'),('atop_date','20260230'),('atop_extended',None)):
            previous = session.settings
            with self.assertRaises((ValueError,argparse.ArgumentTypeError)):
                session.update_setting(key,value)
            self.assertIs(previous,session.settings)

    def test_immutable_boot_selection_requires_explicit_diagnosis_refresh(self):
        session = self.session()
        session.choose_page(4)
        session.refresh()
        session.selected = next(i for i,row in enumerate(session.rows()) if row.action == 'boot' and row.value['index'] == -1)
        row = session.rows()[session.selected]
        session.open_row()
        self.assertEqual(5,session.page)
        self.assertEqual(row.value['boot_id'],session.settings.boot_selector)
        self.assertEqual('incidents',session.data['command'])
        session.refresh()
        self.assertEqual(row.value['boot_id'],session.data['selected_boot']['boot_id'])
        self.assertTrue(session.data['journal_records'])

    def test_navigation_preserves_references_and_back_position(self):
        session = self.session()
        session.refresh()
        session.choose_page(6)
        session.selected=1
        session.open_row()
        self.assertIs(session.data,session.value)
        session.open_row()
        session.back()
        self.assertIs(session.data,session.value)
        session.back()
        self.assertEqual(1,session.selected)
        self.assertEqual([],session.stack)
        session.choose_page(5)
        session.refresh()
        session.timeline()
        self.assertIs(session.data['timeline'],session.value)

    def test_stale_scope_is_visible_and_optional_sources_require_settings(self):
        session = self.session()
        session.choose_page(5)
        session.refresh()
        self.assertNotIn('ssh_analysis',session.data)
        self.assertEqual('not_requested',session.data['atop']['state'])
        self.assertFalse(session.stale)
        session.update_setting('search_ssh')
        self.assertTrue(session.stale)
        session.update_setting('search_firewall')
        session.update_setting('atop_date','20260101')
        session.update_setting('atop_extended')
        session.refresh()
        self.assertFalse(session.stale)
        self.assertEqual('available',session.data['security_analysis']['state'])
        session.choose_page(3)
        self.assertEqual('security_analysis',session.rows()[0].label)

    def test_failure_discards_old_references_and_does_not_cache_reports(self):
        session = self.session()
        session.refresh()
        session.choose_page(6)
        session.selected=1
        session.open_row()
        session.choose_page(0)
        with patch('faultlens.tui_model.status',side_effect=OSError('sensitive')):
            with self.assertRaises(OSError): session.refresh()
        self.assertIsNone(session.data)
        self.assertEqual([],session.stack)

    def test_originals_and_terminal_controls_are_losslessly_visible(self):
        value = 'admin\x1b]52;c;payload\x07\u202e\x9b secret\n192.0.2.1:22'
        text = escaped(value)
        self.assertEqual(value,json.loads(text))
        self.assertTrue(text.isascii())
        self.assertFalse(any(ord(c)<32 or ord(c)==127 for c in text))
        self.assertIn('192.0.2.1:22',text)
        long = value*5000
        self.assertLess(len(brief(long)),300)
        self.assertEqual(long,json.loads(escaped(long)))
        self.assertIs(long,children({'original':long})[0].value)


class TerminalTests(unittest.TestCase):
    def test_draw_keys_resize_scalar_paging_and_no_automatic_refresh(self):
        import curses
        from faultlens.tui import draw, handle, loop
        session = Session()
        with patch.object(session,'refresh',side_effect=AssertionError('No polling')), patch('curses.curs_set'):
            self.assertEqual(0,loop(Screen(('2','7','8','\t',curses.KEY_RESIZE,'q')),session))
        session.stack=[('a\x1b\u202e'*10000,'Original evidence',0,0)]
        for size in ((24,100),(10,40),(8,30),(6,20),(1,1)):
            screen=Screen(size=size)
            draw(screen,session)
            self.assertFalse(any('\x1b' in line or '\u202e' in line for line in screen.writes))
        screen=Screen()
        handle(screen,session,curses.KEY_END)
        draw(screen,session)
        self.assertGreater(session.scroll,0)
        handle(screen,session,curses.KEY_HOME)
        self.assertEqual(0,session.scroll)
        self.assertFalse(handle(screen,session,'q'))

    def test_settings_editor_invalid_input_cancel_and_boolean_toggle(self):
        from faultlens.tui import handle
        session=Session()
        session.choose_page(7)
        handle(Screen(('\x15',';','i','d','\n')),session,'\n')
        self.assertEqual('-1',session.settings.boot_selector)
        self.assertIn('Invalid',session.notice)
        handle(Screen(('\x1b',)),session,'\n')
        session.selected=1
        handle(Screen(),session,'\n')
        self.assertTrue(session.settings.system_journal)

    def test_failure_message_cannot_leak_sensitive_source_error(self):
        from faultlens.tui import handle
        session=Session()
        with patch.object(session,'refresh',side_effect=OSError('secret-in-error')):
            handle(Screen(),session,'r')
        self.assertNotIn('secret-in-error',session.notice)
        self.assertIn('unavailable',session.notice)

    def test_cli_tui_dispatch_alias_and_noninteractive_fail_closed(self):
        out=io.StringIO()
        with patch('faultlens.tui.run',return_value=0) as run:
            self.assertEqual(0,main(['tui'],stdout=out))
            run.assert_called_once()
        with patch('sys.stdin.isatty',return_value=True), patch.object(out,'isatty',return_value=True), patch('faultlens.tui.run',return_value=0) as run:
            self.assertEqual(0,main([],stdout=out))
            run.assert_called_once()
        with patch('sys.stdin.isatty',return_value=False):
            self.assertEqual(1,main(['tui'],stderr=io.StringIO()))
        for args in (['tui','--json'],['tui','--system-journal'],['tui','--sockets']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): main(args)
        out=io.StringIO()
        self.assertEqual(0,main(['health','--json'],sources=SyntheticSources(),runner=SyntheticRunner(),stdout=out))
        self.assertEqual('health',json.loads(out.getvalue())['command'])

    def test_terminal_capability_failure_and_missing_curses_keep_cli_available(self):
        from faultlens.tui import run
        output=io.StringIO()
        with patch('sys.stdin.isatty',return_value=True), patch('sys.stdout.isatty',return_value=True):
            with patch.dict(os.environ,{'TERM':'bad\x1bterm'}):
                self.assertEqual(1,run(stderr=output))
            original_import=__import__
            def no_curses(name,*args,**kwargs):
                if name == 'curses': raise ImportError('optional component')
                return original_import(name,*args,**kwargs)
            with patch.dict(os.environ,{'TERM':'xterm'}), patch('builtins.__import__',side_effect=no_curses):
                self.assertEqual(1,run(stderr=output))
        self.assertNotIn('\x1b',output.getvalue())
        self.assertIn('unavailable',output.getvalue())

    def test_help_depth_and_tiny_terminal_never_trigger_hidden_collection(self):
        from faultlens.tui import handle
        session=Session()
        for _ in range(100): session.help()
        self.assertEqual(64,len(session.stack))
        with patch.object(session,'refresh',side_effect=AssertionError('No hidden collection')):
            self.assertTrue(handle(Screen(size=(2,10)),session,'r'))
            self.assertFalse(handle(Screen(size=(2,10)),session,'q'))

    def test_real_pty_navigation_resize_and_terminal_restoration(self):
        self.pty_session(interrupt=False)
        self.pty_session(interrupt=True)

    def pty_session(self, *, interrupt):
        import fcntl
        master, slave=pty.openpty()
        before=termios.tcgetattr(slave)
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,100,0,0))
        script = """import sys
from pathlib import Path
sys.path.insert(0,str(Path.cwd()))
from faultlens.tui import run
from tests.support import SyntheticSources,SyntheticRunner
raise SystemExit(run(sources=SyntheticSources(),runner=SyntheticRunner()))
"""
        process=subprocess.Popen([sys.executable,'-I','-c',script],stdin=slave,stdout=slave,stderr=slave,
                                 env={**os.environ,'TERM':'xterm-256color'},cwd=Path(__file__).resolve().parents[1])
        output=bytearray()
        try:
            deadline=time.monotonic()+5
            while b'READ-ONLY' not in output and time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]: output.extend(os.read(master,65536))
            self.assertIn(b'READ-ONLY',output)
            os.write(master,b'r278')
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',10,40,0,0))
            process.send_signal(signal.SIGWINCH)
            if interrupt:
                process.send_signal(signal.SIGINT)
            else:
                os.write(master,b'q')
            self.assertEqual(130 if interrupt else 0,process.wait(timeout=5))
            self.assertEqual(before,termios.tcgetattr(slave))
        finally:
            if process.poll() is None: process.kill()
            process.wait(timeout=2)
            os.close(master)
            os.close(slave)
