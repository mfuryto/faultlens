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


class SessionTests(unittest.TestCase):
    def test_literal_search_wraps_without_filtering_collecting_or_copying_evidence(self):
        session=Session()
        evidence={'alpha':'one needle','nested':{'hidden':'needle'},'omega':'another NEEDLE'}
        session.stack=[(evidence,'Invented evidence',0,0)]
        with patch.object(session,'refresh',side_effect=AssertionError('No search collection')):
            session.find('needle')
            self.assertEqual(0,session.selected)
            session.find(); self.assertEqual(2,session.selected)
            session.find(); self.assertEqual(0,session.selected)
            session.find(reverse=True); self.assertEqual(2,session.selected)
            self.assertEqual(3,len(session.rows()))
            self.assertIs(evidence,session.value)
            self.assertIs(evidence['nested'],session.rows()[1].value)
            session.find('hidden')
            self.assertIn('No match',session.notice)
            self.assertEqual(2,session.selected)
            session.find('[')
            self.assertIn('No match',session.notice)

    def test_scalar_search_uses_full_escaped_value_and_wraps_by_line(self):
        session=Session()
        value='a'*100+'NEEDLE'+'b'*100+'needle'+'\x1b]52;c;payload\x07'
        session.stack=[(value,'Invented scalar',0,0)]
        session.find('needle',width=20); self.assertEqual(5,session.scroll)
        session.find(width=20); self.assertEqual(10,session.scroll)
        session.find(width=20); self.assertEqual(5,session.scroll)
        session.find(reverse=True,width=20); self.assertEqual(10,session.scroll)
        session.find('\\u001b',width=20); self.assertGreater(session.scroll,0)
        self.assertIs(value,session.value)
        session.find('needle',width=7)
        self.assertEqual(101//7,session.scroll)

    def test_search_validation_empty_view_and_clear_leave_evidence_unchanged(self):
        session=Session()
        session.find(); self.assertIn('Search cleared',session.notice)
        session.find('anything'); self.assertIn('No match',session.notice)
        for query in ('x'*65,'\x1b','\n','\u202e',12):
            with self.assertRaises(ValueError): session.find(query)
            self.assertEqual('anything',session.search_text)
        session.find(''); self.assertEqual('',session.search_text)

    def test_search_matches_readable_units_and_settings_without_changing_them(self):
        from faultlens.models import Observation,report
        session=Session()
        session.data=report('status',[Observation('memory.total',2*1024**3,'bytes','synthetic')])
        session.find('GiB')
        self.assertEqual('observation',session.rows()[session.selected].action)
        session.choose_page(7)
        settings=session.settings
        session.find('Off')
        self.assertEqual(False,session.rows()[session.selected].value)
        self.assertIs(settings,session.settings)

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
        self.assertTrue(any(row.value is session.data['security_analysis'] for row in session.rows()))

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


class EntrypointTests(unittest.TestCase):
    def test_noninteractive_entrypoint_keeps_cli_available(self):
        from faultlens.tui import run
        output=io.StringIO()
        with patch('sys.stdin.isatty',return_value=False):
            self.assertEqual(1,run(stderr=output))
        self.assertIn('interactive',output.getvalue())

    def test_cli_dispatch_and_health_alias(self):
        output=io.StringIO()
        with patch('faultlens.tui.run',return_value=0) as run:
            self.assertEqual(0,main(['tui'],stdout=output)); run.assert_called_once()
        self.assertEqual(0,main(['health','--json'],sources=SyntheticSources(),runner=SyntheticRunner(),stdout=output))
        self.assertEqual('health',json.loads(output.getvalue())['command'])

    def test_bad_terminal_and_unreviewed_frontend_fail_without_collection(self):
        from faultlens.tui import run
        output=io.StringIO()
        with patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True):
            with patch.dict(os.environ,{'TERM':'bad\x1bterm'}):
                self.assertEqual(1,run(stderr=output))
            with patch.dict(os.environ,{'TERM':'xterm'}),patch('importlib.metadata.version',return_value='0.0.0'):
                self.assertEqual(1,run(stderr=output))
        self.assertNotIn('\x1b',output.getvalue())


if __name__=='__main__': unittest.main()
