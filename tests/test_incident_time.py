"""Invented explicit-offset times and bounded source replies; never read host journals."""
import asyncio
import contextlib
from dataclasses import asdict
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from textual.widgets import DataTable,Input,Static
from faultlens.cli import main
from faultlens.commands import CommandRunner,Result
from faultlens.event_search import search
from faultlens.incidents import diagnose
from faultlens.journal import MAX_REALTIME_US
from faultlens.settings_store import SettingsStore
from faultlens.textual_app import FaultlensApp,ValueDialog
from faultlens.time_window import parse,display
from faultlens.tui_model import Session,Settings,SETTING_KEYS
from faultlens.workspace import page_table
from tests.test_incidents import BOOT,record,listing
from tests.test_event_search import SearchRunner,candidate
from tests.test_firewall import TCP


class IncidentRunner(SearchRunner):
    def __init__(self):
        super().__init__([record(realtime=1500)],kernel=[candidate(realtime=1000),candidate(realtime=2000,monotonic=200)])
        self.options=[]
    def read_boot_window(self,boot_id,since_us,*,until_us=None,system=False):
        self.options.append(('tail',boot_id,system,since_us,until_us));return self.result
    def read_event_candidates(self,boot_id,query,*,system=False,since_us=None,until_us=None):
        self.options.append((query,boot_id,system,since_us,until_us))
        return super().read_event_candidates(boot_id,query,system=system,since_us=since_us,until_us=until_us)
    def read_ssh_candidates(self,boot_id,*,system=False,since_us=None,until_us=None):
        self.options.append(('ssh',boot_id,system,since_us,until_us))
        return Result('completed',listing([record('Failed password for synthetic from 192.0.2.7 port 2222 ssh2',realtime=1500,_COMM='sshd',_TRANSPORT='syslog',_UID='0',_PID='42')]),0)
    def read_firewall_candidates(self,boot_id,*,system=False,since_us=None,until_us=None):
        self.options.append(('firewall',boot_id,system,since_us,until_us))
        return Result('completed',listing([record(TCP,realtime=1500)]),0)


class IncidentTimeTests(unittest.TestCase):
    def test_explicit_offsets_and_microseconds_round_trip_without_float_loss(self):
        self.assertEqual(parse('2026-11-14T23:20:00.123456+01:00'),parse('2026-11-14T22:20:00.123456Z'))
        self.assertEqual(1,parse('1970-01-01T00:00:00.000001Z'))
        self.assertEqual(MAX_REALTIME_US,parse('9999-12-31T23:59:59.999999Z'))
        for value in (0,1,1767225600123456,MAX_REALTIME_US):
            self.assertEqual(value,parse(display(str(value))))
            self.assertEqual(value,parse(str(value),allow_microseconds=True))
        self.assertEqual(parse('2024-02-29T12:00:00Z'),parse('2024-02-29 12:00+00:00'))
        self.assertEqual('Not selected',display(''))

    def test_ambiguous_injected_invalid_or_overprecise_times_fail_before_collection(self):
        for value in ('now','yesterday','2026-11-14','2026-11-14T22:20:00','2026-02-29T12:00Z',
                      '2026-11-14T24:00Z','2026-11-14T12:00:60Z','2026-11-14T12:00:00.1234567Z',
                      '2026-11-14T12:00:00+01:60','2026-11-14T12:00:00+24:00','1969-12-31T23:59:59Z',
                      '1970-01-01T00:00:00+01:00','9999-12-31T23:59:59-01:00','0','١','2026-11-14T12:00Z;id',
                      '2026-11-14T12:00Z\n','2026-11-14T12:00Z\x1b'):
            with self.subTest(value=value),self.assertRaises(ValueError): parse(value)
            runner=IncidentRunner()
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                main(['diagnose','--since',value],runner=runner)
            self.assertEqual([],runner.options)

    def test_cli_uses_exact_inclusive_bounds_for_every_requested_journal_source(self):
        runner=IncidentRunner();output=io.StringIO()
        self.assertEqual(0,main(['diagnose','--system-journal','--since','1970-01-01T00:00:00.001000Z',
            '--until','1970-01-01T01:00:00.002000+01:00','--search-events','--search-ssh','--search-firewall','--json'],runner=runner,stdout=output))
        data=json.loads(output.getvalue())
        self.assertEqual({'tail','kernel_warnings','systemd_events','ssh','firewall'},{item[0] for item in runner.options})
        self.assertTrue(all(item[1:]==(BOOT,True,1000,2000) for item in runner.options))
        self.assertEqual([1000,2000],[item['evidence'][0]['realtime_us'] for item in data['event_search']['queries'][0]['findings']])
        self.assertEqual('available',data['ssh_analysis']['state']);self.assertEqual('available',data['firewall_analysis']['state'])
        self.assertEqual('Unknown',data['root_cause'])

    def test_duplicate_or_reversed_options_and_non_diagnostic_commands_are_rejected(self):
        for options in (['--since','1970-01-01T00:00Z','--since-us','0'],
                        ['--until','1970-01-01T00:00Z','--until-us','0'],
                        ['--since','2026-01-02T00:00Z','--until','2026-01-01T00:00Z']):
            runner=IncidentRunner()
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit): main(['diagnose',*options],runner=runner)
            self.assertEqual([],runner.options)
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit): main(['history','--since','1970-01-01T00:00Z'])

    def test_native_queries_use_only_normalized_numeric_time_arguments(self):
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/journalctl'),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().read_event_candidates(BOOT,'kernel_warnings',system=True,since_us=1000,until_us=2000)
        args=capture.call_args.args[0]
        for argument in ('--system','--since=@0.001000','--until=@0.002000','--lines=501','--priority=warning','_TRANSPORT=kernel'):
            self.assertIn(argument,args)
        for bounds in ((-1,2000),(2000,1000),(True,2000),(0,MAX_REALTIME_US+1)):
            with patch('faultlens.commands._capture',side_effect=AssertionError('No invalid execution')),self.assertRaises(ValueError):
                CommandRunner().read_event_candidates(BOOT,'kernel_warnings',since_us=bounds[0],until_us=bounds[1])

    def test_one_sided_equal_and_zero_event_bounds_are_inclusive(self):
        for start,end,timestamp in ((None,1000,1000),(1000,None,1000),(0,0,0),(1000,1000,1000)):
            runner=SearchRunner(kernel=[candidate(realtime=timestamp)])
            result=search(runner,BOOT,since_us=start,until_us=end,show_evidence=True)
            self.assertEqual(1,len(result['queries'][0]['records']))
            self.assertEqual({'since_realtime_us':start,'until_realtime_us':end},result['requested_window'])
            self.assertEqual('Unknown',result['root_cause'])

    def test_outside_or_invalid_sentinel_rejects_entire_filtered_query_without_fallback(self):
        class Broken(IncidentRunner):
            def read_event_candidates(self,boot_id,query,**options):
                return self.candidates[query]
        for rows in ([candidate(realtime=999)], [candidate(realtime=2001)],
                     [candidate(realtime=999,monotonic=0)]+[candidate(realtime=1500,monotonic=i+1) for i in range(500)]):
            runner=Broken();runner.candidates['kernel_warnings']=Result('completed',listing(rows),0)
            result=search(runner,BOOT,since_us=1000,until_us=2000,show_evidence=True)
            query=result['queries'][0]
            self.assertEqual('invalid',query['parse_state']);self.assertEqual([],query['records']);self.assertEqual([],query['findings'])
            self.assertEqual('partial',result['state'])
            from faultlens.investigation import story
            view=story({'command':'diagnose','state':'available','event_search':result})
            self.assertIn('kernel_warnings search could not be assessed',' '.join(view['gaps']))
            self.assertEqual({'since_realtime_us':1000,'until_realtime_us':2000},result['requested_window'])


class IncidentTimeWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self): asyncio.get_running_loop().slow_callback_duration=2

    async def test_date_edit_saves_numeric_compatible_preferences_and_displays_utc(self):
        with tempfile.TemporaryDirectory() as folder:
            store=SettingsStore(Path(folder)/'config');app=FaultlensApp(initial_collect=False,settings_store=store)
            async with app.run_test(size=(110,32)) as pilot:
                await pilot.pause(.01);app.select_page(7);await pilot.pause(.01)
                table=app.query_one('#grid-7',DataTable);table.move_cursor(row=SETTING_KEYS.index('since_us'))
                await pilot.press('enter');self.assertIsInstance(app.screen,ValueDialog)
                self.assertIn('timezone',' '.join(str(w.render()) for w in app.screen.query(Static)))
                app.screen.query_one(Input).value='2026-11-14T23:20:00+01:00';await pilot.press('enter')
                expected=str(parse('2026-11-14T22:20:00Z'))
                self.assertEqual(expected,app.session.settings.since_us)
                self.assertEqual(expected,store.load(Settings())[0].since_us)
                self.assertIn('2026-11-14T22:20:00.000000Z',str(table.get_cell_at((SETTING_KEYS.index('since_us'),1))))
                before=store.path.read_bytes();await pilot.press('enter')
                self.assertEqual(display(expected),app.screen.query_one(Input).value)
                app.screen.query_one(Input).value='2026-11-14T22:00:00';await pilot.press('enter')
                self.assertIsInstance(app.screen,ValueDialog);self.assertEqual(before,store.path.read_bytes())
                app.screen.query_one(Input).value='';await pilot.press('enter')
                self.assertEqual('',store.load(Settings())[0].since_us)
                await pilot.resize_terminal(40,12);await pilot.pause(.01)
                await pilot.press('enter','escape')

    def test_reversed_date_edit_preserves_previous_settings_and_old_numeric_files(self):
        session=Session();session.update_setting('since_us','1000');session.update_setting('until_us','2000')
        before=asdict(session.settings)
        with self.assertRaises(ValueError): session.update_setting('since_us','1970-01-01T00:00:01Z')
        self.assertEqual(before,asdict(session.settings))
        with tempfile.TemporaryDirectory() as folder:
            store=SettingsStore(Path(folder)/'config');store.save(session.settings)
            restored,status=store.load(Settings());self.assertEqual(before,asdict(restored))
