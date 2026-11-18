"""Invented session snapshots only; never inspect host users, utmp or logind."""
import asyncio
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from textual.widgets import DataTable
from faultlens.cli import main
from faultlens.commands import CATALOG,Command,CommandRunner,Result,_capture
from faultlens.sessions import collect,parse,parse_properties,listed_ids,MAX_ROWS
from faultlens.textual_app import FaultlensApp,SourceDialog,DetailDialog
from faultlens.tui_model import Session
from tests.support import SyntheticSources,SyntheticRunner

WHO='example-admin pts/0 2026-01-01 12:34 . 42 (192.0.2.8)\n'


def properties(identity='7',username='example-admin',remote='2001:db8::8'):
    return '\n'.join(f'{key}={value}' for key,value in dict(Id=identity,Name=username,User='1000',TTY='pts/0',
        Timestamp='Thu 2026-01-01 12:34:56 UTC',RemoteHost=remote,State='active',Type='tty',Class='user').items())+'\n'


class Runner(SyntheticRunner):
    def __init__(self,listing=None,values=None,who=None):
        super().__init__();self.ids=[]
        self.results[Command.LOGIN_SESSION_SERVICE]=Result('completed','active\n',0)
        self.results[Command.LOGIN_SESSION_LIST]=listing or Result('completed','7 1000 example-admin - pts/0\n',0)
        self.results[Command.LOGIN_SESSIONS]=who or Result('completed',WHO,0)
        self.values=values or Result('completed',properties(),0)
    def read_login_session_properties(self,identities):self.ids.append(identities);return self.values


class SessionTests(unittest.TestCase):
    def test_who_preserves_users_sources_precision_and_duplicate_sessions(self):
        text=WHO+WHO.replace('pts/0','pts/1').replace('192.0.2.8','2001:db8::8')+WHO.replace(' (192.0.2.8)','')+WHO.replace('192.0.2.8','example.invalid')
        with patch('socket.getaddrinfo',side_effect=AssertionError('No DNS')):rows=parse(text)
        self.assertEqual(4,len(rows));self.assertEqual(text.splitlines(),[row['original'] for row in rows])
        self.assertEqual('2001:db8::8',rows[1]['source_address'])
        self.assertIsNone(rows[2]['source_reported']);self.assertIsNone(rows[3]['source_address'])
        self.assertEqual('reported_host_or_source',rows[3]['source_kind'])
        self.assertEqual('2026-01-01T12:34+00:00',rows[0]['login_time_utc'])
        self.assertEqual('minute',rows[0]['login_time_precision'])
        self.assertEqual([],parse(''))
        self.assertEqual('local_display',parse(WHO.replace('192.0.2.8',':0'))[0]['source_kind'])

    def test_unsupported_or_oversized_who_output_cannot_return_successful_prefix(self):
        for value in (WHO+'invalid\n',WHO.replace('2026-01-01','2026-02-30'),WHO+'\x1b',WHO+'\r',WHO+'\u2028',
                      WHO.replace(' . ',' 00:99 '),WHO.replace(' 42 ',' -1 '),WHO*(MAX_ROWS+1),WHO*20000):
            with self.subTest(value=value[:60]),self.assertRaises(ValueError):parse(value)
        data=collect(Runner(listing=Result('missing'),who=Result('completed',WHO+'invalid\n',0)))
        self.assertEqual('unavailable',data['state']);self.assertEqual([],data['rows'])

    def test_logind_primary_is_batched_and_keeps_exact_reported_properties(self):
        runner=Runner();data=collect(runner)
        self.assertEqual('available',data['state']);self.assertEqual([['7']],runner.ids)
        self.assertNotIn(Command.LOGIN_SESSIONS,runner.calls)
        row=data['rows'][0];self.assertEqual('second',row['login_time_precision'])
        self.assertEqual('2026-01-01T12:34:56+00:00',row['login_time_utc'])
        self.assertEqual('2001:db8::8',row['source_address']);self.assertEqual('active',row['session_state_reported'])
        self.assertEqual('example-admin',row['original']['Name'])
        rows=parse_properties(properties()+'\n'+properties('8','other-user','192.0.2.9'),['7','8'])
        self.assertEqual(2,len(rows))
        empty_fields=properties().replace('TTY=pts/0','TTY=').replace('Timestamp=Thu 2026-01-01 12:34:56 UTC','Timestamp=n/a')
        row=parse_properties(empty_fields,['7'])[0]
        self.assertEqual('Not reported',row['terminal']);self.assertIsNone(row['login_time_utc'])

    def test_logind_races_unsafe_ids_and_incomplete_properties_fail_closed(self):
        for text in ('self 1000 example\n','--host=remote 1000 example\n','7 1000 example\n7 1000 other\n','7 1000 example\x1b\n'):
            with self.assertRaises(ValueError):listed_ids(text)
        for text in (properties().replace('Id=7','Id=8'),properties()+'Name=duplicate\n',properties().replace('State=active\n',''),properties()+'bad\n'):
            with self.assertRaises(ValueError):parse_properties(text,['7'])
        data=collect(Runner(values=Result('completed',properties().replace('Id=7','Id=8'),0)))
        self.assertEqual('partial',data['state']);self.assertEqual(WHO.rstrip(),data['rows'][0]['original'])
        self.assertEqual('unavailable',data['other_source_evidence']['state'])

    def test_empty_missing_and_failed_sources_never_assert_nobody_logged_in(self):
        for result in (Result('missing'),Result('timeout',WHO),Result('completed',WHO,1)):
            data=collect(Runner(listing=result,who=result))
            self.assertEqual('unavailable',data['state']);self.assertEqual([],data['rows'])
        empty=collect(Runner(listing=Result('completed','',0),who=Result('completed','',0)))
        self.assertEqual('available',empty['state']);self.assertEqual('unknown',empty['completeness'])
        self.assertEqual([],empty['rows']);self.assertIn('does not establish',str(empty['limitations']))
        fallback=collect(Runner(listing=Result('missing')))
        self.assertEqual('partial',fallback['state']);self.assertTrue(fallback['rows'])
        inactive=Runner();inactive.results[Command.LOGIN_SESSION_SERVICE]=Result('completed','inactive\n',3)
        self.assertEqual('partial',collect(inactive)['state'])
        self.assertNotIn(Command.LOGIN_SESSION_LIST,inactive.calls)

    def test_fixed_read_only_commands_timezone_and_id_validation(self):
        self.assertEqual(('who',('--users',)),CATALOG[Command.LOGIN_SESSIONS])
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/who'),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().run(Command.LOGIN_SESSIONS)
            self.assertEqual((['/usr/bin/who','--users'],),capture.call_args.args)
            self.assertTrue(capture.call_args.kwargs['utc'])
            CommandRunner().read_boot('a'*32)
            self.assertNotIn('utc',capture.call_args.kwargs)
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/loginctl'),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().read_login_session_properties(['7','c8'])
            argv=capture.call_args.args[0]
            self.assertEqual(['show-session','7','c8'],argv[1:4]);self.assertIn('--no-ask-password',argv)
            self.assertEqual({'Id','Name','User','TTY','Timestamp','RemoteHost','State','Type','Class'},
                {arg.partition('=')[2] for arg in argv if arg.startswith('--property=')})
            for ids in ([],['self'],['--host=bad'],['7','7'],[{}],['1']*65):
                with self.assertRaises(ValueError):CommandRunner().read_login_session_properties(ids)
            self.assertEqual(1,capture.call_count)
        with patch('faultlens.commands.subprocess.Popen',side_effect=OSError) as spawn,self.assertRaises(OSError):
            _capture(['/usr/bin/who','--users'],utc=True)
        self.assertEqual('UTC',spawn.call_args.kwargs['env']['TZ']);self.assertEqual('C',spawn.call_args.kwargs['env']['LC_ALL'])
        self.assertFalse(spawn.call_args.kwargs['shell'])

    def test_status_cli_and_json_show_all_requested_fields_without_masking(self):
        for flags in ([],['--json'],['--details']):
            output=io.StringIO()
            self.assertEqual(0,main(['status',*flags],sources=SyntheticSources(),runner=Runner(),stdout=output))
            for expected in ('example-admin','pts/0','2026-01-01','2001:db8::8'):self.assertIn(expected,output.getvalue())
            if '--json' in flags:self.assertEqual('available',json.loads(output.getvalue())['login_sessions']['state'])
        output=io.StringIO();main(['status'],sources=SyntheticSources(),runner=Runner(listing=Result('completed','',0),who=Result('completed','',0)),stdout=output)
        self.assertIn('No login records reported',output.getvalue());self.assertIn('does not establish that nobody',output.getvalue())


class SessionWorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):asyncio.get_running_loop().slow_callback_duration=2
    async def test_system_session_rows_open_readable_details_and_resize(self):
        session=Session(sources=SyntheticSources(),runner=Runner());session.refresh()
        app=FaultlensApp(session=session,initial_collect=False);app.snapshots[0]=session.data
        async with app.run_test(size=(100,30)) as pilot:
            table=app.query_one('#grid-0',DataTable)
            table.move_cursor(row=next(i for i,row in enumerate(app.entries[0]) if row.kind=='login_sessions'))
            app.action_open();await pilot.pause(.01);self.assertIsInstance(app.screen,SourceDialog)
            source_table=app.screen.query_one(DataTable)
            self.assertEqual(4,len(source_table.columns));self.assertEqual(1,source_table.row_count)
            cells=source_table.get_row_at(0)
            self.assertIn('2001:db8::8',' '.join(str(cell) for cell in cells))
            await pilot.press('enter');self.assertIsInstance(app.screen,DetailDialog)
            self.assertEqual('active',app.screen.entry.original['session_state_reported'])
            await pilot.press('escape');await pilot.resize_terminal(80,24)
            self.assertGreater(source_table.size.width,0)
            await pilot.resize_terminal(40,10);await pilot.press('escape')
            self.assertEqual(1,len(app.screen_stack))
