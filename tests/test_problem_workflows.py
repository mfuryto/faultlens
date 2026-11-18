"""Problem/time entry points retain source identity without requiring a boot choice."""
import contextlib
import copy
import io
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch

from faultlens.cli import main
from faultlens.commands import Command,CommandRunner,Result
from faultlens.investigation import linked_records
from faultlens.tui_model import Settings
from faultlens.workflows import collect,partition,story
from tests.support import SyntheticHealthRunner,SyntheticNetworkSources
from tests.test_incidents import record

A='a'*32;B='b'*32;START=1767225600000000;END=START+120000000


def event(identity=A,offset=60,mono=10,message='Out of memory: Killed process 42 (synthetic-worker)'):
    return record(message,_BOOT_ID=identity,realtime=START+offset*1000000,monotonic=mono,
                  __CURSOR='s=synthetic-'+identity[:1]+'-'+str(offset),PRIORITY='3')


class Runner(SyntheticHealthRunner):
    def __init__(self,rows=None):
        super().__init__();self.rows=[event(),event(B,70,2)] if rows is None else rows
        self.window_calls=[];self.listings=[];self.fail=set()
    def run(self,command):
        if command==Command.SOCKETS:return Result('completed','',0)
        if command in {Command.JOURNAL_BOOTS,Command.JOURNAL_SYSTEM_BOOTS}:
            self.listings.append(command)
            return Result('completed','0 '+B+' synthetic\n-1 '+A+' synthetic\n',0)
        return super().run(command)
    def read_journal_window(self,start,end,*,boot_id=None,query=None,system=False):
        self.window_calls.append((start,end,boot_id,query,system))
        if query in self.fail:return Result('completed','',1)
        rows=[row for row in self.rows if (boot_id is None or row['_BOOT_ID']==boot_id)
              and (start is None or int(row['__REALTIME_TIMESTAMP'])>=start)
              and (end is None or int(row['__REALTIME_TIMESTAMP'])<=end)]
        if query not in {None,'kernel_warnings'}:rows=[]
        return Result('completed','\n'.join(json.dumps(row) for row in rows),0)


class WorkflowTests(unittest.TestCase):
    def test_period_spans_restarts_without_listing_or_current_collection(self):
        runner=Runner();data=collect(runner,mode='period',since_us=START,until_us=END)
        self.assertEqual([],runner.listings);self.assertEqual({},data['current'])
        self.assertEqual(2,len(data['investigations']));self.assertIsNone(data['boot_filter']['resolved'])
        for child in data['investigations']:
            self.assertIsNone(child['selected_boot']['index'])
            self.assertEqual('Unknown',child['root_cause'])
            finding=child['findings'][0];records=linked_records(child,finding)
            self.assertEqual(child['selected_boot']['boot_id'],records[0]['reference']['boot_id'])
            self.assertEqual(0,child['reconstruction']['monotonic_span_us'])
        self.assertTrue(all(call[:2]==(START,END) and call[2] is None for call in runner.window_calls))
        self.assertIn('OOM',story(data)['answer'])

    def test_explicit_boot_filter_and_before_restart_are_not_fallbacks(self):
        runner=Runner();data=collect(runner,mode='period',since_us=START,until_us=END,boot_id=B)
        self.assertEqual([],runner.listings);self.assertEqual([B],[row['selected_boot']['boot_id'] for row in data['investigations']])
        runner=Runner();data=collect(runner,mode='before-restart')
        self.assertEqual(A,data['boot_filter']['resolved']);self.assertEqual(1,len(runner.listings))
        self.assertTrue(all(call[2]==A for call in runner.window_calls))
        runner=Runner();data=collect(runner,mode='before-restart',boot_index=-2)
        self.assertEqual('unavailable',data['selection_state']);self.assertEqual([],runner.window_calls)

    def test_now_keeps_current_readings_separate_from_recent_history(self):
        runner=Runner();data=collect(runner,sources=SyntheticNetworkSources(),mode='now',clock=lambda:END/1000000)
        self.assertEqual({'health','network'},set(data['current']))
        self.assertEqual(END-900000000,data['requested_window']['since_realtime_us'])
        self.assertTrue(all(call[2] is None for call in runner.window_calls))
        self.assertIn('Current measurements',story(data)['answer'])
        historical=collect(Runner(),mode='period',since_us=START,until_us=END)
        self.assertEqual({},historical['current'])

    def test_unavailable_empty_and_independent_search_findings_are_distinct(self):
        runner=Runner([]);data=collect(runner,mode='period',since_us=START,until_us=END)
        self.assertEqual('available',data['state']);self.assertIn('returned no records',story(data)['answer'])
        runner.fail={None,'kernel_warnings','systemd_events'}
        data=collect(runner,mode='period',since_us=START,until_us=END)
        self.assertIn('could not be assessed',story(data)['answer']);self.assertNotIn('No supported fault',story(data)['answer'])
        runner=Runner();runner.fail={None}
        data=collect(runner,mode='period',since_us=START,until_us=END)
        self.assertEqual('partial',data['state']);self.assertIn('Recorded problems',story(data)['answer'])
        self.assertIn('could not be assessed',story(data)['answer'])
        self.assertTrue(all(child['journal_records']==[] for child in data['investigations']))

    def test_global_caps_invalid_scope_and_partition_count_stay_visible(self):
        rows=[event(A if index==0 else B,offset=index,mono=index) for index in range(501)]
        result=Result('completed','\n'.join(json.dumps(row) for row in rows),0)
        groups,meta=partition(result,START,START+600000000)
        self.assertTrue(meta['record_limit_reached']);self.assertEqual(500,meta['records_retained'])
        self.assertNotIn(A,groups)
        invalid=Result('completed',json.dumps(event(B)),0)
        self.assertEqual('invalid',partition(invalid,START,END,A)[1]['parse_state'])
        invalid=Result('completed','{"_BOOT_ID":"'+A+'","_BOOT_ID":"'+B+'"}',0)
        self.assertEqual('invalid',partition(invalid,START,END)[1]['parse_state'])
        many=Runner([event(format(i+1,'032x'),offset=i) for i in range(8)])
        data=collect(many,mode='period',since_us=START,until_us=END)
        self.assertEqual(7,len(data['investigations']));self.assertEqual(1,data['omitted_boot_scopes'])
        omitted=format(8,'032x')
        self.assertEqual(omitted,json.loads(data['uninterpreted_records']['tail'][omitted])['_BOOT_ID'])
        self.assertEqual('partial',data['state'])

    def test_request_validation_precedes_collection_and_cli_infers_period(self):
        for options in ({'mode':'period','since_us':START},{'mode':'now','since_us':START,'until_us':END},
                        {'mode':'period','since_us':END,'until_us':START},{'boot_id':'$(bad)'},
                        {'boot_index':True},{'mode':'bad'}):
            runner=Runner()
            with self.assertRaises(ValueError):collect(runner,**options)
            self.assertEqual([],runner.window_calls)
        output=io.StringIO();runner=Runner()
        self.assertEqual(0,main(['investigate','--since-us',str(START),'--until-us',str(END),'--json'],runner=runner,stdout=output))
        data=json.loads(output.getvalue());self.assertEqual('period',data['mode']);self.assertEqual(2,len(data['investigations']))
        output=io.StringIO()
        self.assertEqual(0,main(['investigate','--since-us',str(START),'--until-us',str(END),'--no-search-events','--json'],runner=Runner(),stdout=output))
        self.assertEqual({'tail'},set(json.loads(output.getvalue())['query_coverage']))
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as error:
            main(['investigate','--mode','period'],runner=Runner(),stderr=io.StringIO())
        self.assertEqual(2,error.exception.code)

    def test_native_window_command_is_pinned_bounded_and_unfiltered_by_default(self):
        calls=[]
        def capture(args,**kwargs):calls.append(args);return Result('completed','',0)
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/journalctl'),patch('faultlens.commands._capture',side_effect=capture):
            CommandRunner().read_journal_window(START,END,query='kernel_warnings',system=True)
            self.assertNotIn('--boot=', ' '.join(calls[0]));self.assertIn('--lines=501',calls[0])
            self.assertIn('--system',calls[0]);self.assertIn('--since=@1767225600.000000',calls[0])
            for bad in ({'since_us':None,'until_us':None},{'since_us':START,'until_us':END,'boot_id':'$(bad)'},
                        {'since_us':START,'until_us':END,'query':'unsafe'}):
                with self.assertRaises(ValueError):CommandRunner().read_journal_window(**bad)
        self.assertEqual(1,len(calls))

    def test_source_validation_gaps_and_explicit_filter_clear_never_hide_evidence(self):
        class Unexpected(Runner):
            def read_journal_window(self,start,end,*,boot_id=None,query=None,system=False):
                if query=='systemd_events':return Result('completed',json.dumps(event()),0)
                return super().read_journal_window(start,end,boot_id=boot_id,query=query,system=system)
        data=collect(Unexpected(),mode='period',since_us=START,until_us=END)
        self.assertEqual('partial',data['query_coverage']['systemd_events']['state'])
        self.assertEqual('partial',data['state']);self.assertIn('could not be assessed',story(data)['answer'])
        single=collect(Runner(),mode='period',since_us=START,until_us=END,boot_index=0)
        self.assertEqual(B,single['boot_filter']['resolved'])
        cleared=collect(Runner(),mode='period',since_us=START,until_us=END)
        self.assertEqual(2,len(cleared['investigations']))
        with self.assertRaises(ValueError):collect(Runner(),mode='before-restart',boot_index=0)

    def test_independent_crash_source_and_multi_boot_recording_limits_are_preserved(self):
        from tests.support import SyntheticSources
        data=collect(Runner(),mode='period',since_us=START,until_us=END,
            atop_date='20260101',pstore=True,pstore_collector=SyntheticSources().pstore_snapshot)
        self.assertIn('select_one_retained_boot',data['atop']['reason'])
        self.assertTrue(data['pstore']['records'])
        self.assertIn('possible panic signatures',story(data)['answer'])
        self.assertEqual('Unknown',data['root_cause'])
        self.assertTrue(all('pstore' not in child for child in data['investigations']))
