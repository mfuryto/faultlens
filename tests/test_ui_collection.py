"""Synthetic subprocess reports exercise bounded collection and cancellation only."""
import asyncio
import json
import sys
import unittest
from unittest.mock import patch

from faultlens.ui_collection import arguments,collect,bounded_read
from faultlens.tui_model import Settings,Session


class CollectionTests(unittest.IsolatedAsyncioTestCase):
    def test_fixed_cli_arguments_preserve_explicit_source_selection(self):
        settings=Settings()
        self.assertEqual(['status','--json','--sample-seconds','0.1'],arguments(0,settings))
        args=arguments(5,settings)
        self.assertNotIn('--pstore',args); self.assertNotIn('--atop-date',args)
        settings=Settings(boot_selector='a'*32,system_journal=True,atop_date='20260101',atop_extended=True,
                          pstore=True,pstore_archive=True,search_ssh=True,since_us='10',until_us='20')
        args=arguments(5,settings)
        for value in ('--boot-id','a'*32,'--system-journal','--pstore','--pstore-archive','--show-evidence','--atop-extended'):
            self.assertIn(value,args)
        self.assertEqual('10',args[args.index('--since-us')+1])
        with self.assertRaises(ValueError): arguments(7,settings)

    def test_administrator_defaults_enable_reads_without_forcing_scope_or_guessing_dates(self):
        settings=Settings.administrator_defaults()
        self.assertFalse(settings.system_journal); self.assertFalse(settings.atop_extended)
        self.assertEqual('',settings.atop_date)
        self.assertTrue(settings.include_current)
        for page,flags in ((1,('--history',)),(2,('--sockets',)),(3,('--sockets',)),
                           (4,('--include-current',)),(5,('--search-events','--search-ssh',
                              '--search-firewall','--pstore','--pstore-archive'))):
            argv=arguments(page,settings)
            for flag in flags: self.assertIn(flag,argv)
            self.assertNotIn('--system-journal',argv)
            self.assertNotIn('--atop-extended',argv)
        session=Session()
        session.settings=settings; session.update_setting('sample_seconds','0.2')
        self.assertEqual(0.2,session.settings.sample_seconds)
        fresh=Settings.administrator_defaults(); self.assertEqual(0.1,fresh.sample_seconds)

    async def test_output_bound_does_not_accept_a_successful_prefix(self):
        reader=asyncio.StreamReader(); reader.feed_data(b'x'*65); reader.feed_eof()
        with self.assertRaises(ValueError): await bounded_read(reader,64)

    async def run_report(self,script):
        real=asyncio.create_subprocess_exec; calls=[]
        async def launch(*argv,**kwargs):
            calls.append((argv,kwargs))
            return await real(sys.executable,'-I','-c',script,**kwargs)
        with patch('faultlens.ui_collection.asyncio.create_subprocess_exec',side_effect=launch):
            value=await collect(0,Settings())
        return value,calls

    async def test_valid_report_uses_fixed_executable_no_shell_controlled_environment(self):
        value,calls=await self.run_report('print(\'{"schema_version":1,"command":"status","observations":[]}\')')
        self.assertEqual('status',value['command'])
        argv,kwargs=calls[0]
        self.assertEqual(sys.executable,argv[0]); self.assertIn('-I',argv)
        self.assertEqual('/',kwargs['cwd']); self.assertTrue(kwargs['start_new_session'])
        self.assertEqual('C',kwargs['env']['LC_ALL']); self.assertNotIn('shell',kwargs)

    async def test_malformed_wrong_command_and_nonfinite_reports_fail_closed(self):
        for text in ('not json','{"schema_version":1,"command":"diagnose"}',
                     '{"schema_version":1,"command":"status","value":NaN}'):
            with self.assertRaises(ValueError): await self.run_report('print('+repr(text)+')')

    async def test_cancellation_stops_the_collection_process(self):
        real=asyncio.create_subprocess_exec; ready=asyncio.Event(); children=[]
        async def launch(*argv,**kwargs):
            child=await real(sys.executable,'-I','-c','import time; time.sleep(60)',**kwargs)
            children.append(child); ready.set(); return child
        with patch('faultlens.ui_collection.asyncio.create_subprocess_exec',side_effect=launch):
            task=asyncio.create_task(collect(0,Settings())); await ready.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await asyncio.wait_for(task,4)
        self.assertIsNotNone(children[0].returncode)

    async def test_oversized_report_is_rejected_and_child_reaped(self):
        with patch('faultlens.ui_collection.MAX_OUTPUT',64):
            with self.assertRaises(ValueError): await self.run_report('print("x"*65)')

    async def test_deadline_stops_and_reaps_the_collection_process(self):
        real=asyncio.create_subprocess_exec; timeout=asyncio.timeout; children=[]
        async def launch(*argv,**kwargs):
            child=await real(sys.executable,'-I','-c','import time; time.sleep(60)',**kwargs)
            children.append(child); return child
        with patch('faultlens.ui_collection.asyncio.create_subprocess_exec',side_effect=launch),\
             patch('faultlens.ui_collection.asyncio.timeout',side_effect=lambda _:timeout(0.1)):
            with self.assertRaises(TimeoutError): await collect(0,Settings())
        self.assertIsNotNone(children[0].returncode)


if __name__=='__main__': unittest.main()
