"""Shared service workflow on invented manager results, units and journal attempts."""
import io
import json
import unittest

from faultlens import service
from faultlens.commands import Result
from faultlens.service_diagnostics import RESULTS,LOADS,record_detail,problem_rows,followup_window
from faultlens.workspace import Entry,source_table
from tests.test_service import ServiceRunner,journal_record


def collect(unit='example-web.service',changes=None,rows=None,messages=None):
    runner=ServiceRunner(messages or ['Synthetic unclassified failure'])
    text=runner.read_service_properties(unit).stdout
    values=dict(line.split('=',1) for line in text.splitlines());values.update(changes or {})
    runner.status_result=Result('completed','\n'.join(key+'='+value for key,value in values.items())+'\n',0)
    if rows is not None:runner.journal_result=Result('completed','\n'.join(json.dumps(row) for row in rows),0)
    return service.collect(unit,runner)


class GeneralServiceTests(unittest.TestCase):
    def test_manager_results_have_specific_explanations_for_arbitrary_services(self):
        units=('example-web.service','example-mail.service','example-db.service','example-worker@one.service','escaped\\x20worker.service')
        for unit in units:
            for reason in RESULTS:
                with self.subTest(unit=unit,reason=reason):
                    data=collect(unit,{'Result':reason})
                    self.assertEqual(reason,data['assessment']['code'])
                    self.assertTrue(data['assessment']['meaning']);self.assertTrue(data['assessment']['next_steps'])
                    self.assertEqual('Unknown',data['root_cause'])
                    self.assertEqual('Synthetic unclassified failure',data['journal_records'][0]['message'])
                    _,_,entries=source_table(Entry(('Messages',),data,None,'service_messages'),data)
                    self.assertEqual('service_message',entries[0].kind)
                    self.assertIn(unit,entries[0].detail['Service'])
            for load in LOADS:
                self.assertEqual(load,collect(unit,{'LoadState':load})['assessment']['code'])

    def test_unknown_result_and_successful_recovery_are_not_guessed_causes(self):
        unknown=collect(changes={'Result':'future-result'})
        self.assertEqual('unclassified-failure',unknown['assessment']['code'])
        self.assertEqual('future-result',unknown['assessment']['reported']['Result'])
        recovered=collect(changes={'Result':'success','ActiveState':'active','SubState':'running'})
        self.assertEqual('no-current-failed-state',recovered['assessment']['code'])
        self.assertIn('older failures',recovered['assessment']['meaning'])
        self.assertEqual(1,len(problem_rows(recovered)))
        retained=collect(changes={'Result':'timeout','ActiveState':'active','SubState':'running'})
        self.assertIn('current active state is active',retained['assessment']['meaning'])

    def test_main_exit_and_signal_values_have_readable_but_noncausal_meaning(self):
        cases=[({'ExecMainCode':'1','ExecMainStatus':'78'},'status 78'),
               ({'ExecMainCode':'2','ExecMainStatus':'9'},'SIGKILL'),
               ({'ExecMainCode':'3','ExecMainStatus':'11'},'SIGSEGV'),
               ({'ExecMainCode':'2','ExecMainStatus':'999999'},'unknown signal'),
               ({'ExecMainCode':'0','ExecMainStatus':'0'},'No supported')]
        for changes,expected in cases:
            data=collect(changes=changes)
            self.assertIn(expected,service.view(data)['Main-process report'])
            self.assertEqual('Unknown',data['root_cause'])

    def test_common_error_phrases_work_without_named_product_rules(self):
        for text in ('Permission denied','No space left on device','Address already in use','No such file or directory','Read-only file system','Connection refused'):
            data=collect(unit='example-db.service',messages=['Synthetic operation: '+text])
            self.assertEqual(1,len(data['explanations']))
            self.assertEqual(0,data['explanations'][0]['record_index'])
            detail=record_detail(data,0)
            self.assertIn(text,detail['Recorded message']);self.assertTrue(detail['What you can do'])

    def test_invocation_identity_does_not_mix_old_attempts_or_manager_identity(self):
        unit='example-mail.service';rows=[]
        for i,identity in enumerate(('c'*32,'d'*32,'bad')):
            row=journal_record('Synthetic attempt '+str(i),i,unit);row['_SYSTEMD_INVOCATION_ID']=identity;rows.append(row)
        # Manager's own invocation must not be mistaken for the service invocation.
        row=journal_record('Synthetic manager event',3,unit)
        row.update(_SYSTEMD_UNIT='init.scope',UNIT=unit,_PID='1',_COMM='systemd',_SYSTEMD_INVOCATION_ID='c'*32)
        rows.append(row)
        data=collect(unit,rows=rows)
        self.assertEqual({'Same reported invocation ID':1,'Different reported invocation ID':1,'Unverified invocation':2},data['invocation_summary'])
        self.assertIn('Different reported',record_detail(data,1)['Invocation scope'])
        self.assertIn('not automatically',service.view(data)['Log invocation context'])
        self.assertEqual('bad',data['journal_records'][2]['unit_metadata']['_SYSTEMD_INVOCATION_ID'])
        row['INVOCATION_ID']='c'*32
        data=collect(unit,rows=[row]);self.assertEqual(1,data['invocation_summary']['Same reported invocation ID'])

    def test_dependency_result_requires_manager_and_selected_unit_metadata(self):
        unit='example-worker.service';row=journal_record('Synthetic dependency result',0,unit)
        row.update(_PID='1',_COMM='systemd',UNIT=unit,JOB_RESULT='dependency')
        data=collect(unit,{'Result':'success','ActiveState':'inactive','SubState':'dead'},[row])
        self.assertIn('dependency failure',data['explanations'][0]['title'])
        for change in ({'_PID':'500'},{'_COMM':'example'},{'_UID':'1000'},{'UNIT':'other.service'}):
            changed=dict(row,**change)
            self.assertEqual([],collect(unit,rows=[changed])['explanations'])

    def test_unavailable_status_and_journal_remain_independent(self):
        runner=ServiceRunner(['Synthetic failure']);runner.status_result=Result('timeout')
        data=service.collect('example.service',runner)
        self.assertEqual('unavailable',data['assessment']['code']);self.assertEqual(1,len(problem_rows(data)))
        runner=ServiceRunner();runner.journal_result=Result('unavailable')
        data=service.collect('example.service',runner)
        self.assertEqual('exit-code',data['assessment']['code']);self.assertEqual([],problem_rows(data))
        self.assertIn('logs unavailable',service.view(data)['Journal coverage'])

    def test_problem_order_keeps_info_and_unknown_original_messages(self):
        unit='example-web.service';rows=[journal_record('Synthetic informational context',0,unit),
            journal_record('Synthetic unfamiliar failure',1,unit),journal_record('Synthetic bind: Address already in use',2,unit)]
        rows[0]['PRIORITY']='6'
        data=collect(unit,rows=rows)
        self.assertEqual([2,1,0],[row['record_index'] for row in problem_rows(data)])
        _,_,entries=source_table(Entry(('Messages',),data,None,'service_messages'),data)
        self.assertEqual(2,entries[0].navigation['current_page'])
        self.assertIs(data['journal_records'][2],entries[0].original)
        self.assertIn('No supported specific',entries[1].detail['What it means'])
        output=io.StringIO();service.render(data,output)
        self.assertIn('Synthetic unfamiliar failure',' '.join(output.getvalue().split()))

    def test_period_bounds_are_valid_receipt_windows_not_commands(self):
        data=collect();record=data['journal_records'][0]
        start,end=followup_window(record)
        self.assertEqual(240000000,end-start)
        for invalid in (True,-1,'now',None):
            with self.assertRaises(ValueError):followup_window({'reference':{'realtime_us':invalid}})
        self.assertEqual(0,followup_window({'reference':{'realtime_us':1}})[0])
