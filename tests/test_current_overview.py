"""Invented operator scenarios: decisions, source gaps and all original details remain distinct."""
import copy
import io
import json
import unittest
from types import SimpleNamespace

from faultlens.cli import main
from faultlens.commands import Command,Result,CATALOG
from faultlens.current_views import build,observation
from faultlens.health import collect,parse_failed_services
from faultlens.models import Observation,report
from faultlens.presentation import render
from faultlens.workspace import page_table,source_table
from faultlens.tui_model import Settings
from tests.support import SyntheticSources,SyntheticRunner,SyntheticNetworkSources
from tests.test_network_analysis import NetworkSources,analyze,stats

UNIT='example-worker.service loaded failed failed Synthetic worker\n'


class FailedServiceTests(unittest.TestCase):
    def test_fixed_read_only_catalog_and_original_rows(self):
        tool,args=CATALOG[Command.FAILED_SERVICES]
        self.assertEqual('systemctl',tool); self.assertIn('--state=failed',args)
        self.assertNotIn('restart',args)
        row=parse_failed_services(UNIT)[0]
        self.assertEqual('example-worker.service',row['unit'])
        self.assertEqual(UNIT.rstrip(),row['original']); self.assertEqual([],parse_failed_services(''))
        self.assertEqual('escaped\\x20name.service',parse_failed_services('escaped\\x20name.service loaded failed failed Synthetic')[0]['unit'])

    def test_unsupported_over_limit_or_injected_unit_names_never_yield_empty_success(self):
        for value in ('UNIT LOAD ACTIVE SUB DESCRIPTION\n',UNIT+UNIT,'\n',
                      UNIT.replace('.service',';id.service'),UNIT.replace('failed failed','active running'),
                      'a.service loaded failed failed '+'x'*4096,
                      ''.join('example'+str(i)+'.service loaded failed failed Synthetic\n' for i in range(129)),
                      ''.join('example'+str(i)+'.service loaded failed failed '+('x'*3500)+'\n' for i in range(80))):
            with self.subTest(value=value[:60]),self.assertRaises(ValueError): parse_failed_services(value)
        for result in (Result('timeout'),Result('completed','',1),Result('completed',UNIT+UNIT,0)):
            runner=SyntheticRunner();runner.results[Command.FAILED_SERVICES]=result
            data=collect(SyntheticSources(),runner,sample_seconds=0.05)
            self.assertEqual('unavailable',data['failed_services']['state'])
            self.assertEqual([],data['failed_services']['rows'])
            self.assertIn('incomplete',build(data)['summary'])

    def test_cli_health_details_json_and_readable_modes_retain_service_context(self):
        runner=SyntheticRunner();runner.results[Command.SYSTEM_STATE]=Result('completed','degraded\n',1)
        runner.results[Command.FAILED_SERVICES]=Result('completed',UNIT,0)
        for options in ([],['--details'],['--json']):
            output=io.StringIO()
            self.assertEqual(0,main(['health',*options],sources=SyntheticSources(),runner=runner,stdout=output))
            self.assertIn('example-worker.service',output.getvalue())
            if options==['--json']:
                data=json.loads(output.getvalue())
                self.assertEqual('health',data['command']);self.assertTrue(any(o['key']=='cpu.busy' for o in data['observations']))
                self.assertEqual('failed',data['failed_services']['rows'][0]['active'])
        output=io.StringIO();main(['check','--json'],sources=SyntheticSources(),runner=runner,stdout=output)
        self.assertNotIn('failed_services',json.loads(output.getvalue()))

    def test_descriptions_are_retained_but_not_interpreted_by_readable_output(self):
        description='[bold]synthetic[/]\x1b]52;c;invented\x07\u202e'
        runner=SyntheticRunner();runner.results[Command.FAILED_SERVICES]=Result('completed','example.service loaded failed failed '+description,0)
        data=collect(SyntheticSources(),runner,sample_seconds=0.05)
        self.assertEqual(description,data['failed_services']['rows'][0]['description'])
        output=io.StringIO();render(data,output)
        self.assertNotIn('\x1b',output.getvalue());self.assertNotIn('\u202e',output.getvalue())
        self.assertIn('[bold]',output.getvalue())

    def test_invalid_collection_options_fail_before_commands(self):
        runner=SyntheticRunner()
        for value in (True,0,2,float('nan')):
            with self.assertRaises(ValueError): collect(SyntheticSources(),runner,sample_seconds=value)
        self.assertEqual([],runner.calls)


class CurrentDecisionTests(unittest.TestCase):
    def test_health_separates_operational_flags_from_optional_readiness_and_defaults(self):
        data=collect(SyntheticSources(),SyntheticRunner(),sample_seconds=0.05,preservation=True)
        original=copy.deepcopy(data);view=build(data)
        self.assertIn('No operational review flag',view['summary'])
        self.assertIn('incident-data sources',view['summary'])
        settings=next(row for row in view['rows'] if row.label=='Recording configuration')
        self.assertEqual('Info',settings.assessment)
        _,entries=page_table(1,data,Settings())
        group=next(row for row in entries if row.cells[0]=='Recording configuration')
        _,_,details=source_table(group,data)
        unset=[row for row in details if row.original['value'] is None]
        self.assertTrue(unset)
        self.assertTrue(all(row.cells[1]=='Default not verified' and row.cells[2]=='Info' for row in unset))
        self.assertEqual(original,data)

    def test_capacity_and_failed_unit_flags_are_useful_without_inventing_causes(self):
        sources=SyntheticSources();sources.filesystem=lambda:SimpleNamespace(f_blocks=1000,f_bfree=30,f_bavail=20,f_frsize=4096)
        runner=SyntheticRunner();runner.results[Command.SYSTEM_STATE]=Result('completed','degraded\n',1)
        runner.results[Command.FAILED_SERVICES]=Result('completed',UNIT,0)
        data=collect(sources,runner,sample_seconds=0.05)
        view=build(data);self.assertIn('need review',view['summary'])
        self.assertTrue(any(row.kind=='failed_services' and row.assessment=='Review' for row in view['rows']))
        details=next(row for row in view['rows'] if row.label=='Operational checks')
        self.assertTrue(any(item['key']=='filesystem.root.user_used' and item['state']=='critical' for item in details.original))
        self.assertNotIn('root cause confirmed',str(view))

    def test_zero_log_space_is_readiness_review_not_an_invented_recording_failure(self):
        data=report('health',[Observation('cpu.busy',20,'percent','synthetic'),
            Observation('journal.storage.available',0,'bytes','synthetic','unknown')])
        original=copy.deepcopy(data);view=build(data)
        row=next(row for row in view['rows'] if row.label=='Journal log space')
        self.assertEqual('Review',row.assessment)
        self.assertIn('recording failure is not established',row.meaning)
        self.assertIn('readiness settings also need review',view['summary'])
        self.assertEqual(original,data)

    def test_short_cpu_hint_preserves_source_and_explains_threshold(self):
        data=report('status',[Observation('cpu.busy',96,'percent','synthetic')]);original=copy.deepcopy(data)
        row=build(data)['rows'][0]
        self.assertEqual('Review',row.assessment);self.assertIn('>=90%',row.detail['View threshold'])
        self.assertIn('does not establish sustained',row.meaning);self.assertEqual(original,data)

    def test_system_partial_sources_remain_gaps_and_normal_values_do_not_imply_past_health(self):
        for state,value in (('normal',20),('unavailable',None)):
            data=report('status',[Observation('cpu.busy',value,'percent','synthetic',state)])
            view=build(data);self.assertTrue(view['rows'])
            self.assertEqual('Gap' if value is None else 'Measured',view['rows'][0].assessment)
            self.assertIn('incomplete' if value is None else 'No configured',view['summary'])
        item=report('check',[Observation('journal.config.storage',None,'','synthetic','unknown',
            explanation='Final assignment uses an unsupported expression; no value is inferred.')])['observations'][0]
        self.assertEqual('Gap',observation(item).assessment)
        self.assertEqual('Unsupported expression',observation(item).value)

    def test_many_interface_overview_is_bounded_and_every_original_remains_inspectable(self):
        from faultlens.network import collect as network
        data=network(SyntheticNetworkSources(),sleep=lambda _:None,clock=iter((10,10.5)).__next__)
        original=copy.deepcopy(data)
        columns,entries=page_table(2,data,Settings())
        self.assertLessEqual(len(entries),9)
        all_interfaces=next(row for row in entries if row.cells[0]=='All interfaces')
        self.assertIs(data['observations'][0]['value'],all_interfaces.original)
        heading,cols,rows=source_table(all_interfaces,data)
        self.assertEqual(128,len(rows));self.assertEqual({row['interface'] for row in all_interfaces.original},{row.cells[0] for row in rows})
        self.assertEqual(original,data)

    def test_unavailable_protocols_do_not_become_no_error_growth_or_healthy_zero(self):
        data=analyze(NetworkSources(tcp=[OSError('invented')]*2))
        view=build(data)
        self.assertIn('incomplete',view['summary'])
        row=next(row for row in view['rows'] if row.label=='Protocol pressure')
        self.assertEqual('Gap',row.assessment)
        self.assertTrue(any(item['state']=='unavailable' for item in row.original))

    def test_idle_reset_and_growth_interfaces_have_different_meanings(self):
        from tests.test_network_analysis import HEADER,device
        cases=[NetworkSources(devices=[HEADER+device()]*2),
               NetworkSources(devices=[HEADER+device(received=200),HEADER+device(received=100)]),
               NetworkSources(tcp=[stats(),stats((1,0,0,0,0))])]
        idle,reset,growth=[build(analyze(source)) for source in cases]
        self.assertFalse(any(row.assessment=='Active' for row in idle['rows']))
        self.assertTrue(any(row.assessment=='Gap' for row in reset['rows']))
        self.assertIn('need review',growth['summary'])
        self.assertIn('does not establish a flood',next(row for row in growth['rows'] if row.label=='Protocol pressure').meaning)


if __name__=='__main__': unittest.main()
