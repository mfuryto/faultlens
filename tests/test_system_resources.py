"""Synthetic process/storage pressure, races, source restrictions and parent contracts."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from faultlens import processes,filesystems,system_resources
from faultlens.commands import CommandRunner,Result
from faultlens.current_views import build
from faultlens.cli import main
from faultlens.collectors import status
from faultlens.models import report
from faultlens.system_resource_views import filesystem_assessment,filesystem_detail
from tests.support import SyntheticRunner,SyntheticSources
from tests.system_resource_fixtures import stat_text,process_report,storage_report,fs_values


class ProcessResourceTests(unittest.TestCase):
    def test_stat_parentheses_controls_counters_and_pid_identity(self):
        name='synthetic ) worker\n[bold]\x1b'
        row=processes.parse_stat(stat_text(name=name),42,4096)
        self.assertEqual(name,row['name']);self.assertEqual(64*4096,row['rss_bytes'])
        for raw in (stat_text(pid=43),stat_text().replace(' 10 ',' -1 ',1),'42 (unterminated','x'*4097):
            with self.assertRaises(ValueError):processes.parse_stat(raw,42,4096)

    def test_cpu_intervals_are_one_cpu_and_reuse_reset_or_new_pids_are_unknown(self):
        original=process_report();before=copy.deepcopy(original['rows']);after=copy.deepcopy(before)
        before[0].update(cpu_ticks=0,observed_monotonic_s=1)
        after[0].update(cpu_ticks=200,observed_monotonic_s=2)
        rows=processes.compare({'rows':before},{'rows':after},100)
        self.assertEqual(200,rows[0]['cpu_percent'])
        for mutation in ({'start_ticks':101},{'cpu_ticks':-1},{'observed_monotonic_s':1}):
            changed=copy.deepcopy(after);changed[0].update(mutation)
            self.assertIsNone(processes.compare({'rows':before},{'rows':changed},100)[0]['cpu_percent'])
        self.assertIsNone(processes.compare({'rows':[]},{'rows':after},100)[0]['cpu_percent'])

    def test_cgroup_association_is_system_only_and_never_a_command(self):
        self.assertEqual('example-worker@one.service',processes.system_service('0::/system.slice/example-worker@one.service/children\n'))
        self.assertEqual('example.service',processes.system_service('1:name=systemd:/system.slice/example.service\n'))
        self.assertIsNone(processes.system_service('0::/user.slice/user-1000.slice/user@1000.service/app.slice/example.service\n'))
        self.assertIsNone(processes.system_service('0::/system.slice/evil;id.service\n'))
        self.assertIsNone(processes.system_service('0::/system.slice/a.service\n1:name=systemd:/system.slice/b.service\n'))

    def test_descriptor_scanning_rejects_pid_and_source_symlinks_and_reports_caps(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for pid in (42,43,44):
                folder=root/str(pid);folder.mkdir()
                (folder/'stat').write_text(stat_text(pid));(folder/'cgroup').write_text('0::/system.slice/example.service\n')
            (root/'45').symlink_to(root/'42',target_is_directory=True)
            fd=os.open(root,processes.DIRECTORY)
            try:
                snapshot=processes.snapshot(fd,4096,lambda:1.0)
                self.assertEqual(3,len(snapshot['rows']));self.assertEqual(1,snapshot['read_errors'])
                (root/'43/stat').unlink();(root/'43/stat').symlink_to(root/'42/stat')
                self.assertEqual(2,processes.snapshot(fd,4096,lambda:1.0)['read_errors'])
                with patch('faultlens.processes.MAX_PROCESSES',1):
                    limited=processes.snapshot(fd,4096,lambda:1.0)
                    self.assertTrue(limited['process_limit_reached']);self.assertEqual([42],[row['pid'] for row in limited['rows']])
            finally:os.close(fd)


class FilesystemResourceTests(unittest.TestCase):
    def test_mount_escaping_roots_sources_and_invalid_targets(self):
        table=filesystems.mounts('1 0 8:1 / /var\\040data rw shared:1 - ext4 /dev/synthetic rw\n2 1 0:1 memfd:synthetic /run/example ro - tmpfs - ro')
        self.assertEqual('/var data',table[0]['target']);self.assertEqual('memfd:synthetic',table[1]['root'])
        self.assertEqual('-',table[1]['mount_source']);self.assertTrue(table[1]['read_only'])
        for text in ('1 0 8:1 / relative rw - ext4 x rw','1 0 8:1 / /a/../b rw - ext4 x rw',
                     '1 0 8:1 / /bad\\777 rw - ext4 x rw','bad','1 0 8:1 / / rw - ext4 x rw\n1 0 8:1 / /var rw - ext4 x rw'):
            with self.assertRaises(ValueError):filesystems.mounts(text)

    def test_block_and_inode_exhaustion_are_independent_and_use_unrounded_thresholds(self):
        source=storage_report();row=source['rows'][1]
        for blocks,inodes in ((96,20),(20,96)):
            changed=dict(row,capacity=filesystems.capacity(fs_values(blocks,inodes)))
            self.assertEqual('Critical',filesystem_assessment(changed))
            self.assertIn('threshold',filesystem_detail(changed,source)['Observed'])
        changed=dict(row,capacity=filesystems.capacity(fs_values(95,95,True)))
        self.assertEqual('Info',filesystem_assessment(changed))
        values=fs_values(10,0);values.f_files=values.f_ffree=values.f_favail=0
        changed=dict(row,capacity=filesystems.capacity(values))
        self.assertIsNone(changed['capacity']['inode_used_percent'])
        self.assertIn('no inode denominator',str(filesystem_detail(changed,source)))
        values=fs_values();values.f_blocks=1000000;values.f_bfree=values.f_bavail=100001
        changed=dict(row,capacity=filesystems.capacity(values))
        self.assertEqual(90,changed['capacity']['user_used_percent']);self.assertEqual('Measured',filesystem_assessment(changed))
        values.f_bavail=values.f_bfree=100000
        self.assertEqual('Review',filesystem_assessment(dict(row,capacity=filesystems.capacity(values))))

    def test_remote_pseudo_fuse_autofs_and_unsafe_ancestors_are_never_probed(self):
        table=filesystems.mounts('1 0 8:1 / / rw - ext4 root rw\n2 1 0:1 / /remote rw - nfs example rw\n3 2 8:2 / /remote/local rw - ext4 disk rw\n4 1 0:2 / /fuse rw - fuse.sshfs example rw\n5 1 0:3 / /auto rw - autofs example rw\n6 1 0:4 / /proc rw - proc proc rw')
        calls=[]
        def measure(row):calls.append(row['target']);return filesystems.capacity(fs_values())
        result=filesystems.collect_rows(table,measure)
        self.assertEqual(['/'],calls)
        self.assertEqual(5,result['coverage']['not_probed'])
        with patch('faultlens.filesystems.MAX_PROBES',1):
            data=filesystems.collect_rows(filesystems.mounts('1 0 8:1 / / rw - ext4 x rw\n2 1 8:2 / /var rw - ext4 y rw'),measure)
            self.assertTrue(data['coverage']['probe_limit_reached']);self.assertEqual('partial',data['state'])

    def test_mount_probe_requires_descriptor_identity_and_rejects_symlink_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'link').symlink_to(root,target_is_directory=True)
            row=storage_report()['rows'][0]
            for target in (str(root/'link'),str(root)):
                changed=dict(row,target=target,mount_id=2**63-1)
                with self.assertRaises((OSError,ValueError)):filesystems.probe(changed)
        values=fs_values();values.f_favail=values.f_files+1
        with self.assertRaises(ValueError):filesystems.capacity(values)


class SystemResourceContractTests(unittest.TestCase):
    def test_native_worker_arguments_are_fixed_and_invalid_inquiries_never_execute(self):
        with patch('faultlens.commands._capture',return_value=Result('timeout')) as capture:
            for kind,interval in (([],0.1),('file:/etc/shadow',0.1),('processes',True),('filesystems',float('nan')),('processes',0)):
                with self.assertRaises(ValueError):CommandRunner().read_system_resources(kind,interval)
            capture.assert_not_called()
            self.assertEqual('timeout',CommandRunner().read_system_resources('processes',0.1).state)
            argv=capture.call_args.args[0]
            for option in ('-I','-B','-S'):self.assertIn(option,argv)
            self.assertTrue(argv[-3].endswith('/faultlens/_system_exec.py'))
            self.assertEqual(['processes','0.1'],argv[-2:]);self.assertEqual(1048576,capture.call_args.kwargs['limit'])

    def test_independent_failures_duplicate_json_and_inconsistent_numbers_fail_closed(self):
        for bad in (Result('timeout'),Result('output_limit'),Result('completed','',1),Result('completed','{"schema_version":1,"schema_version":1}',0)):
            runner=SyntheticRunner();original=runner.read_system_resources
            runner.read_system_resources=lambda kind,interval:bad if kind=='processes' else original(kind,interval)
            data={};system_resources.attach(data,runner)
            self.assertEqual('unavailable',data['processes']['state']);self.assertEqual('available',data['filesystems']['state'])
        data=process_report();data['rows'][0]['cpu_percent']=999
        with self.assertRaises(ValueError):system_resources.validate(data,'processes')
        data=storage_report();data['rows'][0]['capacity']['available_bytes']=1
        with self.assertRaises(ValueError):system_resources.validate(data,'filesystems')

    def test_system_and_health_explain_a_separate_full_var_and_keep_all_sources(self):
        runner=SyntheticRunner();original=runner.read_system_resources
        def resources(kind,interval):
            if kind!='filesystems':return original(kind,interval)
            value=storage_report();row=next(row for row in value['rows'] if row['target']=='/var')
            row['capacity']=filesystems.capacity(fs_values(99,20))
            return Result('completed',json.dumps(value),0)
        runner.read_system_resources=resources
        for command in ('status','health'):
            output=io.StringIO();self.assertEqual(0,main([command,'--json'],sources=SyntheticSources(),runner=runner,stdout=output))
            data=json.loads(output.getvalue());view=build(data)
            self.assertIn('PID/mount namespaces',view['scope'])
            self.assertNotIn('root filesystem only',view['scope'])
            self.assertTrue(any(row.label=='/var' and row.assessment=='Critical' for row in view['rows']))
            self.assertEqual(3,len(data['filesystems']['rows']));self.assertEqual(2,len(data['processes']['rows']))
            self.assertIn('Review',view['summary']) if command=='status' else self.assertIn('need review',view['summary'])

    def test_unknown_comparisons_and_read_only_root_are_not_zero_or_space_faults(self):
        source=SyntheticSources();source.filesystem=lambda:fs_values(100,100,True)
        observations=status(source,SyntheticRunner(),sleep=lambda _:None)
        roots=[item for item in observations if item.key in {'filesystem.root.used','filesystem.root.user_used'}]
        self.assertTrue(all(item.state=='unknown' for item in roots))
        data=report('status',observations)
        self.assertFalse(any(row.assessment=='Critical' for row in build(data)['rows']))

    def test_inventory_without_any_capacity_measurements_is_a_gap(self):
        data=report('status',[])
        data['filesystems']=filesystems.collect_rows(filesystems.mounts('1 0 0:1 / /remote rw - nfs example rw'),
            lambda row:self.fail('Remote source must not be probed'))
        view=build(data)
        source=next(row for row in view['rows'] if row.kind=='filesystems')
        self.assertEqual('Gap',source.assessment)
        self.assertIn('incomplete',view['summary'])

    def test_cli_details_retain_every_resource_row_and_escape_source_strings(self):
        runner=SyntheticRunner();runner.maximum_system_resources=True
        original=runner.read_system_resources
        def resources(kind,interval):
            result=original(kind,interval)
            if kind=='processes':
                data=json.loads(result.stdout);data['rows'][0]['name']='synthetic\x1b[31m\nworker'
                return Result('completed',json.dumps(data),0)
            return result
        runner.read_system_resources=resources
        output=io.StringIO()
        self.assertEqual(0,main(['status','--details'],sources=SyntheticSources(),runner=runner,stdout=output))
        lines=output.getvalue().splitlines()
        processes=json.loads(next(line.removeprefix('Processes source: ') for line in lines if line.startswith('Processes source: ')))
        mounts=json.loads(next(line.removeprefix('Filesystems source: ') for line in lines if line.startswith('Filesystems source: ')))
        self.assertNotIn('\x1b',output.getvalue())
        self.assertEqual('synthetic\x1b[31m\nworker',processes['rows'][0]['name'])
        self.assertEqual(512,len(processes['rows']));self.assertEqual(256,len(mounts['rows']))
        self.assertTrue(mounts['coverage']['probe_limit_reached'])
