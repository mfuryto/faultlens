"""Synthetic behavior, hostile source, terminal and process-boundary tests."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from faultlens import parsers
from faultlens.cli import main, safe_text
from faultlens.collectors import check, percentage, status
from faultlens.commands import Command, CommandRunner, Result, _capture, trusted_tool
from faultlens.linux import LinuxSources
from tests.support import SyntheticRunner, SyntheticSources


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.sources = SyntheticSources()
        self.runner = SyntheticRunner()

    def snapshot(self):
        return {item.key: item for item in status(self.sources, self.runner, sleep=lambda _: None)}

    def test_status_preserves_units_and_counter_semantics(self):
        data = self.snapshot()
        self.assertEqual(20.0, data['cpu.busy'].value)
        self.assertEqual(50, data['memory.used'].value)
        self.assertEqual(25600, data['swap.used'].value)
        self.assertEqual(60, data['filesystem.root.used'].value)
        self.assertEqual(1024, data['storage.io_counters'].value[0]['read_bytes'])
        self.assertEqual(2048, data['network.counters'].value[0]['sent_bytes'])
        self.assertEqual(20, data['processes.visible'].value)
        self.assertEqual([Command.SYSTEM_STATE], self.runner.calls)

    def test_missing_source_is_not_a_healthy_result(self):
        self.sources.values['/proc/meminfo'] = 'MemTotal: invalid kB'
        data = self.snapshot()
        self.assertEqual('unavailable', data['memory.used'].state)
        self.assertEqual('Unknown', data['memory.used'].confidence)
        self.assertIsNone(data['memory.used'].value)
        self.assertEqual('normal', data['system.uptime'].state)

    def test_optional_tool_failure_does_not_hide_other_status(self):
        self.runner.results[Command.SYSTEM_STATE] = Result('timeout')
        data = self.snapshot()
        self.assertEqual('unavailable', data['services.system_state'].state)
        self.assertEqual(50, data['memory.used'].value)

    def test_memory_without_available_is_not_guessed(self):
        self.sources.values['/proc/meminfo'] = 'MemTotal: 1000 kB\nMemFree: 100 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB'
        data = self.snapshot()
        self.assertIsNone(data['memory.used'].value)
        self.assertEqual(0, data['swap.used'].value)

    def test_no_swap_and_zero_capacity_are_distinct(self):
        self.sources.values['/proc/meminfo'] = 'MemTotal: 0 kB\nMemAvailable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB'
        data = self.snapshot()
        self.assertEqual('unavailable', data['memory.used'].state)
        self.assertEqual(0, data['swap.total'].value)

    def test_threshold_boundaries_are_explicit(self):
        for used, state in ((89, 'normal'), (90, 'warning'), (94, 'warning'), (95, 'critical')):
            item = percentage('test', used, 100, 'synthetic')
            self.assertEqual(state, item.state)
            self.assertEqual({'warning': 90, 'critical': 95}, item.thresholds)
        for used, total in ((101, 100), (-1, 100), (0, 0)):
            with self.assertRaises(ValueError):
                percentage('test', used, total, 'synthetic')

    def test_check_does_not_claim_persistence_from_directory(self):
        data = {i.key: i for i in check(self.sources, self.runner)}
        self.assertEqual('Unknown', data['journal.persistent_directory'].confidence)
        self.assertEqual('unknown', data['journal.persistent_directory'].state)
        self.assertEqual(1, data['journal.previous_boots'].value)
        self.assertEqual('unavailable', data['atop.service_active'].state)
        self.assertNotIn('a' * 32, json.dumps(data['journal.previous_boots'].value))

    def test_empty_or_denied_history_is_not_disabled_persistence(self):
        for result in (Result('completed', '', 0), Result('completed', 'denied', 1), Result('output_limit')):
            self.runner.results[Command.JOURNAL_BOOTS] = result
            item = next(i for i in check(self.sources, self.runner) if i.key == 'journal.previous_boots')
            self.assertIn(item.state, {'unknown', 'unavailable'})

    def test_hostile_command_output_is_never_rendered(self):
        self.runner.results[Command.SYSTEM_STATE] = Result('completed', '\x1b]52;c;private\x07', 0)
        out = io.StringIO()
        self.assertEqual(0, main(['status', '--json'], sources=self.sources, runner=self.runner, stdout=out))
        self.assertNotIn('private', out.getvalue())
        self.assertNotIn('52;c', out.getvalue())


class ParserTests(unittest.TestCase):
    def test_cpu_guest_time_is_not_double_counted(self):
        a = parsers.cpu('cpu 100 0 100 800 0 0 0 0 100 0')
        b = parsers.cpu('cpu 110 0 110 880 0 0 0 0 200 0')
        self.assertEqual(20, parsers.cpu_percent(a, b))

    def test_cpu_reset_or_stalled_sample_is_unavailable(self):
        for before, after in (((1,) * 8, (0,) * 8), ((1,) * 8, (1,) * 8)):
            with self.assertRaises(ValueError):
                parsers.cpu_percent(before, after)

    def test_malformed_and_nonfinite_values_are_rejected(self):
        for value in ('nan', 'inf', '-1'):
            with self.assertRaises(ValueError):
                parsers.number(value)
        for value in ('cpu 1 2', 'cpu -1 0 0 0 0 0 0 0', 'cpu nan 0 0 0 0 0 0 0'):
            with self.assertRaises(ValueError):
                parsers.cpu(value)
        for value in ('MemTotal: 1 MB', 'MemTotal: 1 kB\nMemTotal: 2 kB'):
            with self.assertRaises(ValueError):
                parsers.memory(value)

    def test_malformed_boot_listing_is_not_counted(self):
        with self.assertRaises(ValueError):
            parsers.boot_count('permission denied')
        with self.assertRaises(ValueError):
            parsers.boot_count('-1 ' + 'a' * 32 + ' synthetic\n-1 ' + 'a' * 32 + ' synthetic')

    def test_network_escape_and_oversized_device_sets_are_rejected(self):
        prefix = 'Inter-| Receive | Transmit\n face | counters\n'
        with self.assertRaises(ValueError):
            parsers.network(prefix + '\x1bmalicious: ' + '0 ' * 16)
        with self.assertRaises(ValueError):
            parsers.network(prefix + '\n'.join('eth' + str(i) + ': ' + '0 ' * 16 for i in range(129)))
        with self.assertRaises(ValueError):
            parsers.disk_io('8 0 vda 1 2')


class SourceBoundaryTests(unittest.TestCase):
    def test_bounded_read_rejects_symlinks_fifo_binary_and_oversized_data(self):
        sources = LinuxSources()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plain').write_text('synthetic')
            (root / 'link').symlink_to(root / 'plain')
            os.mkfifo(root / 'fifo')
            (root / 'binary').write_bytes(b'\xff')
            self.assertEqual('synthetic', sources.read(str(root / 'plain')))
            for name in ('link', 'fifo', 'binary'):
                with self.subTest(name=name), self.assertRaises((OSError, ValueError)):
                    sources.read(str(root / name))
            with self.assertRaises(ValueError):
                sources.read(str(root / 'plain'), limit=3)

    def test_untrusted_path_is_not_used_for_dependency_resolution(self):
        with patch.dict(os.environ, {'PATH': '/tmp/attacker'}), patch('faultlens.commands.DIRECTORIES', ()):
            self.assertIsNone(trusted_tool('systemctl'))
        with self.assertRaises(ValueError):
            trusted_tool('sh')
        with patch('faultlens.commands.trusted_tool', return_value=None):
            self.assertEqual('missing', CommandRunner().run(Command.SYSTEM_STATE).state)

    def test_capture_timeout_and_both_output_limits(self):
        started = time.monotonic()
        result = _capture([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.05)
        self.assertEqual('timeout', result.state)
        self.assertLess(time.monotonic() - started, 2)
        for stream in ('stdout', 'stderr'):
            result = _capture([sys.executable, '-c', f'import sys; sys.{stream}.write("x" * 10000)'], limit=100)
            self.assertEqual('output_limit', result.state)

    def test_child_closing_pipes_cannot_evade_timeout(self):
        result = _capture([sys.executable, '-c', 'import os,time; os.close(1); os.close(2); time.sleep(10)'], timeout=0.05)
        self.assertEqual('timeout', result.state)

    def test_descendant_holding_pipes_is_killed_at_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'survived'
            child_code = 'import time,pathlib; time.sleep(0.3); pathlib.Path(' + repr(str(marker)) + ').touch()'
            parent_code = 'import subprocess,sys; subprocess.Popen([sys.executable, "-c", ' + repr(child_code) + '])'
            result = _capture([sys.executable, '-c', parent_code], timeout=0.1)
            self.assertEqual('timeout', result.state)
            time.sleep(0.4)
            self.assertFalse(marker.exists())

    def test_capture_does_not_inherit_environment_or_stdin(self):
        with patch.dict(os.environ, {'FAULTLENS_PRIVATE_TEST': 'synthetic'}):
            result = _capture([sys.executable, '-c', 'import os,sys; print(os.getenv("FAULTLENS_PRIVATE_TEST", "absent")); print(len(sys.stdin.read()))'])
        self.assertEqual('absent\n0\n', result.stdout)
        self.assertEqual(0, result.returncode)


class CliTests(unittest.TestCase):
    def test_json_contract_and_no_runtime_network_or_file_writes(self):
        out = io.StringIO()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), patch('builtins.open', side_effect=AssertionError('disk writes forbidden')):
            result = main(['status', '--json'], sources=SyntheticSources(), runner=SyntheticRunner(), stdout=out)
        data = json.loads(out.getvalue())
        self.assertEqual(0, result)
        self.assertEqual(1, data['schema_version'])
        self.assertEqual('status', data['command'])
        self.assertTrue(data['observations'])
        self.assertTrue(all('source' in i and 'confidence' in i and 'limitations' in i for i in data['observations']))

    def test_unsupported_platform_fails_before_collection(self):
        with patch('faultlens.cli.status', side_effect=AssertionError('must not collect')):
            self.assertEqual(1, main([], platform='darwin', stderr=io.StringIO()))

    def test_bad_sample_bounds_are_rejected_before_collection(self):
        for sample in ('nan', 'inf', '-1', '0', '2', 'bad'):
            with self.subTest(sample=sample), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(['--sample-seconds', sample])
            self.assertEqual(2, result.exception.code)

    def test_terminal_controls_are_neutralized(self):
        self.assertEqual('a?b?c?', safe_text('a\x1bb\x9bc\u202e'))

    def test_argument_errors_cannot_inject_terminal_controls(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaises(SystemExit):
            main(['\x1b]52;c;synthetic\x07'])
        self.assertNotIn('\x1b', output.getvalue())
        self.assertNotIn('\x07', output.getvalue())

    def test_help_and_version_do_not_collect(self):
        with patch('faultlens.cli.status', side_effect=AssertionError('must not collect')):
            for argument in ('--help', '--version'):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
                    main([argument])
                self.assertEqual(0, result.exception.code)
