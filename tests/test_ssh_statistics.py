"""SSH aggregation, bounded forward pagination, scope and literal evidence contracts."""
import io
import json
import unittest
from unittest.mock import patch
from faultlens.commands import CommandRunner,Result
from faultlens.cli import main
from faultlens.ssh_statistics import collect
from faultlens.ssh_presentation import view,render
from tests.ssh_statistics_fixtures import Runner,rows,START,BOOT
from tests.test_ssh_analysis import ssh_record


def statistics(runner=None,**options):
    return collect(runner or Runner(),window='period',since_us=START,until_us=START+86400000000,**options)


class StatisticsTests(unittest.TestCase):
    def test_forward_pages_exceed_old_tail_and_keep_every_counted_original(self):
        runner=Runner(rows(601));data=statistics(runner)
        self.assertEqual(601,data['totals']['failed']);self.assertEqual(4,data['pages_read'])
        self.assertEqual('exhausted',data['scan_state']);self.assertEqual(601,len(data['records']))
        self.assertEqual('s=synthetic;i=199',runner.calls[1][2]['cursor'])
        self.assertEqual(601,len(data['users'][0]['record_indices']))
        self.assertEqual(START,data['users'][0]['first_realtime_us'])

    def test_invalid_user_pam_partial_and_acceptance_do_not_inflate_failures(self):
        messages=['Invalid user synthetic-user from 192.0.2.7 port 2222',
            'pam_unix(sshd:auth): authentication failure; synthetic context',
            'Failed password for invalid user synthetic-user from 192.0.2.7 port 2222 ssh2',
            'Failed publickey for synthetic-user from 2001:db8::7 port 2222 ssh2: ED25519 SHA256:synthetic',
            'Accepted publickey for synthetic-user from 192.0.2.7 port 2222 ssh2: ED25519 SHA256:synthetic',
            'Partial keyboard-interactive/pam for synthetic-user from 192.0.2.7 port 2222 ssh2']
        records=[ssh_record(message,realtime=START+i,monotonic=i,__CURSOR='s=synthetic;i='+str(i)) for i,message in enumerate(messages)]
        data=statistics(Runner(records))
        self.assertEqual({'failed':2,'accepted':1,'partial':1,'invalid_user':1},data['totals'])
        self.assertEqual(1,data['unclassified_records']);self.assertEqual(2,len(data['peers']))
        self.assertIn('not distinct connections',str(data['limitations']))

    def test_cross_boot_period_and_explicit_filter_are_independent(self):
        records=rows(2);records[1]['_BOOT_ID']='c'*32
        data=statistics(Runner(records));self.assertEqual(2,data['totals']['failed']);self.assertIsNone(data['boot_filter'])
        self.assertEqual(1,statistics(Runner(records),boot_id=BOOT)['totals']['failed'])

    def test_current_boot_identity_is_read_from_kernel_not_visible_listing(self):
        class Sources:
            def read(self,path,limit):
                self.path=path;return 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n'
        sources=Sources();runner=Runner()
        data=collect(runner,sources=sources,clock=lambda:(START+86400000000)/1000000)
        self.assertEqual(BOOT,data['boot_filter']);self.assertEqual(BOOT,runner.calls[0][2]['boot_id'])
        self.assertIsNone(runner.calls[0][0])
        class Missing:
            def read(self,*args,**kwargs):raise PermissionError('synthetic')
        data=collect(Runner(),sources=Missing());self.assertEqual('unavailable',data['state'])
        self.assertIsNone(data['totals']['failed'])

    def test_empty_unavailable_and_partial_are_different_answers(self):
        empty=statistics(Runner([]));self.assertEqual('available',empty['state']);self.assertEqual(0,empty['totals']['failed'])
        runner=Runner();runner.failure=Result('timeout');missing=statistics(runner)
        self.assertIsNone(missing['totals']['failed']);self.assertIn('could not be assessed',view(missing)['Answer'])
        with patch('faultlens.ssh_statistics.MAX_PAGES',1):data=statistics(Runner(rows(201)))
        self.assertEqual('partial',data['state']);self.assertEqual(200,data['totals']['failed'])
        self.assertIn('At least 200',view(data)['Answer']);self.assertEqual('page_limit',data['reason'])

    def test_duplicate_cursor_invalid_page_bounds_and_no_progress_fail_closed(self):
        for mutation in (lambda r:r.update(_UID='1000'),lambda r:r.update(_TRANSPORT='stdout'),
                         lambda r:r.pop('__CURSOR'),lambda r:r.update(_BOOT_ID='bad')):
            records=rows(1);mutation(records[0])
            data=statistics(Runner(records));self.assertEqual('invalid_page',data['reason']);self.assertEqual([],data['records'])
        class Repeated(Runner):
            def read_ssh_page(self,*args,**kwargs):return Result('completed','\n'.join(json.dumps(row) for row in rows(200)),0)
        data=statistics(Repeated());self.assertEqual('partial',data['state']);self.assertEqual(200,len(data['records']))
        self.assertEqual('invalid_page',data['reason'])
        for limit,expected in (('MAX_EVIDENCE_BYTES','evidence_limit'),('MAX_GROUPS','group_limit')):
            with patch('faultlens.ssh_statistics.'+limit,0):self.assertEqual(expected,statistics()['reason'])
        with patch('faultlens.ssh_statistics.MAX_SECONDS',0):self.assertEqual('time_limit',statistics()['reason'])

    def test_native_page_arguments_are_validated_and_oldest_first_without_disk_cursor(self):
        with patch('faultlens.commands.trusted_tool',return_value='/usr/bin/journalctl'),patch('faultlens.commands._capture',return_value=Result('completed','',0)) as capture:
            CommandRunner().read_ssh_page(START,START+1,system=True,cursor='s=synthetic;i=1')
            argv=capture.call_args.args[0]
            for value in ('--lines=+200','--system','--after-cursor=s=synthetic;i=1'):self.assertIn(value,argv)
            self.assertFalse(any('cursor-file' in value or 'follow' in value for value in argv))
        with patch('faultlens.commands._capture') as capture:
            for cursor in ('bad cursor','x\n--follow','x;$(id)'):
                with self.assertRaises(ValueError):CommandRunner().read_ssh_page(START,START+1,cursor=cursor)
            with self.assertRaises(ValueError):CommandRunner().read_ssh_page(None,START+1)
            capture.assert_not_called()

    def test_cli_readable_details_originals_json_and_invalid_combinations(self):
        for flags in ([],['--details'],['--show-evidence'],['--json']):
            out=io.StringIO();main(['ssh','--since-us',str(START),'--until-us',str(START+86400000000),*flags],runner=Runner(),stdout=out)
            if flags==['--json']:self.assertEqual(3,json.loads(out.getvalue())['totals']['failed'])
            else:self.assertIn('3 explicit failed-authentication reports',out.getvalue());self.assertIn('synthetic-user',out.getvalue())
        for args in (['ssh','--window','period'],['ssh','--boot','0'],['status','--window','hour'],['ssh','--window','hour','--since-us','0']):
            with self.assertRaises(SystemExit):main(args,stdout=io.StringIO(),stderr=io.StringIO())

    def test_control_text_is_escaped_and_original_retained(self):
        records=[ssh_record('[bold]Synthetic unknown[/]\x1b]52;c;synthetic\x07',realtime=START,__CURSOR='s=synthetic')]
        data=statistics(Runner(records));out=io.StringIO();render(data,out,evidence=True)
        self.assertNotIn('\x1b',out.getvalue());self.assertIn('\\u001b',out.getvalue())
        self.assertEqual(records[0]['MESSAGE'],data['records'][0]['message'])
