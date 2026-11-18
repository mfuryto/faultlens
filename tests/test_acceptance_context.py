"""Synthetic acceptance metadata; never collect server logs or invoke Git."""
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, mock_open, patch

from faultlens import acceptance_context as context
from faultlens.commands import Result


class AcceptanceContextTests(unittest.TestCase):
    def test_os_metadata_is_bounded_and_allowlisted(self):
        with patch('builtins.open',mock_open(read_data=b'ID=debian\nVERSION_ID="12"\nHOST_NAME=private-marker\n')):
            self.assertEqual({'id':'debian','version_id':'12'},context.os_release())
        for raw in (b'ID=debian\nID=ubuntu\n',b'ID="bad\x1b"\n',b'x'*8193,b'ID=\xff\n'):
            with patch('builtins.open',mock_open(read_data=raw)):
                self.assertEqual({'id':None,'version_id':None},context.os_release())
        with patch('builtins.open',side_effect=PermissionError):
            self.assertEqual({'id':None,'version_id':None},context.os_release())

    def test_revision_is_bounded_read_only_and_never_changes_git_trust(self):
        root=MagicMock(spec=Path);root.stat.return_value=SimpleNamespace(st_uid=1000)
        root.__str__.return_value='/synthetic-checkout'
        git=MagicMock(spec=Path);git.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o755)
        git.parents=();git.__str__.return_value='/usr/bin/git'
        execute=MagicMock(return_value=Result('completed','a'*40+'\n',0))
        with patch('faultlens.acceptance_context.os.geteuid',return_value=1000),patch('pathlib.Path.resolve',return_value=git):
            self.assertEqual('a'*40,context.revision(root,execute=execute))
            self.assertEqual(['/usr/bin/git','--no-optional-locks','-C','/synthetic-checkout','rev-parse','--verify','HEAD'],execute.call_args.args[0])
            self.assertEqual({'timeout':2,'limit':1024},execute.call_args.kwargs)
            for result in (Result('timeout'),Result('completed','a'*41,0),Result('completed','native-error',128)):
                execute.return_value=result
                self.assertIsNone(context.revision(root,execute=execute))
            git.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o777)
            execute.reset_mock()
            self.assertIsNone(context.revision(root,execute=execute));execute.assert_not_called()
        for uid in (0,1001):
            execute.reset_mock()
            with patch('faultlens.acceptance_context.os.geteuid',return_value=uid):
                self.assertIsNone(context.revision(root,execute=execute));execute.assert_not_called()

    def test_receipt_keeps_manual_acceptance_and_source_identity_unverified(self):
        with (patch('faultlens.acceptance_context.os_release',return_value={'id':'debian','version_id':'12'}),
              patch('faultlens.acceptance_context.version',return_value='8.2.8'),
              patch('faultlens.acceptance_context.revision',return_value='a'*40),
              patch('faultlens.acceptance_context.platform.python_version',return_value='3.11.18'),
              patch('faultlens.acceptance_context.platform.machine',return_value='x86_64'),
              patch('sys.stdin',io.StringIO()),patch('sys.stdout',io.StringIO())):
            data=context.collect()
        self.assertEqual({'os_release','python','architecture','textual','checkout_revision','working_tree','terminal','operator_acceptance'},set(data))
        self.assertEqual('not_verified',data['working_tree'])
        self.assertEqual('not_recorded',data['operator_acceptance'])
        self.assertIsNone(data['terminal']['columns'])
        terminal=MagicMock();terminal.isatty.return_value=True;terminal.fileno.return_value=99
        with (patch('sys.stdin',terminal),patch('sys.stdout',terminal),
              patch('faultlens.acceptance_context.revision',return_value=None),
              patch('faultlens.acceptance_context.os_release',return_value={}),
              patch('faultlens.acceptance_context.version',side_effect=context.PackageNotFoundError),
              patch('os.get_terminal_size',return_value=os.terminal_size((100,30)))):
            data=context.collect()
        self.assertEqual((100,30),(data['terminal']['columns'],data['terminal']['rows']))
        self.assertIsNone(data['textual'])
