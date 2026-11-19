"""Synthetic Git/source/wheel bundles; no publication or host installation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import build_release as release
from scripts import build_deb
from tests import test_deb_package


@unittest.skipUnless(shutil.which('git') and shutil.which('dpkg-deb'),'Release build tools unavailable')
class ReleaseBundleTests(unittest.TestCase):
    def fixture(self,root):
        for folder in ('faultlens','packaging/debian','scripts','docs/security'):
            (root/folder).mkdir(parents=True)
        (root/'faultlens/__init__.py').write_text('__version__ = "1.0.0"\n')
        (root/'packaging/debian/application-files.txt').write_text('faultlens/__init__.py\n')
        for name in ('control','faultlens','README.Debian','changelog'):
            shutil.copyfile(build_deb.ROOT/'packaging/debian'/name,root/'packaging/debian'/name)
        shutil.copyfile(build_deb.ROOT/'scripts/build_deb.py',root/'scripts/build_deb.py')
        for name in ('LICENSE','NOTICE','README.md','docs/third-party.md'):
            (root/name).write_text('Synthetic source-bundle fixture.\n')
        (root/'.gitignore').write_text('__pycache__/\ndist/\n')
        wheels=root.parent/'wheels';wheels.mkdir()
        wheel=wheels/'example-1.0-py3-none-any.whl';test_deb_package.DebPackageTests().wheel(wheel)
        lock='example==1.0 --hash=sha256:'+build_deb.digest(wheel)+'\n'
        (root/'requirements-tui.txt').write_text(lock)
        audit={'checked_at':'2026-11-19','tool':'synthetic test audit',
               'requirements_sha256':hashlib.sha256(lock.encode()).hexdigest(),
               'results':{'dependencies':[{'name':'example','version':'1.0','vulns':[]}]}}
        (root/'docs/security/dependency-audit-1.0.0.json').write_text(json.dumps(audit))
        def git(*args):
            subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',
                            '-C',str(root),*args],check=True,capture_output=True,
                           env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1'})
        git('init','-q','--initial-branch=main');git('add','.')
        git('-c','user.name=Synthetic developer','-c','user.email=developer@example.invalid','commit','-qm','Synthetic release fixture')
        return wheels

    def test_bundle_rebuilds_offline_and_repeats_identically(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);root=parent/'repo';root.mkdir();wheels=self.fixture(root)
            with patch('scripts.build_release.ROOT',root):
                first=release.bundle(wheels,parent/'release-a')
                second=release.bundle(wheels,parent/'release-b')
                self.assertTrue(first['source_rebuild_verified'])
                self.assertEqual(first,second)
                self.assertEqual('1.0.0',first['version'])
                for path in (parent/'release-a').iterdir():
                    self.assertEqual(build_deb.digest(path),build_deb.digest(parent/'release-b'/path.name))
                (root/'unreviewed.txt').write_text('synthetic uncommitted change')
                with self.assertRaises(ValueError):release.bundle(wheels,parent/'dirty')
                with self.assertRaises(ValueError):release.bundle(wheels,parent/'release-a')

    def test_audit_binding_and_archive_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'repo';root.mkdir();self.fixture(root)
            path=root/'docs/security/dependency-audit-1.0.0.json'
            data=json.loads(path.read_text())
            self.assertEqual(1,release.verify_audit(root,'1.0.0')['dependencies'])
            data['results']['dependencies'][0]['vulns']=[{'id':'SYNTHETIC-EXAMPLE'}]
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):release.verify_audit(root,'1.0.0')
            for name in ('../outside','/absolute','bad\\entry'):
                with self.assertRaises(ValueError):release.safe_path(name)
