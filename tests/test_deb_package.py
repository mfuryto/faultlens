"""Synthetic wheel/package fixtures; no host install, network or native evidence."""
import hashlib
import io
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import build_deb
from faultlens.presentation import local_command
from scripts.package_acceptance import IMAGES


class DebPackageTests(unittest.TestCase):
    def wheel(self,path,extra=None,tag='py3-none-any'):
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('example-1.0.dist-info/WHEEL','Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: '+tag+'\n')
            archive.writestr('example-1.0.dist-info/licenses/LICENSE','Synthetic permissive license fixture\n')
            archive.writestr('example/__init__.py','value = 1\n')
            if extra:
                archive.writestr(*extra)

    def test_wheel_lock_rejects_missing_extra_changed_and_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);wheelhouse=root/'wheels';wheelhouse.mkdir()
            wheel=wheelhouse/'example-1.0-py3-none-any.whl';self.wheel(wheel)
            pin='example==1.0 --hash=sha256:'+build_deb.digest(wheel)+'\n'
            (root/'requirements-tui.txt').write_text(pin)
            with patch('scripts.build_deb.ROOT',root):
                self.assertEqual(1,len(build_deb.locked_wheels(wheelhouse)))
                original=wheel.read_bytes();wheel.write_bytes(original+b'changed')
                with self.assertRaises(ValueError):build_deb.locked_wheels(wheelhouse)
                wheel.write_bytes(original);extra=wheelhouse/'unexpected.whl';extra.write_bytes(b'invented')
                with self.assertRaises(ValueError):build_deb.locked_wheels(wheelhouse)
                extra.unlink();wheel.unlink()
                with self.assertRaises(ValueError):build_deb.locked_wheels(wheelhouse)
                target=root/'target.whl';target.write_bytes(original);wheel.symlink_to(target)
                with self.assertRaises(ValueError):build_deb.locked_wheels(wheelhouse)

    def test_universal_wheel_layout_rejects_escape_symlink_native_and_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for index,name in enumerate(('../escaped.py','/absolute.py','example.data/scripts/run','example\\bad.py')):
                wheel=root/(str(index)+'.whl');self.wheel(wheel,(name,'synthetic'))
                with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,root/('payload'+str(index)))
            link=zipfile.ZipInfo('example/link');link.external_attr=(stat.S_IFLNK|0o777)<<16
            wheel=root/'symlink.whl';self.wheel(wheel,(link,'synthetic-target'))
            with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,root/'link-payload')
            wheel=root/'native.whl';self.wheel(wheel,tag='cp311-cp311-linux_x86_64')
            with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,root/'native-payload')
            wheel=root/'pure.whl';self.wheel(wheel)
            with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,root/'wrong-hash','0'*64)
            outside=root/'outside';outside.mkdir()
            redirect=root/'redirect';redirect.mkdir()
            (redirect/'example').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,redirect)
            self.assertFalse((outside/'__init__.py').exists())
            build_deb.unpack_wheel(wheel,root/'pure')
            with self.assertRaises(ValueError):build_deb.unpack_wheel(wheel,root/'pure')
            self.assertFalse((root/'escaped.py').exists())

    @unittest.skipUnless(shutil.which('dpkg-deb'),'Debian archive builder unavailable')
    def test_artifact_is_reproducible_private_and_has_no_maintainer_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir()
            for name in ('faultlens','packaging/debian','docs','wheels'):(source/name).mkdir(parents=True)
            (source/'packaging/debian/application-files.txt').write_text('faultlens/__init__.py\n')
            (source/'faultlens/local_private.py').write_text('value = \"synthetic unreviewed module\"\n')
            (source/'faultlens/__init__.py').write_text('__version__ = "0.1.0.dev0"\n')
            for name in ('control','faultlens','README.Debian'):
                shutil.copyfile(build_deb.ROOT/'packaging/debian'/name,source/'packaging/debian'/name)
            for name in ('LICENSE','NOTICE','README.md','docs/third-party.md'):
                (source/name).write_text('Synthetic package document fixture.\n')
            wheel=source/'wheels/example.whl';self.wheel(wheel)
            (source/'requirements-tui.txt').write_text('example==1.0 --hash=sha256:'+build_deb.digest(wheel)+'\n')
            with patch('scripts.build_deb.ROOT',source):
                first=build_deb.build(source/'wheels',root/'first',version='0.1.0~dev0+test0',epoch=1795000000)
                second=build_deb.build(source/'wheels',root/'second',version='0.1.0~dev0+test0',epoch=1795000000)
                self.assertEqual(build_deb.digest(first),build_deb.digest(second))
                with self.assertRaises(ValueError):build_deb.build(source/'wheels',root/'first',version='0.1.0~dev0+test0',epoch=1795000000)
                with self.assertRaises(ValueError):build_deb.build(source/'wheels',root/'bad',version='1.0',epoch=1795000000)
            payload=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(first)])
            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                entries=archive.getmembers();names={item.name for item in entries}
                self.assertTrue(all(item.uid==0 and item.gid==0 for item in entries))
                self.assertTrue(all(name=='.' or name.startswith('./usr') for name in names))
                self.assertEqual('/usr/share/faultlens/bin/faultlens',archive.getmember('./usr/bin/faultlens').linkname)
                self.assertIn('./usr/share/faultlens/vendor/example-1.0.dist-info/licenses/LICENSE',names)
                self.assertIn('./usr/share/doc/faultlens/build-manifest.json',names)
                self.assertIn('./usr/share/doc/faultlens/LICENSE',names)
                self.assertTrue(all(not item.mode & 0o6000 for item in entries))
                self.assertNotIn('./usr/share/faultlens/faultlens/local_private.py',names)
            control=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(first)])
            with tarfile.open(fileobj=io.BytesIO(control)) as archive:
                self.assertEqual({'.','./control'},{item.name for item in archive.getmembers()})
                content=archive.extractfile('./control').read().decode()
                self.assertIn('Depends: python3 (>= 3.11)',content)
                self.assertNotIn('Recommends:',content)
                self.assertNotIn('atop',content)

    def test_installed_frontend_failure_requests_package_reinstallation(self):
        from faultlens.tui import run
        out=io.StringIO()
        with (patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),
              patch.dict('os.environ',{'TERM':'xterm'}),
              patch('importlib.metadata.version',return_value='unreviewed'),
              patch('faultlens.tui.__file__','/usr/share/faultlens/faultlens/tui.py')):
            self.assertEqual(1,run(stderr=out))
        self.assertIn('Reinstall a verified Faultlens .deb',out.getvalue())
        self.assertNotIn('pip',out.getvalue())
        self.assertEqual({'debian-12','ubuntu-24.04'},set(IMAGES))
        for image in IMAGES.values(): self.assertRegex(image,r'^(debian|ubuntu)@sha256:[0-9a-f]{64}$')

    def test_installed_suggestions_use_public_launcher_without_changing_source_usage(self):
        self.assertEqual('./bin/faultlens status',local_command('./bin/faultlens status'))
        with patch('faultlens.presentation.__file__','/usr/share/faultlens/faultlens/presentation.py'):
            self.assertEqual('faultlens status',local_command('./bin/faultlens status'))
            self.assertEqual('journalctl --list-boots',local_command('journalctl --list-boots'))
