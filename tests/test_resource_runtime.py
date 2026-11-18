"""Prepared bytecode is private, verified against source, and disposable."""
import os
import py_compile
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.resource_runtime import prepared


class RuntimeTests(unittest.TestCase):
    def test_cache_is_private_preserves_source_and_rejects_stale_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'sample.py'
            source.write_text('value = 1\n')
            old_prefix=sys.pycache_prefix
            with patch('scripts.resource_runtime.source_files',return_value=[source]), prepared() as runtime:
                prefix=runtime['interpreter_options'][1].split('=',1)[1]
                cache=Path(prefix)
                self.assertEqual(0,cache.stat().st_mode & 0o077)
                self.assertEqual(old_prefix,sys.pycache_prefix)
                self.assertFalse((source.parent/'__pycache__').exists())
                files=list(cache.rglob('*.pyc'))
                self.assertEqual(1,len(files))
                self.assertEqual(3,int.from_bytes(files[0].read_bytes()[4:8],'little'))
                self.assertEqual('value = 1\n',source.read_text())
                cached_code='import importlib.util,sys; spec=importlib.util.spec_from_file_location("sample",sys.argv[1]); module=importlib.util.module_from_spec(spec); sys.addaudithook(lambda event,args: (_ for _ in ()).throw(AssertionError("Unexpected recompilation")) if event=="compile" else None); spec.loader.exec_module(module); print(module.value)'
                cached=subprocess.run([sys.executable,'-I','-B',*runtime['interpreter_options'],
                                       '-c',cached_code,str(source)],capture_output=True,text=True,check=True)
                self.assertEqual('1',cached.stdout.strip())
                # CHECKED_HASH validates content even for an equal-size, equal-mtime edit.
                stamp=source.stat()
                source.write_text('value = 2\n')
                os.utime(source,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
                code='import importlib.util,sys; spec=importlib.util.spec_from_file_location("sample",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); print(module.value)'
                child=subprocess.run([sys.executable,'-I','-B',*runtime['interpreter_options'],
                                      '-c',code,str(source)],capture_output=True,text=True,check=True)
                self.assertEqual('2',child.stdout.strip())
            self.assertFalse(cache.exists())

    def test_preparation_failure_restores_prefix_and_removes_cache(self):
        old_prefix=sys.pycache_prefix
        prefixes=[]
        compile_source=py_compile.compile
        def compile_record(*args,**kwargs):
            prefixes.append(Path(sys.pycache_prefix))
            return compile_source(*args,**kwargs)
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'invalid.py';source.write_text('invalid syntax here\n')
            with patch('scripts.resource_runtime.source_files',return_value=[source]), patch('scripts.resource_runtime.py_compile.compile',side_effect=compile_record):
                with self.assertRaises(py_compile.PyCompileError):
                    with prepared(): self.fail('Compilation failure must not start measured workers')
        self.assertEqual(old_prefix,sys.pycache_prefix)
        self.assertTrue(prefixes)
        self.assertTrue(all(not path.exists() for path in prefixes))
