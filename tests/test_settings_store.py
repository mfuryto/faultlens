"""Temporary invented preferences test persistence, validation and safe file handling."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from faultlens.settings_store import SettingsStore,MAX_BYTES
from faultlens.tui_model import Settings


class SettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)/'config'; self.store=SettingsStore(self.base)
        self.defaults=Settings.administrator_defaults()

    def write(self,value):
        self.base.mkdir(mode=0o700,exist_ok=True)
        self.store.path.parent.mkdir(mode=0o700,exist_ok=True)
        self.store.path.write_text(value); self.store.path.chmod(0o600)

    def test_missing_preferences_use_defaults_without_creating_directories(self):
        settings,message=self.store.load(self.defaults)
        self.assertIs(self.defaults,settings); self.assertFalse(self.base.exists())
        self.assertIn('defaults',message)

    def test_roundtrip_keeps_all_settings_and_only_settings_with_private_permissions(self):
        chosen=Settings.administrator_defaults(); chosen.sample_seconds=0.2
        chosen.boot_selector='a'*32; chosen.atop_date='20260101'; chosen.atop_extended=True
        chosen.since_us='100'; chosen.until_us='200'; chosen.sockets=False
        self.store.save(chosen)
        actual,message=SettingsStore(self.base).load(self.defaults)
        self.assertEqual(chosen,actual); self.assertIn('loaded',message)
        data=json.loads(self.store.path.read_text())
        self.assertEqual({'schema_version','settings'},set(data))
        self.assertEqual(set(asdict(chosen)),set(data['settings']))
        self.assertEqual(0o700,stat.S_IMODE(self.store.path.parent.stat().st_mode))
        self.assertEqual(0o600,stat.S_IMODE(self.store.path.stat().st_mode))
        self.assertEqual(['settings.json'],[p.name for p in self.store.path.parent.iterdir()])

    def test_invalid_schema_types_ranges_and_combined_options_are_rejected_atomically(self):
        baseline={'schema_version':2,'settings':asdict(self.defaults)}
        texts=['not json','{}','{"schema_version":1,"schema_version":1,"settings":{}}',
               json.dumps({**baseline,'schema_version':True}),json.dumps({**baseline,'schema_version':3})]
        for key,value in (('investigation_mode','bad'),('investigation_mode','period'),('sockets',1),('boot_count',True),('sample_seconds','0.2'),
                          ('sample_seconds',float('nan')),('sample_seconds',99),('boot_count',99),
                          ('boot_selector',';id'),('atop_date','20260230'),('atop_extended',True),
                          ('until_us','-1'),('since_us','9'*65),('boot_selector','\x1b')):
            values={**baseline['settings'],key:value}
            texts.append(json.dumps({'schema_version':2,'settings':values}))
        texts.append(json.dumps({'schema_version':2,'settings':{**baseline['settings'],'evidence':'invented'}}))
        texts.append(json.dumps({'schema_version':2,'settings':{**baseline['settings'],'since_us':'200','until_us':'100'}}))
        for text in texts:
            with self.subTest(text=text):
                self.write(text); actual,message=self.store.load(self.defaults)
                self.assertIs(self.defaults,actual); self.assertIn('invalid',message)

    def test_oversized_file_is_rejected(self):
        self.write('x'*(MAX_BYTES+1))
        self.assertIs(self.defaults,self.store.load(self.defaults)[0])

    def test_file_symlink_is_not_read_or_overwritten(self):
        outside=Path(self.temp.name)/'outside'; outside.write_text('invented original')
        self.base.mkdir(mode=0o700)
        self.store.path.parent.mkdir(mode=0o700)
        self.store.path.symlink_to(outside)
        self.assertIs(self.defaults,self.store.load(self.defaults)[0])
        with self.assertRaises(OSError): self.store.save(self.defaults)
        self.assertEqual('invented original',outside.read_text()); self.assertTrue(self.store.path.is_symlink())

    def test_directory_symlinks_are_not_followed(self):
        real=Path(self.temp.name)/'real'; real.mkdir()
        self.base.symlink_to(real,target_is_directory=True)
        self.assertIs(self.defaults,self.store.load(self.defaults)[0])
        with self.assertRaises(OSError): self.store.save(self.defaults)
        self.assertEqual([],list(real.iterdir()))

    def test_shared_or_foreign_owned_paths_are_refused_without_chmod(self):
        self.store.save(self.defaults)
        for path in (self.store.path,self.store.path.parent,self.base):
            before=stat.S_IMODE(path.stat().st_mode); path.chmod(0o777)
            try:
                self.assertIs(self.defaults,self.store.load(self.defaults)[0])
                with self.assertRaises(ValueError): self.store.save(self.defaults)
                self.assertEqual(0o777,stat.S_IMODE(path.stat().st_mode))
            finally: path.chmod(before)
        with patch('faultlens.settings_store.os.geteuid',return_value=os.geteuid()+10000):
            self.assertIs(self.defaults,self.store.load(self.defaults)[0])
            with self.assertRaises(ValueError): self.store.save(self.defaults)

    def test_hardlinks_and_fifo_are_refused_without_blocking_or_writing(self):
        self.store.save(self.defaults)
        linked=Path(self.temp.name)/'linked'; os.link(self.store.path,linked)
        self.assertIs(self.defaults,self.store.load(self.defaults)[0])
        with self.assertRaises(ValueError): self.store.save(self.defaults)
        self.store.path.unlink(); linked.unlink(); os.mkfifo(self.store.path,0o600)
        self.assertIs(self.defaults,self.store.load(self.defaults)[0])
        with self.assertRaises(ValueError): self.store.save(self.defaults)

    def test_failed_atomic_replace_keeps_previous_settings_and_cleans_temporary_file(self):
        self.store.save(self.defaults); previous=self.store.path.read_bytes()
        changed=Settings.administrator_defaults(); changed.sockets=False
        with patch('faultlens.settings_store.os.replace',side_effect=OSError('invented disk failure')):
            with self.assertRaises(OSError): self.store.save(changed)
        self.assertEqual(previous,self.store.path.read_bytes())
        self.assertEqual(['settings.json'],[p.name for p in self.store.path.parent.iterdir()])

    def test_xdg_location_and_relative_xdg_fallback(self):
        with patch.dict(os.environ,{'XDG_CONFIG_HOME':str(self.base)}):
            self.assertEqual(self.store.path,SettingsStore().path)
        with patch.dict(os.environ,{'XDG_CONFIG_HOME':'relative'}),patch('pathlib.Path.home',return_value=Path(self.temp.name)):
            self.assertEqual(Path(self.temp.name)/'.config/faultlens/settings.json',SettingsStore().path)


    def test_version_one_migration_retains_scope_and_version_two_roundtrip(self):
        previous=asdict(Settings(boot_selector='a'*32,search_events=True,atop_date='20260101',since_us='100',until_us='200'))
        previous.pop('investigation_mode')
        original=dict(previous)
        self.write(json.dumps({'schema_version':1,'settings':previous}))
        loaded,message=self.store.load(self.defaults)
        self.assertIn('Migrated',message);self.assertEqual('period',loaded.investigation_mode)
        self.assertEqual(original,{key:value for key,value in asdict(loaded).items() if key!='investigation_mode'})
        self.store.save(loaded)
        self.assertEqual(2,json.loads(self.store.path.read_text())['schema_version'])
        self.assertEqual(loaded,self.store.load(self.defaults)[0])
        previous['until_us']=''
        self.write(json.dumps({'schema_version':1,'settings':previous}))
        legacy,message=self.store.load(self.defaults)
        self.assertEqual('',legacy.investigation_mode);self.assertEqual('100',legacy.since_us)
        previous['since_us']=''
        self.write(json.dumps({'schema_version':1,'settings':previous}))
        self.assertEqual('before-restart',self.store.load(self.defaults)[0].investigation_mode)


if __name__=='__main__': unittest.main()
