"""Constrained fresh-process acceptance uses invented data, never host reports."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

from tests.resource_diagnostics import emit,capture


class ConstrainedAcceptanceTests(unittest.TestCase):
    def test_one_cpu_address_space_profiles(self):
        script=Path(__file__).resolve().parents[1]/'scripts/vps_acceptance.py'
        result=capture([sys.executable,'-I',str(script),'--json'],capture_output=True,text=True,timeout=30,check=False)
        emit(result)
        self.assertEqual(0,result.returncode,'Synthetic resource command failed; see bounded resource metadata above.')
        data=json.loads(result.stdout)
        self.assertTrue(data['synthetic'])
        self.assertEqual('private_checked_hash',data['runtime']['bytecode_cache'])
        self.assertGreater(data['runtime']['preparation_wall_seconds'],0)
        self.assertFalse(data['deployment_test'])
        self.assertTrue(data['passed'])
        self.assertEqual(21,len(data['profiles']))
        self.assertEqual({128,256,512},{p['address_space_limit_mib'] for p in data['profiles']})
        self.assertTrue(all(p['cpu_affinity_count']==1 and p['passed'] for p in data['profiles']))
