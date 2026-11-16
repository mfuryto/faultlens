"""Constrained fresh-process acceptance uses invented data, never host reports."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class ConstrainedAcceptanceTests(unittest.TestCase):
    def test_one_cpu_address_space_profiles(self):
        script=Path(__file__).resolve().parents[1]/'scripts/vps_acceptance.py'
        result=subprocess.run([sys.executable,'-I',str(script),'--json'],capture_output=True,text=True,timeout=30,check=True)
        data=json.loads(result.stdout)
        self.assertTrue(data['synthetic'])
        self.assertFalse(data['deployment_test'])
        self.assertTrue(data['passed'])
        self.assertEqual(21,len(data['profiles']))
        self.assertEqual({128,256,512},{p['address_space_limit_mib'] for p in data['profiles']})
        self.assertTrue(all(p['cpu_affinity_count']==1 and p['passed'] for p in data['profiles']))
