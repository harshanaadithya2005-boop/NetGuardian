"""Page separation, read-only incident review and immutable lockdown checks."""
import unittest
from pathlib import Path
from unittest.mock import MagicMock
import requests
import config
import test_router_quarantine as fixture
from router import write_safety

class StabilizationTests(unittest.TestCase):
    patch_value=fixture.RouterQuarantineTests.patch_value
    login=fixture.RouterQuarantineTests.login
    def setUp(self):
        fixture.RouterQuarantineTests.setUp(self)
        write_safety.LOCK_FILE.write_text('Retained test incident lock')
        self.patch_value(config,'VIVA_DATABASE_PATH',Path(self.temp.name)/'viva.db')

    def test_interfaces_are_separate_and_original_pages_work(self):
        home=self.http.get('/').data
        self.assertIn(b'stats-grid',home);self.assertIn(b'devices-table-body',home)
        self.assertNotIn(b'id="security-pipeline"',home);self.assertNotIn(b'id="viva-lab"',home)
        self.assertNotIn(b'simulation-panel',home)
        threat=self.http.get('/threat-detection').data
        self.assertIn(b'id="security-pipeline"',threat);self.assertIn(b'id="incident-review"',threat)
        self.assertNotIn(b'id="viva-lab"',threat)
        viva=self.http.get('/viva-lab').data
        self.assertIn(b'id="viva-lab"',viva);self.assertIn(b'simulation-panel',viva)
        self.assertNotIn(b'id="security-pipeline"',viva)
        for path in ['/devices','/alerts','/analytics','/reports',f'/device/{self.device}']:
            self.assertEqual(self.http.get(path).status_code,200)

    def test_incident_review_auth_csrf_and_no_unlock(self):
        self.assertEqual(self.http.get('/api/router/incident').status_code,401)
        headers=self.login()
        self.assertTrue(self.http.get('/api/admin/session').json['authenticated'])
        self.assertEqual(self.http.post('/api/router/incident/verify',json={}).status_code,403)
        before=write_safety.LOCK_FILE.read_bytes()
        result=self.http.post('/api/router/incident/verify',json={'approve':True,'unlock':True},headers=headers)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json['configuration_writes'],0)
        self.assertFalse(result.json['ready_for_manual_live']);self.assertFalse(result.json['unlock_available'])
        self.assertEqual(result.json['root_cause'],'UNCONFIRMED')
        self.assertEqual(self.router.writes,[]);self.assertEqual(write_safety.LOCK_FILE.read_bytes(),before)
        live=self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=headers)
        self.assertEqual(live.json['code'],'INCIDENT_LOCKDOWN')

    def test_read_only_guard_rejects_even_accidental_configuration_posts(self):
        headers=self.login();session=MagicMock();self.router.session=session
        original=session.request
        def accidentally_write():
            self.router.session.request('POST','http://192.168.8.1/api/wlan/multi-macfilter-settings')
        self.router.probe_quarantine_capabilities=accidentally_write
        result=self.http.post('/api/router/incident/verify',json={},headers=headers).json
        self.assertEqual(result['read_error']['code'],'READ_ONLY_GUARD')
        original.assert_not_called();self.assertEqual(result['configuration_writes'],0)

    def test_read_only_unreachable_router_keeps_all_gates_closed(self):
        headers=self.login();self.router.failure=requests.ConnectionError('Mock unreachable')
        result=self.http.post('/api/router/incident/verify',json={},headers=headers).json
        self.assertEqual(result['read_error']['code'],'ROUTER_UNREACHABLE')
        self.assertTrue(result['writes_locked']);self.assertFalse(result['ready_for_manual_live'])

    def test_replay_and_old_lab_work_without_physical_writes(self):
        headers=self.login()
        self.assertEqual(self.http.post('/api/security/viva/run',json={'scenario':'combined'}).status_code,403)
        self.assertEqual(self.http.post('/api/security/viva/run',json=[],headers=headers).status_code,400)
        normal=self.http.post('/api/security/viva/run',json={'scenario':'normal'},headers=headers)
        self.assertEqual(normal.json['risk']['risk_score'],20)
        combined=self.http.post('/api/security/viva/run',json={'scenario':'combined'},headers=headers)
        self.assertEqual(combined.json['risk']['risk_score'],70)
        self.assertEqual(combined.json['risk']['response_decision']['state'],'AUTO_SIMULATED')
        ident=combined.json['risk']['response_decision']['id']
        self.assertEqual(self.http.post('/api/security/viva/release',json={'decision_id':ident},headers=headers).status_code,200)
        self.assertIn('RELEASED',[d['state'] for d in self.http.get('/api/security/viva').json['security']['decisions']])
        self.assertEqual(self.http.post('/api/security/viva/reset',json={},headers=headers).json['security']['risks'],[])
        self.assertEqual(self.router.writes,[]);self.assertTrue(write_safety.locked())

if __name__=='__main__':unittest.main()
