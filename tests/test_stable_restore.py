"""Clean-dashboard and existing administrator sign-in restoration regressions."""
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
import config
import test_application as fixture
from router import control_api

class StableRestoreTests(unittest.TestCase):
    def setUp(self):
        fixture.ApplicationTests.setUp(self)
        self.password='isolated-restore-test-only'
        self.hash_patch=patch.object(config,'ADMIN_PASSWORD_HASH',generate_password_hash(self.password))
        self.hash_patch.start();self.addCleanup(self.hash_patch.stop)
        control_api._attempts.clear()

    def test_clean_home_and_profile_keep_original_controls(self):
        for path in ['/',f'/device/{self.device}']:
            response=self.client.get(path);self.assertEqual(response.status_code,200)
            self.assertNotIn(b'id="security-pipeline"',response.data)
            self.assertNotIn(b'id="viva-lab"',response.data)
            self.assertNotIn(b'security-pipeline.js',response.data)
            self.assertIn(b'router-admin-login',response.data)
        self.assertIn(b'stats-grid',self.client.get('/').data)
        self.assertEqual(self.client.get('/api/security').status_code,200)
        self.assertNotIn(b'Attack Simulation &amp; Demonstration Lab',self.client.get('/').data)

    def test_scrypt_login_rejection_success_session_and_csrf(self):
        token=self.client.get('/api/admin/session').json['csrf_token']
        self.assertEqual(self.client.post('/api/admin/login',json={'password':self.password}).status_code,403)
        bad=self.client.post('/api/admin/login',json={'password':'invalid-test-password'},headers={'X-CSRF-Token':token})
        self.assertEqual(bad.status_code,401)
        good=self.client.post('/api/admin/login',json={'password':self.password},headers={'X-CSRF-Token':token})
        self.assertEqual(good.status_code,200)
        self.assertNotEqual(good.json['csrf_token'],token)
        self.assertTrue(self.client.get('/api/admin/session').json['authenticated'])
        self.assertEqual(self.client.post('/api/admin/logout',headers={'X-CSRF-Token':token}).status_code,403)
        self.assertEqual(self.client.post('/api/admin/logout',headers={'X-CSRF-Token':good.json['csrf_token']}).status_code,200)
        self.assertFalse(self.client.get('/api/admin/session').json['authenticated'])

    def test_all_original_pages_and_safety_lock(self):
        for path in ['/devices','/alerts','/analytics','/reports','/api/health','/api/analytics']:
            self.assertEqual(self.client.get(path).status_code,200)
        status=self.client.get('/api/protection-mode').json
        self.assertEqual(status['protection_mode'],'DEMO');self.assertTrue(status['writes_locked'])
        self.assertFalse(config.AUTO_QUARANTINE)

if __name__=='__main__':unittest.main()
