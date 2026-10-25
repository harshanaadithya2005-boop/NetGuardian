"""Private-address verification uses mocked Huawei clients and isolated SQLite."""
import unittest
from unittest.mock import patch
import config
import test_quarantine_identity as identity
from router import wifi_identity
from database import db

A=identity.A
B=identity.B


class WifiIdentityTests(unittest.TestCase):
    setUp=identity.QuarantineIdentityTests.setUp
    patch_value=identity.QuarantineIdentityTests.patch_value
    login=identity.QuarantineIdentityTests.login
    configure_three=identity.QuarantineIdentityTests.configure_three
    prepare=identity.QuarantineIdentityTests.prepare
    execute=identity.QuarantineIdentityTests.execute

    def configure(self):
        self.configure_three()
        self.patch_value(config,'STABLE_WIFI_IDENTITY_BINDINGS',{})
        self.patch_value(wifi_identity,'_bindings',{})

    def verify(self,device=None,**overrides):
        data=dict(mac=A,ip='192.168.8.101',ssid_indices=['0'],stable_mac_confirmed=True,non_management=True,confirmed=True)
        data.update(overrides)
        return self.http.post(f'/api/device/{device or self.device}/router-identity/verify',json=data,headers=self.headers)

    def test_private_address_verified_then_exact_wire_block_and_release(self):
        self.configure()
        self.assertEqual(self.prepare(self.device,A).json['code'],'RANDOMIZED_IDENTITY_UNVERIFIED')
        self.assertEqual(self.verify(mac=A.lower()).status_code,200)
        self.assertEqual(self.router.writes,[])
        plan=self.prepare(self.device,A).json
        self.assertEqual(plan['mac'],A)
        self.assertEqual(self.execute(plan).json['enforcement']['state'],'ACTIVE')
        self.assertTrue(self.router.snapshot.contains(A,['0']))
        self.assertFalse(self.router.snapshot.contains(B,['0']))
        self.assertFalse(self.router.snapshot.contains(identity.C,['0']))
        self.assertEqual(self.execute(self.prepare(self.device,A,'release').json).json['enforcement']['state'],'RELEASED')

    def test_other_device_mac_and_wrong_ip_never_bind(self):
        self.configure()
        self.assertEqual(self.verify(device=self.b).json['code'],'IDENTITY_CHANGED')
        self.assertEqual(self.verify(ip='192.168.8.103').json['code'],'IDENTITY_CHANGED')
        self.assertEqual(wifi_identity._bindings,{})
        self.assertEqual(self.router.writes,[])

    def test_unknown_rotating_or_conflicting_client_is_rejected(self):
        self.configure()
        self.router.clients=[r for r in self.router.clients if r['mac']!=A]
        self.assertEqual(self.verify().json['code'],'WIFI_IDENTITY_UNVERIFIED')
        self.assertEqual(self.router.writes,[])

    def test_auth_csrf_and_independent_confirmations_required(self):
        self.configure()
        self.assertEqual(self.verify(stable_mac_confirmed=False).json['code'],'IDENTITY_CONFIRMATION_REQUIRED')
        self.assertEqual(self.verify(non_management=False).json['code'],'IDENTITY_CONFIRMATION_REQUIRED')
        self.assertEqual(self.http.post(f'/api/device/{self.device}/router-identity/verify',json={}).status_code,403)
        other=self.http.application.test_client()
        self.assertEqual(other.post(f'/api/device/{self.device}/router-identity/verify',json={}).status_code,401)
        self.assertEqual(self.router.writes,[])

    def test_expiry_logout_and_restart_require_new_verification(self):
        self.configure();self.assertEqual(self.verify().status_code,200)
        for value in wifi_identity._bindings.values():value['expires_at']=0
        self.assertEqual(self.prepare(self.device,A).json['code'],'RANDOMIZED_IDENTITY_UNVERIFIED')
        self.assertEqual(self.verify().status_code,200)
        self.headers=self.login()
        self.assertEqual(self.prepare(self.device,A).json['code'],'RANDOMIZED_IDENTITY_UNVERIFIED')
        self.assertEqual(self.verify().status_code,200)
        wifi_identity._bindings.clear()
        self.assertEqual(self.prepare(self.device,A).json['code'],'RANDOMIZED_IDENTITY_UNVERIFIED')

    def test_identity_rechecked_after_verification_and_plan(self):
        self.configure();self.assertEqual(self.verify().status_code,200)
        plan=self.prepare(self.device,A).json
        self.router.clients=[r for r in self.router.clients if r['mac']!=A]
        self.assertEqual(self.execute(plan).json['enforcement']['error_code'],'WIFI_IDENTITY_UNVERIFIED')
        self.assertEqual(self.router.writes,[])

    def test_duplicate_mac_management_and_multiple_ssids_refused(self):
        self.configure()
        with patch('response.router_quarantine.local_identities',return_value=({'192.168.8.101'},{A})):
            self.assertEqual(self.verify().json['code'],'PROTECTED_DEVICE')
        self.router.enabled_wifi_scopes=lambda:['0','1']
        self.assertEqual(self.verify().json['code'],'SSID_IDENTITY_UNVERIFIED')
        self.router.enabled_wifi_scopes=lambda:['0']
        conn=db.get_connection()
        try:
            conn.execute('UPDATE devices SET mac_address=? WHERE id=?',(' '+A.lower()+' ',self.c));conn.commit()
        finally:conn.close()
        self.assertEqual(self.verify().json['code'],'AMBIGUOUS_IDENTITY')
        self.assertEqual(self.router.writes,[])

    def test_audit_and_form_are_present_without_enforcement_success(self):
        self.configure();self.assertEqual(self.verify().status_code,200)
        self.assertIn(b'router-identity-form',self.http.get(f'/device/{self.device}').data)
        conn=db.get_connection()
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM router_quarantine_audit WHERE action='verify_identity' AND state='IDENTITY_VERIFIED'").fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM router_quarantines').fetchone()[0],0)
        finally:conn.close()
        self.assertEqual(self.router.writes,[])


if __name__=='__main__':unittest.main()
