"""Focused mocked recovery tests. Never connect to the physical router."""
import json
import os
import time
import unittest
from unittest.mock import patch

import config
from database import db, models
from router import incident_closure, manual_mode, write_safety
import test_quarantine_identity as identity
from test_quarantine_identity import B, A


class ManualLiveRecoveryTests(unittest.TestCase):
    setUp = identity.QuarantineIdentityTests.setUp
    patch_value = identity.QuarantineIdentityTests.patch_value
    login = identity.QuarantineIdentityTests.login
    configure_three = identity.QuarantineIdentityTests.configure_three
    prepare = identity.QuarantineIdentityTests.prepare
    execute = identity.QuarantineIdentityTests.execute

    def setup_hardware_evidence(self):
        # ONLY isolated mock transport: a later authorized physical test must
        # produce equivalent audited evidence. No production guard is changed.
        write_safety.LOCK_FILE.write_text('test incident retained')
        os.utime(write_safety.LOCK_FILE, (time.time()-10, time.time()-10))
        with patch.object(write_safety, 'locked', return_value=False):
            self.configure_three()
            block = self.prepare(self.b, B).json
            self.assertEqual(self.execute(block).json['enforcement']['state'], 'ACTIVE')
            release = self.prepare(self.b, B, 'release').json
            self.assertEqual(self.execute(release).json['enforcement']['state'], 'RELEASED')
        manual_mode.switch('DEMO', 'mock restart')
        self.data = dict(confirmed=True, root_cause='Synthetic test evidence establishes and corrects the mock incident cause.',
                         hardware_test_approval='Separate explicit MOCK hardware test authorization reference',
                         block_operation_id=block['plan_id'], release_operation_id=release['plan_id'],
                         non_target_device_ids=[self.device],
                         observations={key: True for key in incident_closure.OBSERVATIONS})
        self.report = dict(filter_digest=self.router.snapshot.digest(), enabled_ssid_indices=['0'],
                           firmware=identity.fixture.FIRMWARE, identity_reviews=[
                               dict(device_id=self.b,eligible=True,mac=B),dict(device_id=self.device,eligible=True,mac=A)],
                           management_route={'wired_route_identified':True},saved_plan_identity_mismatches=[])

    def close(self):
        with patch('router.incident_review.verify_read_only', return_value=self.report):
            return self.http.post('/api/router/incident/close', json=self.data, headers=self.headers)

    def test_auth_csrf_and_observations_alone_cannot_unlock(self):
        write_safety.LOCK_FILE.write_text('retained')
        self.assertEqual(self.http.post('/api/router/incident/close',json={}).status_code,401)
        self.headers=self.login()
        self.assertEqual(self.http.post('/api/router/incident/close',json={}).status_code,403)
        rejected=self.http.post('/api/router/incident/close',json={'confirmed':True},headers=self.headers)
        self.assertEqual(rejected.json['code'],'CAUSE_UNRESOLVED')
        self.assertTrue(write_safety.locked());self.assertEqual(self.router.writes,[])

    def test_verified_closure_retains_marker_requires_mode_approval_after_restart(self):
        self.setup_hardware_evidence();before=write_safety.LOCK_FILE.read_bytes();writes=len(self.router.writes)
        self.assertEqual(self.close().status_code,200)
        self.assertEqual(write_safety.LOCK_FILE.read_bytes(),before)
        self.assertFalse(write_safety.locked());self.assertEqual(manual_mode.get_mode(),'DEMO')
        result=self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers)
        self.assertEqual(result.json['protection_mode'],'LIVE')
        manual_mode._mode='DEMO';manual_mode._generation+=1;manual_mode._grants={}
        self.assertFalse(write_safety.locked());self.assertEqual(manual_mode.get_mode(),'DEMO')
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers).status_code,200)
        self.assertEqual(len(self.router.writes),writes)

    def test_closure_corruption_marker_change_or_audit_change_relocks(self):
        self.setup_hardware_evidence();self.assertEqual(self.close().status_code,200)
        receipt=incident_closure._path();original=receipt.read_text()
        envelope=json.loads(original);envelope['record']['root_cause']='tampered'
        receipt.write_text(json.dumps(envelope));self.assertTrue(write_safety.locked())
        receipt.write_text(original);self.assertFalse(write_safety.locked())
        marker=write_safety.LOCK_FILE.read_bytes();write_safety.LOCK_FILE.write_text('new incident')
        self.assertTrue(write_safety.locked());write_safety.LOCK_FILE.write_bytes(marker)
        self.assertTrue(write_safety.locked())  # new marker timestamp, same text

    def test_missing_transport_or_historical_test_cannot_close(self):
        self.setup_hardware_evidence()
        conn=db.get_connection();conn.execute("DELETE FROM router_quarantine_audit WHERE actor='transport'");conn.commit();conn.close()
        self.assertEqual(self.close().json['code'],'POST_INCIDENT_TEST_REQUIRED')
        self.assertTrue(write_safety.locked())

    def test_stale_target_or_failed_restoration_never_closes(self):
        self.setup_hardware_evidence()
        self.report['identity_reviews'][0]['eligible']=False
        self.assertEqual(self.close().json['code'],'FRESH_VERIFICATION_FAILED')
        self.report['identity_reviews'][0]['eligible']=True
        self.report['filter_digest']='wrong'
        self.assertEqual(self.close().json['code'],'FRESH_VERIFICATION_FAILED')
        self.assertTrue(write_safety.locked())

    def test_changed_audit_revokes_closure_and_wrong_identity_rejected(self):
        self.setup_hardware_evidence()
        conn=db.get_connection();conn.execute('UPDATE router_quarantine_plans SET device_id=? WHERE id=?',(self.c,self.data['release_operation_id']));conn.commit();conn.close()
        self.assertEqual(self.close().json['code'],'HARDWARE_IDENTITY_MISMATCH')
        conn=db.get_connection();conn.execute('UPDATE router_quarantine_plans SET device_id=? WHERE id=?',(self.b,self.data['release_operation_id']));conn.commit();conn.close()
        self.assertEqual(self.close().status_code,200)
        conn=db.get_connection();conn.execute("UPDATE router_quarantine_audit SET message='changed' WHERE operation_id=?",(self.data['block_operation_id'],));conn.commit();conn.close()
        self.assertTrue(write_safety.locked())

    def test_current_router_mac_change_rejects_cached_target(self):
        self.configure_three()
        plan=self.prepare(self.b,B).json
        self.router.clients=[r for r in self.router.clients if r['mac']!=B]
        result=self.execute(plan)
        self.assertEqual(result.json['enforcement']['state'],'FAILED')
        self.assertEqual(result.json['enforcement']['error_code'],'WIFI_IDENTITY_UNVERIFIED')
        self.assertEqual(self.router.writes,[])

    def test_live_after_closure_and_release_in_demo_preserves_other_devices(self):
        self.setup_hardware_evidence();self.assertEqual(self.close().status_code,200)
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers).status_code,200)
        plan=self.prepare(self.b,B).json
        self.assertEqual(self.execute(plan).json['enforcement']['state'],'ACTIVE')
        self.assertFalse(self.router.snapshot.contains(A,['0']))
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'DEMO','confirmed':True},headers=self.headers).status_code,200)
        self.assertEqual(self.execute(self.prepare(self.b,B,'release').json).json['enforcement']['state'],'RELEASED')
        self.assertFalse(self.router.snapshot.contains(B,['0']));self.assertFalse(write_safety.locked())

    def test_firmware_change_after_closure_refuses_live_target(self):
        self.setup_hardware_evidence();self.assertEqual(self.close().status_code,200)
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers).status_code,200)
        original=self.router.probe_quarantine_capabilities
        def changed():
            report,snapshot=original();report['firmware']={'SoftwareVersion':'changed'};return report,snapshot
        self.router.probe_quarantine_capabilities=changed
        count=len(self.router.writes)
        self.assertEqual(self.prepare(self.b,B).json['code'],'HARDWARE_SCOPE_CHANGED')
        self.assertEqual(len(self.router.writes),count)


if __name__=='__main__':unittest.main()
