"""Normal dashboard control integration; all physical router calls are mocked."""
import json
import unittest
from unittest.mock import patch
import test_router_quarantine as fixture
MAC=fixture.MAC
from router import manual_mode
from router.mac_filter import WritePermit,QuarantineError
from database import db


class DashboardModeTests(unittest.TestCase):
    setUp=fixture.RouterQuarantineTests.setUp
    patch_value=fixture.RouterQuarantineTests.patch_value
    login=fixture.RouterQuarantineTests.login

    def mode(self,value,headers):
        return self.http.post('/api/protection-mode',json={'mode':value,'confirmed':True},headers=headers)
    def prepare(self,action,headers):
        return self.http.post(f'/api/device/{self.device}/router-quarantine/plan',json={'action':action,'mac':MAC,'ssid_indices':['0'],'allow_enable':True},headers=headers)
    def execute(self,plan,headers):
        return self.http.post('/api/router/quarantine/execute',json={'plan_id':plan['plan_id'],'confirmed':True,**{k:plan[k] for k in ('device_id','mac','ssid_indices','expected_digest')}},headers=headers)
    def block(self,headers):
        self.assertEqual(self.mode('LIVE',headers).status_code,200)
        plan=self.prepare('quarantine',headers)
        self.assertEqual(plan.status_code,200)
        response=self.execute(plan.json,headers)
        self.assertEqual(response.status_code,200)
        return response.json

    def test_startup_default_and_login_do_not_enable_live_or_write(self):
        self.assertEqual(self.http.get('/api/protection-mode').json['protection_mode'],'DEMO')
        self.login()
        self.assertEqual(manual_mode.get_mode(),'DEMO')
        self.assertEqual(self.router.writes,[])
        self.assertEqual(self.prepare('quarantine',self.login()).json['code'],'LIVE_MODE_REQUIRED')

    def test_switch_requires_admin_csrf_and_confirmation_and_never_router_io(self):
        url='/api/protection-mode'
        self.assertEqual(self.http.post(url,json={'mode':'LIVE','confirmed':True}).status_code,401)
        headers=self.login()
        self.assertEqual(self.http.post(url,json={'mode':'LIVE','confirmed':True}).status_code,403)
        self.assertEqual(self.http.post(url,json={'mode':'LIVE'},headers=headers).status_code,400)
        with patch.object(self.router,'probe_quarantine_capabilities',side_effect=AssertionError('Mode switch must not touch router')):
            self.assertEqual(self.mode('LIVE',headers).status_code,200)
            self.assertEqual(self.mode('DEMO',headers).status_code,200)
        conn=db.get_connection()
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM protection_mode_audit').fetchone()[0],2);conn.close()
        self.assertEqual(self.router.writes,[])

    def test_live_block_and_release_in_demo_without_legacy_test_flags(self):
        import config
        self.patch_value(config,'PROTECTION_MODE','DEMO')
        self.patch_value(config,'ROUTER_WRITES_ENABLED',False)
        self.patch_value(config,'RECOVERY_CONFIRMED',False)
        self.patch_value(config,'AUTHORIZED_TEST_MACS',frozenset())
        headers=self.login();result=self.block(headers)
        self.assertEqual(result['enforcement']['state'],'ACTIVE')
        self.assertEqual(self.mode('DEMO',headers).status_code,200)
        self.assertEqual(len(self.router.writes),1)
        status=self.http.get('/api/protection-mode').json
        self.assertEqual(status['pending_managed_devices'][0]['device_id'],self.device)
        plan=self.prepare('release',headers)
        self.assertTrue(plan.json['can_execute'])
        result=self.execute(plan.json,headers)
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json['enforcement']['state'],'RELEASED')
        self.assertFalse(result.json['enforcement']['verified_enforced'])
        self.assertEqual(len(self.router.writes),2)

    def test_mode_change_invalidates_old_block_confirmation(self):
        headers=self.login();self.mode('LIVE',headers)
        plan=self.prepare('quarantine',headers).json
        self.mode('DEMO',headers);self.mode('LIVE',headers)
        result=self.execute(plan,headers)
        self.assertEqual(result.status_code,409)
        self.assertEqual(result.json['code'],'MODE_CHANGED')
        self.assertEqual(self.router.writes,[])

    def test_release_plan_remains_usable_after_mode_change(self):
        headers=self.login();self.block(headers)
        plan=self.prepare('release',headers).json
        self.mode('DEMO',headers)
        self.assertEqual(self.execute(plan,headers).json['enforcement']['state'],'RELEASED')

    def test_restart_to_demo_preserves_owned_release_path(self):
        headers=self.login();self.block(headers)
        # Model a fresh process: runtime mode and in-memory grants disappear.
        manual_mode._mode='DEMO';manual_mode._generation=0;manual_mode._grants.clear()
        headers=self.login()
        plan=self.prepare('recover',headers).json
        self.assertEqual(self.execute(plan,headers).json['enforcement']['state'],'RELEASED')

    def test_lowercase_router_mac_release_and_readback(self):
        headers=self.login();self.block(headers)
        self.router.snapshot.ssids['0'].find('WifiMacFilterMac0').text=MAC.lower()
        self.mode('DEMO',headers)
        result=self.execute(self.prepare('release',headers).json,headers)
        self.assertEqual(result.json['enforcement']['state'],'RELEASED')

    def test_failed_readback_is_not_reported_as_active(self):
        headers=self.login();self.mode('LIVE',headers);self.router.no_apply=True
        result=self.execute(self.prepare('quarantine',headers).json,headers)
        self.assertEqual(result.status_code,409)
        self.assertEqual(result.json['enforcement']['state'],'FAILED')
        self.assertIsNone(result.json['enforcement']['verified_enforced'])
        self.mode('DEMO',headers)
        self.router.no_apply=False
        recovered=self.execute(self.prepare('recover',headers).json,headers)
        self.assertEqual(recovered.json['enforcement']['state'],'RELEASED')

    def test_database_demo_flags_cannot_mark_live_enforcement(self):
        conn=db.get_connection();conn.execute("UPDATE devices SET status='quarantined' WHERE id=?",(self.device,));conn.commit();conn.close()
        state=self.http.get(f'/api/device/{self.device}/enforcement').json
        self.assertEqual(state['state'],'NOT_REQUESTED')
        self.assertIsNone(state['verified_enforced'])

    def test_reconcile_keeps_recovery_available_for_incomplete_mode_restore(self):
        headers=self.login();self.block(headers);self.mode('DEMO',headers)
        self.router.snapshot.ssids['0'].find('WifiMacFilterMac0').text=''
        result=self.http.post(f'/api/device/{self.device}/router-quarantine/reconcile',headers=headers)
        self.assertEqual(result.json['enforcement']['state'],'FAILED')
        self.assertFalse(result.json['enforcement']['verified_enforced'])
        result=self.execute(self.prepare('recover',headers).json,headers)
        self.assertEqual(result.json['enforcement']['state'],'RELEASED')
        self.assertEqual(self.router.snapshot.ssids['0'].findtext('WifiMacFilterStatus'),'0')

    def test_schema_v3_upgrade_preserves_active_ownership_and_recovery(self):
        import sqlite3
        from pathlib import Path
        headers=self.login();self.block(headers)
        conn=db.get_connection()
        owned=tuple(conn.execute('SELECT * FROM router_quarantines').fetchone())
        conn.execute('ALTER TABLE router_quarantine_plans DROP COLUMN control_channel')
        conn.execute('ALTER TABLE router_quarantine_plans DROP COLUMN mode_generation')
        conn.execute('DROP TABLE protection_mode_audit');conn.execute('PRAGMA user_version=3')
        conn.commit();conn.close()
        db.initialize_database()
        backups=list(Path(self.temp.name).glob('*.before_schema_*.db'))
        self.assertEqual(len(backups),1)
        from contextlib import closing
        with closing(sqlite3.connect(backups[0])) as backup:
            self.assertEqual(backup.execute('PRAGMA user_version').fetchone()[0],3)
        conn=db.get_connection()
        self.assertEqual(tuple(conn.execute('SELECT * FROM router_quarantines').fetchone()),owned)
        self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0],5)
        conn.close()
        self.mode('DEMO',headers)
        self.assertEqual(self.execute(self.prepare('release',headers).json,headers).json['enforcement']['state'],'RELEASED')

    def test_post_grant_is_single_use_and_mode_checked_at_send(self):
        from router.mac_filter import FilterSnapshot,plan_block
        headers=self.login();self.mode('LIVE',headers)
        before=FilterSnapshot(self.router.snapshot.xml());after,_=plan_block(before,MAC,['0'],True)
        import time
        token=manual_mode.grant('quarantine',MAC,before,after,'test-admin',time.time()+60,manual_mode.generation())
        permit=WritePermit('operation',MAC,before.digest(),after.digest(),time.time()+60,token)
        with manual_mode.authorized_wire_write(permit,before,after):pass
        with self.assertRaises(QuarantineError):
            with manual_mode.authorized_wire_write(permit,before,after):pass

if __name__=='__main__':unittest.main()
