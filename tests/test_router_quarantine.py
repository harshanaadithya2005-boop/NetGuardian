"""Isolated router-control tests. No real router or production SQLite access."""
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

import requests
from werkzeug.security import generate_password_hash
import config
import app as web
from database import db,models
from response import router_quarantine as service
from router.mac_filter import FilterSnapshot,QuarantineError,plan_block,plan_release,WritePermit,FIRMWARE
from router.huawei_client import HuaweiRouterClient
from router import control_api,manual_mode
from router import write_safety

MAC='02:11:22:33:44:55'
DESKTOP='02:11:22:33:44:66'
OTHER='02:AA:BB:CC:DD:01'
FIXTURE=Path(__file__).parent/'fixtures/b310_mac_filter.xml'


class FakeRouter:
    def __init__(self):
        self.snapshot=FilterSnapshot(FIXTURE.read_text(encoding='utf-8'))
        self.writes=[];self.failure=None;self.write_failure=None;self.no_apply=False
    def close(self): pass
    def probe_quarantine_capabilities(self):
        if self.failure: raise self.failure
        return {'firmware':FIRMWARE,'filters':self.snapshot.summary()},FilterSnapshot(self.snapshot.xml())
    def read_mac_filter(self):
        if self.failure: raise self.failure
        return FilterSnapshot(self.snapshot.xml())
    def get_connected_wifi_devices(self):
        if self.failure: raise self.failure
        return [] if self.snapshot.contains(MAC,['0']) else [{'ip':'192.168.8.101','mac':MAC,'hostname':'mock-phone'}]
    def enabled_wifi_scopes(self):return ['0']
    def write_mac_filter(self,before,after,permit):
        permit.validate(before,after)
        if self.snapshot.digest()!=before.digest(): raise QuarantineError('CONCURRENT_CHANGE','Settings changed')
        self.writes.append(after.xml(request=True))
        if self.write_failure=='before': raise requests.ConnectionError('synthetic unreachable')
        if not self.no_apply: self.snapshot=FilterSnapshot(after.xml())
        if self.write_failure=='after': raise requests.Timeout('synthetic lost response after apply')


class RouterQuarantineTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]/'.test-work';root.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=root);self.addCleanup(self.temp.cleanup)
        self.patch_value(write_safety,'LOCK_FILE',Path(self.temp.name)/'mock-lock')
        self.patch_value(config,'STABLE_WIFI_IDENTITY_BINDINGS',{MAC:{'device_id':1,'ip':'192.168.8.101','hostname':'mock-phone','ssid_indices':['0']}})
        self.patch_value(manual_mode,'_mode','DEMO')
        self.patch_value(manual_mode,'_generation',0)
        self.patch_value(manual_mode,'_grants',{})
        self.patch_value(db,'DB_PATH',Path(self.temp.name)/'test.db')
        self.patch_value(config,'TARGET_NETWORK','192.168.8.0/24')
        self.patch_value(config,'PROTECTION_MODE','LIVE')
        self.patch_value(config,'ROUTER_WRITES_ENABLED',True)
        self.patch_value(config,'RECOVERY_CONFIRMED',True)
        self.patch_value(config,'AUTHORIZED_TEST_MACS',frozenset({MAC}))
        self.patch_value(config,'PROTECTED_MANAGEMENT_MACS',frozenset())
        self.patch_value(config,'PROTECTED_MANAGEMENT_IPS',frozenset())
        self.patch_value(config,'ADMIN_PASSWORD_HASH',generate_password_hash('test-only-password',method='pbkdf2:sha256:1000'))
        db.initialize_database()
        self.device=models.add_or_update_device('192.168.8.101',MAC,device_type='Mobile')
        self.router=FakeRouter()
        self.patch_value(service,'new_client',lambda:self.router)
        self.patch_value(service,'local_identities',lambda:({'192.168.8.102'},{DESKTOP}))
        web.app.config['TESTING']=True
        self.http=web.app.test_client()
        control_api._attempts.clear()
    def patch_value(self,target,name,value):
        p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)
    def plan(self,action='quarantine',indices=None,enable=True,session='test-admin'):
        return service.prepare(self.device,action,MAC,indices or ['0'],enable,session,'127.0.0.1')
    def execute(self,plan):
        return service.execute(plan['plan_id'],'test-admin','127.0.0.1')
    def assert_error(self,code,fn):
        with self.assertRaises(QuarantineError) as result: fn()
        self.assertEqual(result.exception.code,code)
    def login(self):
        token=self.http.get('/api/admin/session').json['csrf_token']
        response=self.http.post('/api/admin/login',json={'password':'test-only-password'},headers={'X-CSRF-Token':token})
        self.assertEqual(response.status_code,200)
        return {'X-CSRF-Token':response.json['csrf_token']}

    def test_block_readback_states_and_release_restore(self):
        original=self.router.snapshot.digest()
        state=self.execute(self.plan())
        self.assertEqual(state['state'],'ACTIVE');self.assertTrue(state['verified_enforced'])
        self.assertFalse(state['client_connected'])
        self.assertEqual(models.get_device_by_id(self.device)['status'],'online')
        conn=db.get_connection()
        states=[r[0] for r in conn.execute('SELECT state FROM router_quarantine_audit ORDER BY id')];conn.close()
        self.assertEqual(states,['REQUESTED','APPLYING','ACTIVE'])
        self.assertEqual(self.execute(self.plan('release'))['state'],'RELEASED')
        self.assertEqual(self.router.snapshot.digest(),original)

    def test_duplicate_execute_and_prepare_do_not_write_twice(self):
        plan=self.plan();self.execute(plan)
        self.assertEqual(self.execute(plan)['state'],'ACTIVE')
        self.assertTrue(self.plan()['idempotent'])
        self.assertEqual(len(self.router.writes),1)
        self.execute(self.plan('release'))
        self.assertTrue(self.plan('release')['idempotent'])
        self.assertEqual(len(self.router.writes),2)

    def test_authentication_rejected_journaled_without_write(self):
        plan=self.plan();self.router.failure=RuntimeError('synthetic auth rejected')
        result=self.execute(plan)
        self.assertEqual(result['state'],'FAILED');self.assertEqual(result['error_code'],'ROUTER_AUTH_REJECTED')
        self.assertIsNone(result['verified_enforced']);self.assertEqual(self.router.writes,[])

    def test_unreachable_router_and_timeout_before_write(self):
        plan=self.plan();self.router.failure=requests.ConnectionError('synthetic unreachable')
        result=self.execute(plan)
        self.assertEqual(result['error_code'],'ROUTER_UNREACHABLE');self.assertEqual(self.router.writes,[])

    def test_timeout_after_apply_reconcile_and_recovery(self):
        original=self.router.snapshot.digest()
        self.router.write_failure='after'
        result=self.execute(self.plan())
        self.assertEqual(result['state'],'FAILED');self.assertIsNone(result['verified_enforced'])
        self.assertEqual(service.reconcile(self.device)['state'],'ACTIVE')
        self.router.write_failure=None
        self.assertEqual(self.execute(self.plan('recover'))['state'],'RELEASED')
        self.assertEqual(self.router.snapshot.digest(),original)

    def test_readback_mismatch_never_claims_active(self):
        self.router.no_apply=True
        result=self.execute(self.plan())
        self.assertEqual(result['state'],'FAILED');self.assertEqual(result['error_code'],'VERIFICATION_FAILED')
        self.assertIsNone(result['verified_enforced'])
        self.assertEqual(service.reconcile(self.device)['state'],'RELEASED')

    def test_current_modes_and_unmanaged_rules_are_not_overwritten(self):
        self.assert_error('MODE_CHANGE_REQUIRED',lambda:self.plan(enable=False))
        self.router.snapshot.ssids['0'].find('WifiMacFilterStatus').text='1'
        self.assert_error('WHITELIST_MODE',self.plan)
        self.router.snapshot.ssids['0'].find('WifiMacFilterStatus').text='0'
        self.router.snapshot.ssids['0'].find('WifiMacFilterMac0').text=OTHER
        self.assert_error('MODE_CHANGE_REQUIRED',self.plan)
        self.router.snapshot.ssids['0'].find('WifiMacFilterStatus').text='2'
        self.router.snapshot.ssids['0'].find('WifiMacFilterMac1').text=MAC
        self.assert_error('EXISTING_RULE',self.plan)
        self.assertEqual(self.router.writes,[])

    def test_existing_rules_and_unknown_fields_preserved_on_block_release(self):
        node=self.router.snapshot.ssids['0'];node.find('WifiMacFilterStatus').text='2'
        node.find('WifiMacFilterMac0').text=OTHER;node.find('wifihostname0').text='Keep this router rule'
        ET.SubElement(node,'VendorExtra').text='retain'
        original=self.router.snapshot.digest()
        self.execute(self.plan())
        self.assertEqual(self.router.snapshot.ssids['0'].findtext('WifiMacFilterMac0'),OTHER)
        self.execute(self.plan('release'))
        self.assertEqual(self.router.snapshot.digest(),original)

    def test_concurrent_edit_rejects_before_write(self):
        plan=self.plan();self.router.snapshot.ssids['2'].find('wifihostname3').text='External change'
        result=self.execute(plan)
        self.assertEqual(result['state'],'FAILED');self.assertEqual(result['error_code'],'CONCURRENT_CHANGE')
        self.assertEqual(self.router.writes,[])
        self.assertEqual(self.router.snapshot.ssids['2'].findtext('wifihostname3'),'External change')

    def test_recovery_preserves_later_external_rules(self):
        self.execute(self.plan())
        self.router.snapshot.ssids['0'].find('WifiMacFilterMac5').text=OTHER
        self.router.snapshot.ssids['0'].find('wifihostname5').text='Do not overwrite'
        result=self.execute(self.plan('recover'))
        self.assertEqual(result['state'],'RELEASED')
        node=self.router.snapshot.ssids['0']
        self.assertEqual(node.findtext('WifiMacFilterMac5'),OTHER)
        self.assertEqual(node.findtext('wifihostname5'),'Do not overwrite')
        self.assertEqual(node.findtext('WifiMacFilterStatus'),'2')

    def test_full_lists_refused(self):
        node=self.router.snapshot.ssids['0'];node.find('WifiMacFilterStatus').text='2'
        for i in range(10): node.find(f'WifiMacFilterMac{i}').text=f'02:00:00:00:00:{i+1:02X}'
        self.assert_error('LIST_FULL',self.plan)

    def test_protected_router_host_pc_and_management_devices(self):
        gateway=models.add_or_update_device('192.168.8.1','02:11:22:33:44:01',device_type='Gateway/Router')
        desktop=models.add_or_update_device('192.168.8.102',DESKTOP,device_type='Desktop')
        self.assert_error('PROTECTED_DEVICE',lambda:service.prepare(gateway,'quarantine','02:11:22:33:44:01',['0'],True,'test-admin'))
        self.assert_error('PROTECTED_DEVICE',lambda:service.prepare(desktop,'quarantine',DESKTOP,['0'],True,'test-admin'))
        self.patch_value(config,'PROTECTED_MANAGEMENT_MACS',frozenset({MAC}))
        self.assert_error('PROTECTED_DEVICE',self.plan)
        self.assertEqual(self.router.writes,[])

    def test_controller_ip_and_unknown_local_identity_fail_closed(self):
        self.assert_error('PROTECTED_DEVICE',lambda:service.prepare(self.device,'quarantine',MAC,['0'],True,'test-admin','192.168.8.101'))
        self.patch_value(service,'local_identities',MagicMock(side_effect=QuarantineError('HOST_IDENTITY_UNKNOWN','Cannot identify host')))
        self.assert_error('HOST_IDENTITY_UNKNOWN',self.plan)

    def test_stale_device_mac_and_disconnected_candidate_refused(self):
        self.assert_error('IDENTITY_CHANGED',lambda:service.prepare(self.device,'quarantine',OTHER,['0'],True,'test-admin'))
        self.patch_value(self.router,'get_connected_wifi_devices',lambda:[])
        self.assert_error('WIFI_IDENTITY_UNVERIFIED',self.plan)

    def test_default_write_gates_and_mac_allowlist(self):
        plan=self.plan()
        self.patch_value(config,'ROUTER_WRITES_ENABLED',False)
        self.assert_error('WRITES_DISABLED',lambda:self.execute(plan))
        self.assertEqual(self.router.writes,[])
        self.patch_value(config,'ROUTER_WRITES_ENABLED',True)
        self.patch_value(config,'AUTHORIZED_TEST_MACS',frozenset())
        self.assert_error('NOT_AUTHORIZED',lambda:self.execute(plan))
        self.assertEqual(self.router.writes,[])

    def test_plan_session_binding_expiry_and_lease(self):
        plan=self.plan()
        self.assert_error('PLAN_NOT_FOUND',lambda:service.execute(plan['plan_id'],'different-admin'))
        conn=db.get_connection();conn.execute('UPDATE router_quarantine_plans SET expires_at=0');conn.commit();conn.close()
        self.assert_error('PLAN_EXPIRED',lambda:self.execute(plan))
        conn=db.get_connection();conn.execute('INSERT INTO router_operation_lease VALUES (1,?,?)',('another-owner',time.time()+60));conn.commit();conn.close()
        self.assert_error('BUSY',lambda:self.execute(plan))

    def test_api_requires_admin_csrf_and_explicit_confirmation(self):
        route=f'/api/device/{self.device}/router-quarantine/plan'
        self.assertEqual(self.http.post(route,json={}).status_code,401)
        headers=self.login()
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=headers).status_code,200)
        self.assertEqual(self.http.post(route,json={}).status_code,403)
        response=self.http.post(route,json={'action':'quarantine','mac':MAC,'ssid_indices':['0'],'allow_enable':True},headers=headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.http.post('/api/router/quarantine/execute',json={'plan_id':response.json['plan_id']},headers=headers).status_code,400)
        self.assertEqual(self.http.post('/api/router/quarantine/execute',json={'plan_id':response.json['plan_id'],'confirmed':True},headers={**headers,'Origin':'https://evil.example'}).status_code,403)
        response=self.http.post('/api/router/quarantine/execute',json={'plan_id':response.json['plan_id'],'confirmed':True,**{k:response.json[k] for k in ('device_id','mac','ssid_indices','expected_digest')}},headers=headers)
        self.assertEqual(response.status_code,200);self.assertEqual(response.json['enforcement']['state'],'ACTIVE')
        self.assertEqual(self.http.get(f'/api/device/{self.device}/router-quarantine/recovery').status_code,200)
        self.assertEqual(self.http.post(f'/api/device/{self.device}/quarantine',json={'action':'quarantine'}).status_code,409)

    def test_rejected_admin_login_and_snapshots_not_public(self):
        token=self.http.get('/api/admin/session').json['csrf_token']
        self.assertEqual(self.http.post('/api/admin/login',json={'password':'wrong'},headers={'X-CSRF-Token':token}).status_code,401)
        self.assertEqual(self.http.get(f'/api/device/{self.device}/router-quarantine/recovery').status_code,401)
        self.execute(self.plan())
        status=self.http.get(f'/api/device/{self.device}/enforcement').json
        self.assertNotIn('before_xml',status);self.assertNotIn('ownership_json',status)

    def test_mode_change_after_block_prevents_blind_recovery(self):
        self.execute(self.plan())
        self.router.snapshot.ssids['0'].find('WifiMacFilterStatus').text='1'
        self.assert_error('MODE_CONFLICT',lambda:self.plan('recover'))
        self.assertEqual(len(self.router.writes),1)

    def test_release_does_not_depend_on_stale_dhcp_address(self):
        self.execute(self.plan())
        conn=db.get_connection();conn.execute('UPDATE devices SET ip_address=NULL WHERE id=?',(self.device,));conn.commit();conn.close()
        self.assertEqual(self.execute(self.plan('recover'))['state'],'RELEASED')

    def test_all_four_scopes_change_only_target_mode_and_empty_slots(self):
        self.patch_value(config,'STABLE_WIFI_IDENTITY_BINDINGS',{MAC:{'device_id':self.device,'ip':'192.168.8.101','hostname':'mock-phone','ssid_indices':['0','1','2','3']}})
        before=FilterSnapshot(self.router.snapshot.xml())
        plan=self.plan(indices=['0','1','2','3'])
        self.execute(plan)
        self.assertTrue(self.router.snapshot.contains(MAC,['0','1','2','3']))
        for index in self.router.snapshot.ssids:
            self.assertEqual(self.router.snapshot.ssids[index].findtext('WifiMacFilterMac0'),MAC)
            self.assertEqual(before.ssids[index].findtext('WifiMacFilterMac0'),'')
        self.execute(self.plan('release'))
        self.assertEqual(self.router.snapshot.digest(),before.digest())

    def test_two_prepared_blocks_cannot_destroy_active_recovery_metadata(self):
        first=self.plan();second=self.plan()
        self.execute(first)
        self.assert_error('ALREADY_MANAGED',lambda:self.execute(second))
        record=service.recovery_record(self.device)
        self.assertTrue(record['ownership'])
        self.assertEqual(record['state'],'ACTIVE')
        self.assertEqual(self.execute(self.plan('recover'))['state'],'RELEASED')

    def test_audit_retains_each_original_configuration_snapshot(self):
        self.execute(self.plan());self.execute(self.plan('release'))
        audit=service.recovery_record(self.device)['audit']
        requests=[json.loads(row['details_json']) for row in audit if row['state']=='REQUESTED']
        self.assertEqual(len(requests),2)
        self.assertEqual(FilterSnapshot(requests[0]['before_xml']).ssids['0'].findtext('WifiMacFilterStatus'),'0')
        self.assertEqual(FilterSnapshot(requests[1]['before_xml']).ssids['0'].findtext('WifiMacFilterStatus'),'2')

    def test_schema_v2_is_backed_up_before_router_tables_added(self):
        conn=db.get_connection()
        conn.execute('DROP TABLE router_quarantine_plans')
        conn.execute('PRAGMA user_version=2')
        before=tuple(conn.execute('SELECT COUNT(*) FROM devices').fetchone())
        conn.commit();conn.close()
        db.initialize_database()
        backups=list(Path(self.temp.name).glob('*.before_schema_*.db'))
        self.assertEqual(len(backups),1)
        import sqlite3
        backup=sqlite3.connect(backups[0])
        self.assertEqual(backup.execute('PRAGMA user_version').fetchone()[0],2)
        self.assertIsNone(backup.execute("SELECT 1 FROM sqlite_master WHERE name='router_quarantine_plans'").fetchone())
        backup.close()
        conn=db.get_connection()
        self.assertEqual(tuple(conn.execute('SELECT COUNT(*) FROM devices').fetchone()),before)
        self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0],5)
        self.assertEqual(conn.execute('PRAGMA foreign_key_check').fetchall(),[])
        conn.close()

    def test_high_risk_never_calls_quarantine_even_with_auto_flag(self):
        import risk.risk_engine as risk
        dev=models.get_device_by_id(self.device)
        with patch.object(config,'AUTO_QUARANTINE',True),patch.object(risk,'get_recent_traffic',return_value=[]),patch.object(risk,'get_recent_tcp_syn_traffic',return_value=[]),patch.object(risk,'get_recent_dns_queries',return_value=[]),patch.object(risk,'check_unknown_device',return_value={'detected':True,'classification':'known_untrusted'}),patch.object(risk,'check_port_scan',return_value={'detected':True,'unique_ports_count':20}),patch.object(risk,'check_dns_anomaly',return_value={'detected':True}),patch.object(risk,'check_behaviour_drift_for_device',return_value={'detected':True,'traffic_spike':True,'drift_score':100}),patch.object(risk,'quarantine_device') as quarantine:
            result=risk.evaluate_device_risk(dev,auto_quarantine=True)
        self.assertEqual(result['risk_score'],100)
        quarantine.assert_not_called()
        self.assertEqual(self.router.writes,[])

    def test_crash_left_applying_reconciles_after_process_restart(self):
        self.execute(self.plan())
        conn=db.get_connection();conn.execute("UPDATE router_quarantines SET state='APPLYING', verified_enforced=NULL, verified_at=NULL");conn.commit();conn.close()
        self.assertEqual(service.get_state(self.device)['state'],'APPLYING')
        self.assertEqual(service.reconcile(self.device)['state'],'ACTIVE')
        self.assertEqual(len(self.router.writes),1)

    def test_released_external_rule_is_not_deleted_by_duplicate_release(self):
        self.execute(self.plan());self.execute(self.plan('release'))
        node=self.router.snapshot.ssids['0'];node.find('WifiMacFilterMac4').text=MAC;node.find('WifiMacFilterStatus').text='2'
        self.assert_error('EXTERNAL_RULE',lambda:self.plan('release'))
        self.assertEqual(len(self.router.writes),2)

    def test_admin_expiry_and_nonlocal_host_rejected(self):
        headers=self.login()
        with self.http.session_transaction() as session:session['admin_until']=0
        self.assertEqual(self.http.post(f'/api/device/{self.device}/router-quarantine/reconcile',headers=headers).status_code,401)
        self.assertEqual(self.http.get('/api/admin/session',headers={'Host':'attacker.example'}).status_code,403)



class RouterTransportTests(unittest.TestCase):
    def test_inactive_management_adapters_are_protected(self):
        from scapy import all as scapy
        def address(iface): return '192.168.8.102' if iface=='wired' else '0.0.0.0'
        with patch.object(scapy,'get_if_list',return_value=['wired','inactive-wifi']),patch.object(scapy,'get_if_addr',side_effect=address),patch.object(scapy,'get_if_hwaddr',side_effect=[DESKTOP,OTHER]):
            ips,macs=service.local_identities()
        self.assertIn('192.168.8.102',ips)
        self.assertIn(OTHER,macs)
        self.assertIn(DESKTOP,macs)

    def test_exact_firmware_schema_and_no_generic_endpoint_fallback(self):
        client=HuaweiRouterClient('test','not-a-real-password')
        info=ET.Element('response')
        for key,value in FIRMWARE.items():ET.SubElement(info,key).text=value
        features=ET.fromstring('<response><maxapnum>4</maxapnum><isdoublechip>0</isdoublechip></response>')
        with patch.object(client,'get_xml',side_effect=[info,features,ET.fromstring(FIXTURE.read_text(encoding='utf-8'))]):
            report,_=client.probe_quarantine_capabilities()
            self.assertEqual(report['endpoint'],'/api/wlan/multi-macfilter-settings')
        info.find('SoftwareVersion').text='different'
        with patch.object(client,'get_xml',return_value=info):
            with self.assertRaises(QuarantineError):client.probe_quarantine_capabilities()
        with self.assertRaises(RuntimeError):client._post('/api/wlan/mac-filter',{})
        client.close()

    def test_token_refresh_and_exact_payload_write_contract(self):
        before=FilterSnapshot(FIXTURE.read_text(encoding='utf-8'));after,_=plan_block(before,MAC,['0'],True)
        client=HuaweiRouterClient('test','not-a-real-password');client.authenticated=True;client.token='old-test-token'
        response=MagicMock(status_code=200,content=b'<response>OK</response>',headers={'__RequestVerificationTokenone':'new-test-token'})
        with patch.object(write_safety,'locked',return_value=False),patch.object(config,'PROTECTION_MODE','LIVE'),patch.object(config,'ROUTER_WRITES_ENABLED',True),patch.object(config,'RECOVERY_CONFIRMED',True),patch.object(config,'AUTHORIZED_TEST_MACS',{MAC}),patch.object(client,'read_mac_filter',return_value=before),patch.object(client.session,'post',return_value=response) as post:
            permit=WritePermit('test-operation',MAC,before.digest(),after.digest(),time.time()+60)
            client.write_mac_filter(before,after,permit)
            self.assertEqual(post.call_args.args[0],'http://192.168.8.1/api/wlan/multi-macfilter-settings')
            self.assertEqual(ET.fromstring(post.call_args.kwargs['data']).tag,'request')
            self.assertEqual(post.call_args.kwargs['headers']['__RequestVerificationToken'],'old-test-token')
            self.assertFalse(post.call_args.kwargs['allow_redirects'])
            self.assertEqual(client.token,'new-test-token')
        client.close()

if __name__=='__main__':unittest.main()
