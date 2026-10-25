"""Three-device HTTP-to-final-Huawei-XML identity regressions; no real router."""
from pathlib import Path
import json
import unittest
from unittest.mock import patch
import requests
import test_router_quarantine as fixture
from database import db,models
from response import router_quarantine as service
from router import manual_mode,write_safety
from router.huawei_client import HuaweiRouterClient
from router.mac_filter import FilterSnapshot,plan_block,WritePermit,QuarantineError

A=fixture.MAC
B='14:20:30:40:50:61'
C='18:20:30:40:50:62'

class ThreeDeviceRouter(fixture.FakeRouter):
    def __init__(self):
        super().__init__()
        self.clients=[{'ip':'192.168.8.101','mac':A,'hostname':'mock-phone'},
                      {'ip':'192.168.8.103','mac':B,'hostname':'Device-B'},
                      {'ip':'192.168.8.104','mac':C,'hostname':'Device-C'}]
    def get_connected_wifi_devices(self):
        return [dict(c) for c in self.clients if not self.snapshot.contains(c['mac'],['0'])]
    def write_mac_filter(self,before,after,permit):
        # Exercise the real transport and capture its exact wire XML.
        client=HuaweiRouterClient('mock','mock-only');client.authenticated=True;client.token='mock-token'
        client.read_mac_filter=self.read_mac_filter
        def post(url,**kwargs):
            assert url=='http://192.168.8.1/api/wlan/multi-macfilter-settings'
            wire=kwargs['data'].decode();self.writes.append(wire)
            if not self.no_apply:
                self.snapshot=FilterSnapshot(wire)
                for node in self.snapshot.ssids.values():
                    for j in range(10):
                        field=node.find(f'WifiMacFilterMac{j}')
                        if field.text:field.text=field.text.lower()
            response=requests.Response();response.status_code=200;response._content=b'<response>OK</response>'
            return response
        with patch.object(client.session,'post',side_effect=post):client.write_mac_filter(before,after,permit)
        client.close()

class QuarantineIdentityTests(unittest.TestCase):
    setUp=fixture.RouterQuarantineTests.setUp
    patch_value=fixture.RouterQuarantineTests.patch_value
    login=fixture.RouterQuarantineTests.login

    def configure_three(self):
        self.router=ThreeDeviceRouter();self.patch_value(service,'new_client',lambda:self.router)
        self.b=models.add_or_update_device('192.168.8.103',B,hostname='Device-B')
        self.c=models.add_or_update_device('192.168.8.104',C,hostname='Device-C')
        self.headers=self.login()
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers).status_code,200)
    def prepare(self,device,mac,action='quarantine'):
        return self.http.post(f'/api/device/{device}/router-quarantine/plan',json=dict(mac=mac,action=action,ssid_indices=['0'],allow_enable=True),headers=self.headers)
    def execute(self,plan,**override):
        data={k:plan[k] for k in ('device_id','mac','ssid_indices','expected_digest')}
        data.update(plan_id=plan['plan_id'],confirmed=True);data.update(override)
        return self.http.post('/api/router/quarantine/execute',json=data,headers=self.headers)

    def test_b_never_changes_a_rule_and_release_retains_a_and_c(self):
        self.configure_three()
        self.router.snapshot,_=plan_block(self.router.snapshot,A,['0'],True)
        original_a=self.router.snapshot.ssids['0'].findtext('WifiMacFilterMac0')
        bp=self.prepare(self.b,B).json
        self.assertEqual(bp['mac'],B);self.assertEqual(bp['device_id'],self.b)
        self.assertEqual(self.execute(bp).json['enforcement']['state'],'ACTIVE')
        wire=FilterSnapshot(self.router.writes[-1])
        self.assertEqual(wire.ssids['0'].findtext('WifiMacFilterMac0'),original_a)
        self.assertEqual(wire.ssids['0'].findtext('WifiMacFilterMac1'),B)
        conn=db.get_connection()
        details=json.loads(conn.execute("SELECT details_json FROM router_quarantine_audit WHERE actor='transport' ORDER BY id DESC LIMIT 1").fetchone()[0]);conn.close()
        self.assertEqual(details['wire_xml'],self.router.writes[-1]);self.assertEqual(details['device_id'],self.b)
        self.assertFalse(wire.contains(C,['0']))
        self.assertEqual(self.execute(self.prepare(self.c,C).json).json['enforcement']['state'],'ACTIVE')
        self.assertEqual(self.execute(self.prepare(self.b,B,'release').json).json['enforcement']['state'],'RELEASED')
        self.assertTrue(self.router.snapshot.contains(A,['0']));self.assertTrue(self.router.snapshot.contains(C,['0']))
        self.assertFalse(self.router.snapshot.contains(B,['0']))

    def test_wrong_id_mac_scope_or_digest_confirmation_is_rejected(self):
        self.configure_three();p=self.prepare(self.b,B).json
        for override in ({'device_id':self.device},{'mac':A},{'ssid_indices':['1']},{'expected_digest':'wrong'}):
            response=self.execute(p,**override)
            self.assertEqual(response.json['code'],'TARGET_CONFIRMATION_MISMATCH')
        self.assertEqual(self.router.writes,[])
        self.assertEqual(self.execute(p).json['enforcement']['state'],'ACTIVE')

    def test_corrupted_saved_xml_cannot_target_another_mac(self):
        self.configure_three();p=self.prepare(self.b,B).json
        conn=db.get_connection();row=conn.execute('SELECT after_xml FROM router_quarantine_plans WHERE id=?',(p['plan_id'],)).fetchone()
        altered=FilterSnapshot(row[0]);altered.ssids['0'].find('WifiMacFilterMac0').text=A
        conn.execute('UPDATE router_quarantine_plans SET after_xml=? WHERE id=?',(altered.xml(),p['plan_id']));conn.commit();conn.close()
        self.assertEqual(self.execute(p).json['code'],'TARGET_CONFIRMATION_MISMATCH')
        p['expected_digest']=altered.digest()
        self.assertEqual(self.execute(p).json['code'],'TARGET_DELTA_MISMATCH')
        self.assertEqual(self.router.writes,[])

    def test_live_identity_rechecked_after_plan_and_duplicates_refused(self):
        self.configure_three();p=self.prepare(self.b,B).json
        self.router.clients.append({'ip':'192.168.8.103','mac':C,'hostname':'Device-C'})
        result=self.execute(p)
        self.assertEqual(result.json['enforcement']['state'],'FAILED')
        self.assertEqual(result.json['enforcement']['error_code'],'WIFI_IDENTITY_UNVERIFIED')
        self.assertEqual(self.router.writes,[])

    def test_database_duplicate_and_wrong_mac_fail_without_fallback(self):
        self.configure_three()
        self.assertEqual(self.prepare(self.b,A).json['code'],'IDENTITY_CHANGED')
        conn=db.get_connection();conn.execute('UPDATE devices SET mac_address=? WHERE id=?',(' '+B.lower()+' ',self.c));conn.commit();conn.close()
        self.assertEqual(self.prepare(self.b,B).json['code'],'AMBIGUOUS_IDENTITY')
        self.assertEqual(self.router.writes,[])

    def test_randomized_mac_without_independent_binding_is_refused(self):
        self.configure_three();self.patch_value(__import__('config'),'STABLE_WIFI_IDENTITY_BINDINGS',{})
        self.assertEqual(self.prepare(self.device,A).json['code'],'RANDOMIZED_IDENTITY_UNVERIFIED')
        self.assertEqual(self.router.writes,[])

    def test_ambiguous_ssid_and_stale_hostname_are_refused(self):
        self.configure_three();self.patch_value(self.router,'enabled_wifi_scopes',lambda:['0','1'])
        self.assertEqual(self.prepare(self.b,B).json['code'],'SSID_IDENTITY_UNVERIFIED')
        self.patch_value(self.router,'enabled_wifi_scopes',lambda:['0'])
        self.router.clients[1]['hostname']='someone-else'
        self.assertEqual(self.prepare(self.b,B).json['code'],'IDENTITY_CHANGED')
        self.assertEqual(self.router.writes,[])

    def test_persistent_incident_lock_rejects_mode_and_queued_wire_write(self):
        self.configure_three();p=self.prepare(self.b,B).json
        write_safety.LOCK_FILE.write_text('test incident')
        self.assertEqual(manual_mode.get_mode(),'DEMO')
        self.assertTrue(self.http.get('/api/admin/session').json['writes_locked'])
        self.assertEqual(self.execute(p).json['code'],'INCIDENT_LOCKDOWN')
        self.assertEqual(self.http.post('/api/protection-mode',json={'mode':'LIVE','confirmed':True},headers=self.headers).json['code'],'INCIDENT_LOCKDOWN')
        self.assertEqual(self.router.writes,[])

if __name__=='__main__':unittest.main()
