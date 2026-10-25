"""Recorded packet evidence, persistent policy, isolated replay and safety tests."""
from datetime import datetime,timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import unittest,json,sqlite3
import test_application as fixture
import config
from database import db,models
from risk import risk_engine as risk
from response import policy
from detection.connection_patterns import check_connection_patterns
from detection.evidence_store import current_security
from ai.ai_engine import explain_alert,explain_detection
from router import write_safety
from simulation import viva_lab

class SecurityPipelineTests(unittest.TestCase):
    setUp=fixture.ApplicationTests.setUp
    connection=fixture.ApplicationTests.connection
    def syn(self,count=8):
        for i in range(count):models.log_traffic(self.device,'192.168.8.250','192.168.8.254',protocol='TCP',tcp_flags='S',destination_port=1000+i,packet_size=60)
    def dns(self,count=24):
        for i in range(count):models.log_traffic(self.device,'192.168.8.250','192.168.8.1',protocol='DNS',destination_port=53,dns_query=f'q{i}.example.test',packet_size=90)
    def counts(self):
        conn=self.connection()
        try:return tuple(conn.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ['devices','traffic','alerts','detection_evidence','risk_history','response_decisions'])
        finally:conn.close()
    def test_risk_bands_unique_contributions_and_clamping(self):
        self.assertEqual(risk.calculate_risk(['port_scan']*5),30)
        for indicators,score in [([],0),(['unknown_device'],20),(['port_scan','dns_anomaly'],50),(['unknown_device','port_scan','dns_anomaly'],70),(['port_scan','dns_anomaly','sustained_flood','suspicious_connection'],90)]:
            self.assertEqual(risk.calculate_risk(indicators),score)
        self.assertEqual(risk.calculate_risk(list(config.RISK_WEIGHTS)),100)
    def test_packet_to_evidence_alert_history_and_expiry(self):
        self.syn();self.dns();r=risk.evaluate_device_risk(self.device)
        self.assertEqual(r['risk_score'],70);self.assertEqual(r['source'],'LIVE_CAPTURE')
        self.assertEqual({d['type'] for d in r['detections']},{'unknown_device','port_scan','dns_anomaly'})
        self.assertTrue(all(d['evidence_id'] for d in r['detections']))
        before=self.counts();risk.evaluate_device_risk(self.device);self.assertEqual(self.counts(),before)
        conn=self.connection();conn.execute("UPDATE traffic SET timestamp=datetime('now','localtime','-31 minutes')");conn.commit();conn.close()
        self.assertEqual(risk.evaluate_device_risk(self.device)['risk_score'],20)
        self.assertEqual(current_security()['risks'][0]['previous_risk_score'],70)
    def test_trusted_device_still_detects_scan(self):
        models.set_device_trusted(self.device,True);self.syn()
        self.assertEqual(risk.evaluate_device_risk(self.device)['risk_score'],30)
    def test_resolved_alert_is_not_recreated_from_identical_packets(self):
        self.syn();risk.evaluate_device_risk(self.device)
        conn=self.connection();conn.execute("UPDATE alerts SET status='resolved' WHERE alert_type='port_scan'");conn.commit();before=conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0];conn.close()
        risk.evaluate_device_risk(self.device)
        conn=self.connection();self.assertEqual(conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],before);conn.close()
    def test_open_alert_scores_follow_current_aggregate_and_ai_cache_is_versioned(self):
        self.syn();risk.evaluate_device_risk(self.device)
        conn=self.connection();ident=conn.execute("SELECT id FROM alerts WHERE alert_type='port_scan'").fetchone()[0];conn.close()
        self.assertEqual(self.client.get(f'/alerts/{ident}/explain').status_code,200)
        self.dns();risk.evaluate_device_risk(self.device)
        conn=self.connection();self.assertEqual(conn.execute('SELECT risk_score FROM alerts WHERE id=?',(ident,)).fetchone()[0],70);conn.close()
        self.assertEqual(self.client.get(f'/alerts/{ident}/explain').status_code,200)
        conn=self.connection();self.assertEqual(conn.execute('SELECT COUNT(*) FROM ai_reports WHERE alert_id=?',(ident,)).fetchone()[0],2);conn.close()

    def test_dns_baseline_and_entropy_do_not_flag_every_unfamiliar_domain(self):
        from detection.dns_anomaly import check_dns_anomaly
        domains=[f'q{i}.example.test' for i in range(24)]
        self.assertFalse(check_dns_anomaly(['a9b8c7d6e5f4g3h2i1.example.test'])['detected'])
        self.assertTrue(check_dns_anomaly(domains)['detected'])
        self.assertFalse(check_dns_anomaly(domains,baseline_query_rate=100)['detected'])
    def test_unknown_device_alone_never_automatically_quarantines(self):
        policy.set_settings(dict(mode='AUTOMATIC_RESPONSE',enabled=True))
        with patch('response.router_quarantine.new_client',side_effect=AssertionError('No router eligibility needed below thresholds')):
            r=risk.evaluate_device_risk(self.device)
        self.assertEqual(r['response_decision']['state'],'POLICY_EVALUATED')
    def test_resolved_packet_evidence_is_not_reused_for_automatic_response(self):
        self.syn();self.dns();risk.evaluate_device_risk(self.device)
        conn=self.connection();conn.execute("UPDATE alerts SET status='resolved' WHERE alert_type='port_scan'");conn.commit();conn.close()
        policy.set_settings(dict(mode='AUTOMATIC_RESPONSE',enabled=True))
        with patch.object(policy,'eligibility',side_effect=AssertionError('Resolved scan cannot authorize response')):
            result=risk.evaluate_device_risk(self.device)
        self.assertEqual(result['response_decision']['state'],'POLICY_EVALUATED')
    def test_auto_physical_setting_rejected_and_lock_unchanged(self):
        self.assertTrue(write_safety.locked());self.assertFalse(config.AUTO_QUARANTINE)
        with self.assertRaises(ValueError):policy.set_settings(dict(automatic_physical_enforcement=True))
        self.assertTrue(write_safety.locked())
    def test_real_risk_requires_review_and_no_router_write_method_is_called(self):
        self.syn();self.dns();policy.set_settings(dict(mode='AUTOMATIC_RESPONSE',enabled=True))
        with patch.object(policy,'eligibility',return_value=(True,'Mock verified identity.')),patch('router.huawei_client.HuaweiRouterClient.write_mac_filter',side_effect=AssertionError('No write allowed')):
            r=risk.evaluate_device_risk(self.device)
        self.assertEqual(r['response_decision']['state'],'PENDING_REVIEW')
        self.assertFalse(r['response_decision']['details']['physical_enforcement_available'])
    def test_stale_evidence_and_low_confidence_require_no_response(self):
        self.syn();self.dns();r=risk.evaluate_device_risk(self.device)
        policy.set_settings(dict(mode='AUTOMATIC_RESPONSE',enabled=True))
        for d in r['detections']:d['observed_at']=(datetime.now()-timedelta(minutes=10)).isoformat()
        with patch.object(policy,'eligibility',side_effect=AssertionError('Stale evidence must not pass')):
            decision=policy.evaluate(models.get_device_by_id(self.device),r)
        self.assertEqual(decision['state'],'POLICY_EVALUATED')
    def test_policy_settings_survive_reinitialization_and_concurrent_decisions(self):
        self.syn();self.dns();policy.set_settings(dict(mode='MANUAL_LIVE',enabled=False));db.initialize_database()
        self.assertEqual(policy.settings()['mode'],'MANUAL_LIVE')
        with ThreadPoolExecutor(max_workers=3) as pool:results=list(pool.map(lambda _:risk.evaluate_device_risk(self.device),range(3)))
        self.assertEqual(len({r['response_decision']['id'] for r in results}),1)
    def test_sustained_flood_rejects_single_burst_and_detects_consecutive_intervals(self):
        now=datetime.now().replace(microsecond=0);rows=[]
        for offset in [0,10,20]:rows.append(dict(source_ip='x',timestamp=(now-timedelta(seconds=offset)).isoformat(),packet_size=10000000))
        self.assertFalse(check_connection_patterns(rows[:1],'x')[1]['detected'])
        self.assertTrue(check_connection_patterns(rows,'x')[1]['detected'])
    def test_tcp_patterns_and_inbound_traffic(self):
        rows=[dict(id=i,source_ip='x',protocol='TCP',tcp_flags='FPU',destination_port=i+1) for i in range(8)]
        self.assertTrue(check_connection_patterns(rows,'x')[0]['detected'])
        self.assertFalse(check_connection_patterns(rows,'y')[0]['detected'])
    def test_horizontal_scan_counts_local_targets_but_excludes_normal_https(self):
        from detection.port_scan import check_port_scan
        rows=[dict(source_ip='192.168.8.250',destination_ip=f'192.168.8.{i+10}',protocol='TCP',tcp_flags='S',destination_port=22) for i in range(12)]
        result=check_port_scan(rows,source_ip='192.168.8.250')
        self.assertTrue(result['detected']);self.assertEqual(result['local_target_count'],12)
        for row in rows:row['destination_port']=443
        self.assertFalse(check_port_scan(rows,source_ip='192.168.8.250')['detected'])
    def test_overlapping_scan_flood_and_behavior_are_not_multiple_incidents(self):
        for seconds in [0,10,20]:
            for port in range(8):models.log_traffic(self.device,'192.168.8.250','192.168.8.254',tcp_flags='S',destination_port=1000+port,packet_size=2000000,timestamp=(datetime.now()-timedelta(seconds=seconds)).isoformat())
        with patch.object(risk,'check_behaviour_drift_for_device',return_value=dict(detected=True,traffic_spike=True,drift_score=80,breakdown={'distinct_ips':{'drift_pct':500}})):
            result=risk.evaluate_device_risk(self.device)
        self.assertEqual(result['risk_score'],50)
        self.assertEqual(result['contributions']['sustained_flood'],0)
        self.assertEqual(result['contributions']['traffic_spike'],0)
        self.assertEqual(result['contributions']['behaviour_drift'],0)
    def test_explanation_uses_recorded_evidence_without_model_invention(self):
        self.syn();r=risk.evaluate_device_risk(self.device);d=next(d for d in r['detections'] if d['type']=='port_scan')
        text=explain_detection(d);self.assertIn('8 packet records',text);self.assertIn('+30',text)
        with patch('ai.ai_engine._ask_ollama',side_effect=AssertionError('Facts must come from evidence')):
            summary,_,source=explain_alert('port_scan','HIGH',50,'8 SYN ports recorded','192.168.8.250')
        self.assertIn('8 SYN ports recorded',summary);self.assertEqual(source,'Built-in')
    def test_offline_replay_auto_simulation_release_reset_and_production_isolation(self):
        before=self.counts();health=__import__('capture.packet_capture',fromlist=['capture_health']).get_capture_health()
        with patch.object(config,'VIVA_DATABASE_PATH',Path(self.temp.name)/'viva.db'),patch('response.router_quarantine.new_client',side_effect=AssertionError('No physical router access')):
            normal=viva_lab.run('normal');self.assertEqual(normal['risk']['risk_score'],20)
            result=viva_lab.run('combined');self.assertEqual(result['risk']['risk_score'],70)
            self.assertEqual(result['risk']['response_decision']['state'],'AUTO_SIMULATED')
            ident=result['risk']['response_decision']['id'];viva_lab.release(ident)
            self.assertIn('RELEASED',[d['state'] for d in viva_lab.status()['security']['decisions']])
            self.assertEqual(viva_lab.reset()['security']['risks'],[])
        self.assertEqual(self.counts(),before)
        self.assertEqual(__import__('capture.packet_capture',fromlist=['capture_health']).get_capture_health(),health)
    def test_simulated_response_duplicate_evidence_and_new_incident_do_not_double_apply(self):
        with patch.object(config,'VIVA_DATABASE_PATH',Path(self.temp.name)/'viva.db'):
            result=viva_lab.run('combined');ident=result['risk']['response_decision']['id']
            with viva_lab.session():
                dev=viva_lab.device();again=risk.evaluate_device_risk(dev,policy_router=viva_lab.LabRouter(dev))
                self.assertEqual(again['response_decision']['id'],ident)
            newer=viva_lab.run('combined')
            self.assertEqual(newer['risk']['response_decision']['state'],'PENDING_REVIEW')
            self.assertEqual(sum(d['state']=='AUTO_SIMULATED' for d in newer['security']['decisions']),1)
    def test_concurrent_simulated_policy_creates_one_owned_response(self):
        path=Path(self.temp.name)/'viva.db'
        with patch.object(config,'VIVA_DATABASE_PATH',path):
            with viva_lab.session():
                dev=viva_lab.device();policy.set_settings(dict(mode='DEMO'))
                self.syn();self.dns();result=risk.evaluate_device_risk(dev,policy_router=viva_lab.LabRouter(dev))
                policy.set_settings(dict(mode='AUTOMATIC_RESPONSE',enabled=True))
            def decide(_):
                with db.isolated_database(path):return policy.evaluate(dev,result,viva_lab.LabRouter(dev))
            with ThreadPoolExecutor(max_workers=3) as pool:decisions=list(pool.map(decide,range(3)))
            self.assertEqual(len({d['id'] for d in decisions}),1)
            self.assertTrue(all(d['state']=='AUTO_SIMULATED' for d in decisions))
    def test_lab_context_is_thread_local(self):
        other=Path(self.temp.name)/'isolated.db'
        def inside():
            with db.isolated_database(other):return db.database_path(),db.is_isolated()
        with ThreadPoolExecutor(max_workers=1) as pool:self.assertEqual(pool.submit(inside).result(),(other,True))
        self.assertFalse(db.is_isolated());self.assertEqual(db.database_path(),self.path)
    def test_dashboard_security_api_and_lab_admin_csrf(self):
        self.syn();risk.evaluate_device_risk(self.device)
        self.assertEqual(self.client.get('/api/security').status_code,200)
        self.assertEqual(self.client.post('/api/security/viva/run',json={'scenario':'combined'}).status_code,401)
        self.assertEqual(self.client.post('/api/security/policy',json={'mode':'AUTOMATIC_RESPONSE'}).status_code,401)
    def test_schema_v4_migration_is_additive_and_repeatable(self):
        before=self.counts();conn=self.connection();conn.execute('PRAGMA user_version=4');conn.commit();conn.close()
        db.initialize_database();self.assertEqual(self.counts(),before);db.initialize_database()
        self.assertEqual(len(list(self.path.parent.glob('*.before_schema_*.db'))),1)
    def test_incomplete_behavioral_windows_are_not_detections(self):
        from detection.behaviour_drift import observation_quality
        from analytics.collection_schedule import get_safe_completed_window_end
        self.assertFalse(observation_quality(self.device,get_safe_completed_window_end(datetime.now()))['eligible'])

    def test_qualified_complete_window_detects_volume_and_missing_coverage_refuses(self):
        from analytics.collection_schedule import get_safe_completed_window_end
        from analytics.baseline_history_v2 import save_observation_v2
        from analytics.capture_heartbeat import record_heartbeat
        from analytics.capture_sessions_v2 import start_capture_session_v2
        from detection.behaviour_drift import check_behaviour_drift_for_device
        end=get_safe_completed_window_end(datetime.now());conn=self.connection()
        for i in range(12):
            stop=end-timedelta(minutes=5*(i+1))
            metrics=dict(device_id=self.device,ip_address='192.168.8.250',window_minutes=5,window_start=(stop-timedelta(minutes=5)).isoformat(),window_end=stop.isoformat(),packet_count=50,data_mb=1.,dns_requests=6,distinct_ips=4,distinct_ports=3)
            save_observation_v2(conn,metrics,'02:AA:BB:CC:DD:EE')
        start_capture_session_v2(conn,end-timedelta(minutes=6))
        for minute in range(5):record_heartbeat(conn,end-timedelta(minutes=5-minute))
        conn.commit();conn.close()
        for minute in range(5):
            for _ in range(5):models.log_traffic(self.device,'192.168.8.250','1.1.1.1',packet_size=1000000,timestamp=(end-timedelta(minutes=5-minute)).isoformat())
        result=check_behaviour_drift_for_device(self.device)
        self.assertTrue(result['detected']);self.assertTrue(result['traffic_spike'])
        conn=self.connection();conn.execute('DELETE FROM capture_heartbeats');conn.commit();conn.close()
        self.assertFalse(check_behaviour_drift_for_device(self.device)['detected'])

    def test_policy_protected_and_randomized_identity_rejections(self):
        class Router:
            def get_connected_wifi_devices(inner):return [dict(ip='192.168.8.250',mac='02:AA:BB:CC:DD:EE',hostname='Private device')]
        dev=models.get_device_by_id(self.device)
        with patch('response.router_quarantine.local_identities',return_value=({'192.168.8.102'},{'02:11:22:33:44:66'})):
            eligible,reason=policy.eligibility(dev,Router());self.assertFalse(eligible);self.assertIn('RANDOMIZED_IDENTITY_UNVERIFIED',reason)
        with patch('response.router_quarantine.local_identities',return_value=({'192.168.8.250'},{'02:AA:BB:CC:DD:EE'})):
            eligible,reason=policy.eligibility(dev,Router());self.assertFalse(eligible);self.assertIn('PROTECTED_DEVICE',reason)
        from response.router_quarantine import validate_device
        from router.mac_filter import QuarantineError
        with self.assertRaises(QuarantineError) as error:validate_device(self.device,dev['mac_address'],management_identity=(set(),set()))
        self.assertEqual(error.exception.code,'INVALID_CONTEXT')

    def test_critical_score_is_distinct_from_detector_severity(self):
        models.set_device_trusted(self.device,True);self.syn();self.dns()
        for i in range(8):models.log_traffic(self.device,'192.168.8.250','192.168.8.254',tcp_flags='FPU',destination_port=i+100,packet_size=60)
        for seconds in [0,10,20]:models.log_traffic(self.device,'192.168.8.250','192.168.8.254',packet_size=10000000,timestamp=(datetime.now()-timedelta(seconds=seconds)).isoformat())
        result=risk.evaluate_device_risk(self.device)
        self.assertEqual(result['risk_score'],90);self.assertEqual(result['severity'],'CRITICAL')

if __name__=='__main__':unittest.main()
