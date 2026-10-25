"""Integration tests use real SQLite and Scapy packets in isolated databases."""
import os
os.environ["TARGET_NETWORK"] = "192.168.8.0/24"
import sqlite3
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch

import config
from database import db, models
import app as web
from capture import packet_capture as capture
from monitoring.traffic_monitor import create_traffic_table
from router.router_sync import mark_disconnected_wifi_devices_offline
from response.quarantine import quarantine_device, release_device
from risk.risk_engine import evaluate_device_risk
from detection.behaviour_drift import check_behaviour_drift_for_device
from analytics.baseline_history_v2 import save_observation_v2
from analytics.learned_baseline import get_learned_baseline
from router import write_safety


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        (Path(__file__).resolve().parents[1]/".test-work").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]/".test-work")
        self.addCleanup(self.temp.cleanup)
        # Safety tests must not depend on a developer's private incident marker
        # being present in a fresh checkout, or inspect the production marker.
        marker = Path(self.temp.name)/'incident-test-marker'
        marker.write_text('Isolated regression-test incident lock', encoding='utf-8')
        safety_patch = patch.object(write_safety, 'LOCK_FILE', marker)
        safety_patch.start()
        self.addCleanup(safety_patch.stop)
        self.path = Path(self.temp.name)/"test.db"
        self.patch = patch.object(db, "DB_PATH", self.path)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.network = patch.object(config, "TARGET_NETWORK", "192.168.8.0/24")
        self.network.start()
        self.addCleanup(self.network.stop)
        db.initialize_database()
        create_traffic_table()
        self.device = models.add_or_update_device("192.168.8.250", "02:AA:BB:CC:DD:EE", device_type="Workstation")
        self.client = web.app.test_client()
        web.app.config["TESTING"] = True

    def connection(self):
        return db.get_connection()

    def test_fresh_database_and_all_pages(self):
        models.log_traffic(self.device, "192.168.8.250", "8.8.8.8", packet_size=200)
        for url in ["/", "/devices", "/alerts", "/analytics", "/reports", f"/device/{self.device}",
                    "/api/stats", "/api/devices", "/api/alerts", "/api/traffic", "/api/analytics", "/api/health",
                    "/reports/alerts.csv", "/reports/report.pdf"]:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(config.PROTECTION_MODE, "DEMO")
        self.assertFalse(config.AUTO_QUARANTINE)

    def test_legacy_schema_migration_preserves_history_and_backup(self):
        conn = self.connection()
        conn.execute("ALTER TABLE devices DROP COLUMN missed_scans")
        conn.execute("ALTER TABLE traffic DROP COLUMN tcp_flags")
        conn.execute("PRAGMA user_version=0")
        conn.commit()
        before = conn.execute("SELECT * FROM alerts").fetchall()
        conn.close()
        db.initialize_database()
        conn = self.connection()
        self.assertEqual(len(conn.execute("SELECT * FROM alerts").fetchall()), len(before))
        self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        conn.close()
        self.assertEqual(len(list(self.path.parent.glob('*.before_schema_*.db'))), 1)
        db.initialize_database()
        self.assertEqual(len(list(self.path.parent.glob('*.before_schema_*.db'))), 1)
        models.log_traffic(self.device, "192.168.8.250", "1.1.1.1", tcp_flags="S")

    def test_legacy_not_null_ip_rebuild_preserves_references(self):
        other = Path(self.temp.name)/"legacy.db"
        conn = sqlite3.connect(other)
        conn.executescript("""
            CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT, hostname TEXT, device_name TEXT, device_type TEXT,
                first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,status TEXT DEFAULT 'online',
                trusted INTEGER DEFAULT 0,risk_score INTEGER DEFAULT 0);
            INSERT INTO devices VALUES (17,'192.168.8.111','AUTO-CAPTURED',NULL,NULL,NULL,'2026-10-01','2026-10-01','offline',0,0);
            CREATE TABLE retained (device_id INTEGER REFERENCES devices(id), value TEXT);
            INSERT INTO retained VALUES (17,'keep');
        """)
        conn.close()
        with patch.object(db,"DB_PATH",other):
            db.initialize_database()
            models.add_or_update_device("192.168.8.111", "02:11:22:33:44:55")
            conn = db.get_connection()
            self.assertIsNone(conn.execute("SELECT ip_address FROM devices WHERE id=17").fetchone()[0])
            self.assertEqual(conn.execute("SELECT value FROM retained").fetchone()[0], 'keep')
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            conn.close()

    def test_manual_quarantine_reversal_and_router_preservation(self):
        models.set_device_status(self.device, "offline")
        with patch('subprocess.run') as command:
            self.assertTrue(quarantine_device(self.device)[0])
            self.assertTrue(quarantine_device(self.device)[0])
            mark_disconnected_wifi_devices_offline(["02:AA:BB:CC:DD:EE"])
            self.assertEqual(models.get_device_by_id(self.device)["status"], "quarantined")
            self.assertTrue(release_device(self.device)[0])
            self.assertEqual(models.get_device_by_id(self.device)["status"], "offline")
            self.assertTrue(release_device(self.device)[0])
            command.assert_not_called()
        conn=self.connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM quarantine_logs").fetchone()[0], 2)
        conn.close()

    def test_quarantine_safety_and_api_validation(self):
        gateway=models.add_or_update_device("192.168.8.1","02:00:00:00:00:01",device_type="Gateway/Router")
        self.assertFalse(quarantine_device(gateway)[0])
        self.assertFalse(quarantine_device(self.device, "192.168.8.249")[0])
        prefix=f"/api/device/{self.device}"
        for body in [{}, [], {"action":"typo"}, {"action": ["release"]}]:
            self.assertEqual(self.client.post(prefix+"/quarantine",json=body).status_code,400)
        for body in [{}, [], {"trusted":"false"}, {"trusted":2}]:
            self.assertEqual(self.client.post(prefix+"/trust",json=body).status_code,400)
        self.assertEqual(self.client.post('/api/device/9999/trust',json={"trusted":True}).status_code,404)
        self.assertEqual(self.client.post('/api/alerts/9999/resolve').status_code,404)
        self.assertEqual(self.client.post(prefix+'/trust',json={"trusted":True},headers={"Origin":"https://evil.example"}).status_code,403)
        self.assertEqual(self.client.post(prefix+'/quarantine',json={"action":"quarantine"}).status_code,200)
        self.assertFalse(self.client.post(prefix+'/quarantine',json={"action":"release"}).json['enforced'])

    def test_scapy_packet_to_risk_alert_and_dashboard(self):
        from scapy.all import Ether,IP,TCP,UDP,DNS,DNSQR
        capture.capture_health.start()
        self.addCleanup(capture.capture_health.stop)
        with patch.object(capture,'get_local_ip',return_value=None), patch.object(capture,'get_local_mac',return_value=None):
            for port in range(1000,1010):
                capture.process_packet(Ether(src='02:aa:bb:cc:dd:ee')/IP(src='192.168.8.250',dst='1.1.1.1')/TCP(dport=port,flags='S'))
            for i in range(20):
                capture.process_packet(Ether(src='02:aa:bb:cc:dd:ee')/IP(src='192.168.8.250',dst='8.8.8.8')/UDP(dport=53)/DNS(qr=0,qd=DNSQR(qname=f'query{i}.example.com')))
        result=evaluate_device_risk(self.device,auto_quarantine=True)
        self.assertIn('port_scan',result['indicators'])
        self.assertIn('dns_anomaly',result['indicators'])
        self.assertGreaterEqual(result['risk_score'],70)
        self.assertFalse(result['quarantined'])
        self.assertEqual(len(self.client.get('/api/traffic').json),30)
        self.assertIn('port_scan',{r['alert_type'] for r in self.client.get('/api/alerts').json})
        self.assertEqual(sum(self.client.get('/api/analytics').json['proto_values']),30)
        self.assertEqual(capture.get_capture_health()['traffic_records_persisted'],30)

    def test_inbound_and_simulated_traffic_do_not_cause_behavior_anomaly(self):
        for _ in range(25):
            models.log_traffic(self.device,'1.1.1.1','192.168.8.250',destination_port=1000+_,packet_size=1000000)
            models.log_traffic(self.device,'192.168.8.250','8.8.8.8',packet_size=1000000,is_simulated=True)
        result=check_behaviour_drift_for_device(self.device)
        self.assertFalse(result['detected'])
        self.assertEqual(result['metrics']['packet_count'],0)
        self.assertEqual(sum(self.client.get('/api/analytics').json['proto_values']),25)

    def test_qualified_history_learns_matching_baseline(self):
        end=datetime.now().replace(second=0,microsecond=0)
        end=end.replace(minute=end.minute//5*5)-timedelta(minutes=10)
        conn=self.connection()
        for i in range(12):
            start=end-timedelta(minutes=5)
            metrics=dict(device_id=self.device,ip_address='192.168.8.250',window_minutes=5,
                         window_start=start.isoformat(timespec='seconds'),window_end=end.isoformat(timespec='seconds'),
                         packet_count=50,data_mb=1.0,dns_requests=6,distinct_ips=4,distinct_ports=3)
            save_observation_v2(conn,metrics,'02:AA:BB:CC:DD:EE')
            end=start
        conn.commit();conn.close()
        profile,count=get_learned_baseline(self.device,'02:AA:BB:CC:DD:EE',datetime.now())
        self.assertEqual(count,12)
        self.assertEqual(profile['normal_bandwidth'],1.0)
        self.assertEqual(check_behaviour_drift_for_device(self.device)['baseline_source'],'LEARNED')
        from analytics.collection_schedule import get_safe_completed_window_end
        completed=get_safe_completed_window_end(datetime.now())
        for i in range(25):
            models.log_traffic(self.device,'192.168.8.250','1.1.1.1',packet_size=1000000,timestamp=(completed-timedelta(seconds=10)).isoformat(timespec='seconds'))
        with patch('detection.behaviour_drift.observation_quality',return_value={'eligible':True,'status':'QUALIFIED_TEST_WINDOW'}):
            result=check_behaviour_drift_for_device(self.device)
        self.assertTrue(result['detected'])
        self.assertTrue(result['traffic_spike'])
        self.assertFalse(result['provisional'])

    def test_ai_fallback_and_saved_explanation(self):
        alert_id=models.create_alert(self.device,'dns_anomaly',20,'MEDIUM','Test DNS')
        with patch('ai.ai_engine._ask_ollama',side_effect=ConnectionError('offline')):
            response=self.client.get(f'/alerts/{alert_id}/explain')
            self.assertEqual(response.status_code,200)
            self.assertIn(b'Built-in',response.data)
        with patch('ai.ai_engine._ask_ollama',side_effect=AssertionError('must use saved explanation')):
            self.assertEqual(self.client.get(f'/alerts/{alert_id}/explain').status_code,200)

    def test_configured_daily_budgets_remain_provisional_during_learning(self):
        for i in range(25):
            models.log_traffic(self.device,'192.168.8.250','1.1.1.1',packet_size=1000000,timestamp=(datetime.now()-timedelta(seconds=10)).isoformat(timespec='seconds'))
        result=check_behaviour_drift_for_device(self.device)
        self.assertFalse(result['detected'])
        self.assertTrue(result['provisional'])
        self.assertEqual(result['status'],'BASELINE_WARMUP')

    def test_background_cycle_persists_only_qualified_healthy_history(self):
        from monitoring import engine
        from analytics.collection_schedule import get_safe_completed_window_end
        from analytics.capture_heartbeat import record_heartbeat
        from analytics.capture_sessions_v2 import start_capture_session_v2
        from capture.heartbeat_reporter import CaptureHeartbeatReporter
        now=datetime.now()
        end=get_safe_completed_window_end(now)
        models.set_device_trusted(self.device,True)
        conn=self.connection()
        session=start_capture_session_v2(conn,end-timedelta(minutes=6))
        for minute in range(5):
            timestamp=end-timedelta(minutes=5-minute)
            record_heartbeat(conn,timestamp)
            for i in range(5):
                conn.execute("INSERT INTO traffic (device_id,source_ip,destination_ip,protocol,packet_size,timestamp) VALUES (?,?,'1.1.1.1','TCP',100,?)",
                             (self.device,'192.168.8.250',timestamp.isoformat(timespec='seconds')))
        conn.commit();conn.close()
        snapshot=dict(status='CAPTURING',running=True,recent_successful_write=True,heartbeat_candidate=True,worker_error=None)
        with patch.object(capture,'get_capture_health',return_value=snapshot), patch.object(capture,'capture_session_id',session), patch.object(engine,'reporter',CaptureHeartbeatReporter(db.get_connection)):
            self.assertEqual(engine.collect_cycle(now)['stored'],1)
            self.assertEqual(engine.collect_cycle(now)['stored'],0)
        conn=self.connection()
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM behaviour_window_history_v2').fetchone()[0],1)
        conn.close()

    def test_capture_stops_on_quiet_link_and_closes_session(self):
        import time
        capture._stop_capture.clear()
        with patch.object(capture,'SCAPY_AVAILABLE',True), patch.object(capture,'detect_active_interface',return_value='test'), patch.object(capture,'sniff',side_effect=lambda **kw: capture._stop_capture.wait(0.05)):
            self.assertTrue(capture.start_capture())
            limit=time.monotonic()+2
            while not capture.capture_session_id and time.monotonic()<limit:
                time.sleep(0.01)
            self.assertIsNotNone(capture.capture_session_id)
            capture.stop_capture()
            self.assertFalse(capture.is_capturing())
        self.assertEqual(capture.get_capture_health()['status'],'STOPPED')
        conn=self.connection()
        self.assertEqual(conn.execute('SELECT end_reason FROM capture_sessions_v2').fetchone()[0],'STOPPED')
        conn.close()

    def test_legacy_alert_adapter_and_rename(self):
        from alerts.alert_manager import create_alert
        ident=create_alert(self.device,'traffic_spike',60,'adapter')
        self.assertTrue(ident)
        self.assertEqual(self.client.post(f'/api/device/{self.device}/name',json={'device_name':'Lab laptop'}).status_code,200)
        self.assertEqual(models.get_device_by_id(self.device)['device_name'],'Lab laptop')

if __name__ == '__main__':
    unittest.main()
