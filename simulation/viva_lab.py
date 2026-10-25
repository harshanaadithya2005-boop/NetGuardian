"""Offline Scapy packet replay through the real capture/detection/risk pipeline.

No packets are transmitted. Context-local SQLite isolation prevents concurrent
monitoring threads from being redirected into the lab database.
"""
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
import ipaddress,json,uuid
import xml.etree.ElementTree as ET
import config
from database import db,models
from response import policy
from detection.evidence_store import current_security

_lock=RLock()
MAC='10:20:30:40:50:70'

def lab_path():
    path=Path(config.VIVA_DATABASE_PATH).resolve()
    if not path.is_relative_to((config.BASE_DIR/'.test-work').resolve()) or path==Path(db.DB_PATH).resolve():
        raise ValueError('Viva database must be isolated within .test-work')
    path.parent.mkdir(parents=True,exist_ok=True)
    return path

@contextmanager
def session():
    with _lock,db.isolated_database(lab_path()):
        db.initialize_database()
        from monitoring.traffic_monitor import create_traffic_table
        create_traffic_table()
        yield

class LabRouter:
    def __init__(self,device):
        self.device=device
        network=ipaddress.ip_network(config.TARGET_NETWORK,strict=False)
        self.management_identity=({str(network.network_address+2)},{'10:20:30:40:50:72'})
    def get_connected_wifi_devices(self):return [dict(ip=self.device['ip_address'],mac=MAC,hostname='Viva synthetic device')]
    def enabled_wifi_scopes(self):return ['0']
    def probe_quarantine_capabilities(self):
        from router.mac_filter import FilterSnapshot
        root=ET.Element('response');ssids=ET.SubElement(root,'Ssids')
        for index in range(4):
            node=ET.SubElement(ssids,'Ssid');ET.SubElement(node,'Index').text=str(index);ET.SubElement(node,'WifiMacFilterStatus').text='0'
            for slot in range(10):ET.SubElement(node,f'WifiMacFilterMac{slot}');ET.SubElement(node,f'wifihostname{slot}')
        return {'source':'ISOLATED_MOCK_ROUTER'},FilterSnapshot(root)

def device():
    network=ipaddress.ip_network(config.TARGET_NETWORK,strict=False)
    ip=str(network.network_address+min(250,network.num_addresses-2))
    existing=models.get_device_by_mac(MAC)
    if existing:return existing
    ident=models.add_or_update_device(ip,MAC,hostname='Viva synthetic device',device_name='VIVA synthetic device (offline replay)',device_type='Synthetic')
    return models.get_device_by_id(ident)

def run(scenario):
    if not isinstance(scenario,str) or scenario not in {'normal','port_scan','dns_burst','combined'}:raise ValueError('Choose normal, port_scan, dns_burst or combined')
    with session():
        from capture.packet_capture import process_packet
        from scapy.all import Ether,IP,TCP,UDP,DNS,DNSQR
        from risk.risk_engine import evaluate_device_risk
        dev=device();ip=dev['ip_address'];destination=str(ipaddress.ip_network(config.TARGET_NETWORK,strict=False).network_address+1)
        packets=[]
        if scenario in {'port_scan','combined'}:
            packets += [Ether(src=MAC,dst='10:20:30:40:50:71')/IP(src=ip,dst=destination)/TCP(sport=42000+i,dport=1000+i,flags='S') for i in range(16)]
        if scenario in {'dns_burst','combined'}:
            packets += [Ether(src=MAC,dst='10:20:30:40:50:71')/IP(src=ip,dst=destination)/UDP(sport=43000+i,dport=53)/DNS(id=i,rd=1,qd=DNSQR(qname=f'query-{i}.example.test')) for i in range(24)]
        if scenario=='normal':packets=[Ether(src=MAC,dst='10:20:30:40:50:71')/IP(src=ip,dst=destination)/TCP(dport=443,flags='A')]
        policy.set_settings(dict(enabled=True,mode='AUTOMATIC_RESPONSE'))
        # Supplying this strictly local model avoids any authentication or router I/O.
        for packet in packets:process_packet(packet)
        result=evaluate_device_risk(dev,policy_router=LabRouter(dev))
        return dict(scenario=scenario,packet_replay_count=len(packets),packets_transmitted=0,
                    source='ISOLATED_PACKET_REPLAY',risk=result,security=current_security(),
                    warning='Synthetic offline packets; real detector code, isolated data. No physical router enforcement.')

def status():
    with session():
        conn=db.get_connection()
        try:count=conn.execute('SELECT COUNT(*) FROM traffic').fetchone()[0]
        finally:conn.close()
        return dict(security=current_security(),packet_records=count,physical_router_writes=0,source='ISOLATED_PACKET_REPLAY')

def release(ident):
    with session():policy.release_simulated(ident);return dict(security=current_security(),physical_router_writes=0)

def reset():
    with session():
        conn=db.get_connection()
        try:
            conn.execute('BEGIN IMMEDIATE')
            for table in ['response_events','response_decisions','risk_current','risk_history','detection_evidence','ai_reports','alerts','traffic','traffic_statistics']:
                if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():conn.execute('DELETE FROM '+table)
            conn.execute('UPDATE devices SET risk_score=CASE WHEN trusted=0 THEN ? ELSE ? END',(config.RISK_WEIGHTS['unknown_device'],config.RISK_BASELINE))
            conn.commit()
        except Exception:conn.rollback();raise
        finally:conn.close()
    return status()
