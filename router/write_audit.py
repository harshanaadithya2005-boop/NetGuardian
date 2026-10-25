"""Persist the exact serialized intent before a configuration request can leave."""
from datetime import datetime
import hashlib,json
from database.db import get_connection
from router.mac_filter import QuarantineError

def record_wire_intent(permit,payload):
    if permit.device_id is None:return # Standalone approved CLI has its own journal.
    conn=get_connection()
    try:
        row=conn.execute('SELECT mac_address,operation_id FROM router_quarantines WHERE device_id=?',(permit.device_id,)).fetchone()
        if not row or row['mac_address']!=permit.mac or row['operation_id']!=permit.operation_id:
            raise QuarantineError('TARGET_DELTA_MISMATCH','Persisted device intent differs from the router write. Nothing sent.')
        details=dict(device_id=permit.device_id,mac=permit.mac,ssid_indices=list(permit.ssid_indices),
                     wire_xml=payload.decode('utf-8'),wire_sha256=hashlib.sha256(payload).hexdigest(),
                     transmission='NOT_YET_SENT')
        conn.execute('INSERT INTO router_quarantine_audit (operation_id,device_id,mac_address,action,state,actor,message,details_json,timestamp) VALUES (?,?,?,?,?,?,?,?,?)',
                     (permit.operation_id,permit.device_id,permit.mac,permit.action,'APPLYING','transport',
                      'Exact serialized XML journaled before transmission; read-back still required.',json.dumps(details),datetime.now().isoformat(timespec='seconds')))
        conn.commit()
    finally:conn.close()
