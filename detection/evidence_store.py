"""Durable immutable evidence and current risk snapshots. No router write capability."""
from datetime import datetime,timedelta
import hashlib,json
from database.db import get_connection,is_isolated

def create_tables(conn):
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS response_settings (id INTEGER PRIMARY KEY CHECK(id=1),policy_json TEXT NOT NULL,updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS response_settings_audit (id INTEGER PRIMARY KEY,policy_json TEXT NOT NULL,timestamp TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS detection_evidence (
      id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
      detection_type TEXT NOT NULL, fingerprint TEXT NOT NULL, source TEXT NOT NULL,
      severity TEXT NOT NULL, confidence REAL NOT NULL, evidence_json TEXT NOT NULL,
      first_seen TEXT NOT NULL, expires_at TEXT NOT NULL, alert_id INTEGER REFERENCES alerts(id),
      UNIQUE(device_id,detection_type,fingerprint,source));
    CREATE TABLE IF NOT EXISTS risk_history (
      id INTEGER PRIMARY KEY,device_id INTEGER NOT NULL REFERENCES devices(id),
      previous_score INTEGER NOT NULL, score INTEGER NOT NULL, severity TEXT NOT NULL,
      signature TEXT NOT NULL, details_json TEXT NOT NULL, timestamp TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS risk_current (
      device_id INTEGER PRIMARY KEY REFERENCES devices(id),details_json TEXT NOT NULL,evaluated_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_risk_device ON risk_history(device_id,id);
    CREATE TABLE IF NOT EXISTS response_decisions (
      id INTEGER PRIMARY KEY,device_id INTEGER NOT NULL REFERENCES devices(id),
      mac_address TEXT,source TEXT NOT NULL,initiation TEXT NOT NULL DEFAULT 'automatic',
      state TEXT NOT NULL,action TEXT NOT NULL,signature TEXT NOT NULL,
      details_json TEXT NOT NULL,requested_at TEXT NOT NULL,verified_at TEXT,
      UNIQUE(device_id,signature,source));
    CREATE TABLE IF NOT EXISTS response_events (
      id INTEGER PRIMARY KEY,decision_id INTEGER NOT NULL REFERENCES response_decisions(id),
      state TEXT NOT NULL,details_json TEXT NOT NULL,timestamp TEXT NOT NULL);
    ''')

def evidence_fingerprint(result):
    # Processing time is deliberately excluded: the same packets are one incident.
    evidence=result.get('evidence',{})
    body={'type':result['type'],'packet_ids':sorted(evidence.get('packet_ids',[])),
          'metrics':evidence.get('metrics'),'reasons':evidence.get('reasons'),
          'classification':evidence.get('classification')}
    return hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()

def save_evaluation(device,result):
    conn=get_connection()
    try:
        if not conn.execute('SELECT 1 FROM devices WHERE id=?',(device['id'],)).fetchone():return result
        conn.execute('BEGIN IMMEDIATE')
        source='ISOLATED_PACKET_REPLAY' if is_isolated() else 'LIVE_CAPTURE'
        now=datetime.now().isoformat(timespec='seconds')
        for d in result['detections']:
            fp=evidence_fingerprint(d)
            evidence_source=d['source']
            conn.execute('INSERT OR IGNORE INTO detection_evidence (device_id,detection_type,fingerprint,source,severity,confidence,evidence_json,first_seen,expires_at,alert_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
                         (device['id'],d['type'],fp,evidence_source,d['severity'],d['confidence'],json.dumps(d),now,d['expires_at'],d.get('alert_id')))
            d['evidence_id']=conn.execute('SELECT id FROM detection_evidence WHERE device_id=? AND detection_type=? AND fingerprint=? AND source=?',(device['id'],d['type'],fp,evidence_source)).fetchone()[0]
        signature=hashlib.sha256(json.dumps({'score':result['risk_score'],'evidence':sorted(d['evidence_id'] for d in result['detections'])},sort_keys=True).encode()).hexdigest()
        latest=conn.execute('SELECT score,signature FROM risk_history WHERE device_id=? ORDER BY id DESC LIMIT 1',(device['id'],)).fetchone()
        result['previous_risk_score']=latest['score'] if latest else int(device.get('risk_score') or 0)
        if not latest or latest['signature']!=signature:
            conn.execute('INSERT INTO risk_history (device_id,previous_score,score,severity,signature,details_json,timestamp) VALUES (?,?,?,?,?,?,?)',
                         (device['id'],result['previous_risk_score'],result['risk_score'],result['severity'],signature,json.dumps(result),now))
        conn.execute('INSERT INTO risk_current VALUES (?,?,?) ON CONFLICT(device_id) DO UPDATE SET details_json=excluded.details_json,evaluated_at=excluded.evaluated_at',(device['id'],json.dumps(result),now))
        conn.execute('UPDATE devices SET risk_score=? WHERE id=?',(result['risk_score'],device['id']))
        conn.commit()
        return result
    except Exception:conn.rollback();raise
    finally:conn.close()

def current_security(device_id=None):
    conn=get_connection()
    try:
        where='WHERE device_id=?' if device_id is not None else ''
        args=(device_id,) if device_id is not None else ()
        risks=[json.loads(r[0]) for r in conn.execute('SELECT details_json FROM risk_current '+where,args)]
        for risk in risks:
            risk['stale']=(datetime.now()-datetime.fromisoformat(risk['evaluated_at'])).total_seconds()>60
        decisions=[dict(r) for r in conn.execute('SELECT * FROM response_decisions '+where+' ORDER BY id DESC LIMIT 30',args)]
        for d in decisions:d['details']=json.loads(d.pop('details_json'))
        return dict(risks=risks,decisions=decisions,source='ISOLATED_PACKET_REPLAY' if is_isolated() else 'LIVE_CAPTURE')
    finally:conn.close()
