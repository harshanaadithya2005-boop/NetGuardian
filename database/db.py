import sqlite3
import re
from datetime import datetime
from pathlib import Path
from contextvars import ContextVar
from contextlib import contextmanager

# Database path inside database directory
from config import DATABASE_PATH
DB_PATH = DATABASE_PATH
_isolated_path = ContextVar('netguardian_isolated_database', default=None)

def database_path():
    return _isolated_path.get() or DB_PATH

def is_isolated():
    return _isolated_path.get() is not None

@contextmanager
def isolated_database(path):
    path=Path(path).resolve()
    if path==Path(DB_PATH).resolve():raise ValueError('Lab must not use production database')
    token=_isolated_path.set(path)
    try:yield
    finally:_isolated_path.reset(token)


def get_connection(custom_path=None):
    """Create and return an SQLite connection to the NetGuardian database with row access."""
    path = custom_path or database_path()
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    # Enable SQLite foreign key enforcement
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database():
    """Create all required NetGuardian tables if they do not already exist."""
    connection = get_connection()
    # SQLite's backup API includes committed WAL pages and works while readers
    # are active. Back up existing data before any schema changes.
    if connection.execute("PRAGMA user_version").fetchone()[0] < 5:
        existing = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='devices'"
        ).fetchone()
        if existing:
            backup_path = Path(database_path()).with_name(
                Path(database_path()).stem + '.before_schema_' +
                datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.db'
            )
            backup = sqlite3.connect(backup_path)
            try:
                connection.backup(backup)
                if backup.execute('PRAGMA integrity_check').fetchone()[0]!='ok':
                    raise RuntimeError('Pre-migration database backup failed integrity verification')
            finally:
                backup.close()
        _allow_unassigned_ips(connection)
    cursor = connection.cursor()

    cursor.executescript("""
        -- Devices inventory table
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            device_name TEXT,
            device_type TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'online', -- online, offline, quarantined
            trusted INTEGER NOT NULL DEFAULT 0,    -- 0: untrusted, 1: trusted
            risk_score INTEGER NOT NULL DEFAULT 0  -- 0 - 100
        );

        -- Network traffic telemetry table
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT,
            protocol TEXT DEFAULT 'TCP',
            destination_port INTEGER,
            packet_size INTEGER DEFAULT 0,
            dns_query TEXT,
            timestamp TEXT NOT NULL,
            is_simulated INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        -- Security alerts table
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,              -- port_scan, unknown_device, dns_anomaly, traffic_spike, behaviour_drift
            risk_score INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL,                -- LOW, MEDIUM, HIGH, CRITICAL
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',  -- open, resolved, ignored
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        -- Baseline behavioral profile for drift detection
        CREATE TABLE IF NOT EXISTS behaviour_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL UNIQUE,
            normal_bandwidth REAL DEFAULT 10.0,    -- MB/day
            normal_protocols TEXT DEFAULT 'TCP,UDP',
            normal_ports TEXT DEFAULT '80,443,53',
            normal_dns_rate INTEGER DEFAULT 40,    -- queries/day
            normal_dest_ips INTEGER DEFAULT 12,    -- distinct external IPs/day
            active_hours TEXT DEFAULT '08:00-18:00',
            updated_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        -- Device quarantine audit trail
        CREATE TABLE IF NOT EXISTS quarantine_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            action TEXT NOT NULL,                  -- quarantined, released
            reason TEXT,
            performed_by TEXT DEFAULT 'NetGuardian Auto-Engine',
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        -- Create indexes for fast querying
        CREATE INDEX IF NOT EXISTS idx_traffic_device ON traffic(device_id);
        CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
    """)


    # Member 3: AI-generated security reports
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            summary TEXT,
            recommendation TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    """)



    connection.commit()
    # Additive migrations support databases from all earlier project versions.
    for table, column, declaration in (
        ('ai_reports', 'evidence_signature', 'TEXT'),
        ('devices', 'missed_scans', 'INTEGER NOT NULL DEFAULT 0'),
        ('traffic', 'is_simulated', 'INTEGER NOT NULL DEFAULT 0'),
        ('traffic', 'tcp_flags', 'TEXT'),
    ):
        columns = {row['name'] for row in connection.execute(f'PRAGMA table_info({table})')}
        if column not in columns:
            connection.execute(f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')
    connection.executescript('''
        CREATE TABLE IF NOT EXISTS quarantine_state (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id),
            previous_status TEXT NOT NULL,
            observed_ip TEXT,
            mode TEXT NOT NULL DEFAULT 'DEMO'
        );
        CREATE TABLE IF NOT EXISTS alert_reset_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_cleared_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS huawei_wifi_devices (mac_address TEXT PRIMARY KEY);
        CREATE INDEX IF NOT EXISTS idx_traffic_device_time ON traffic(device_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_traffic_device_datetime ON traffic(device_id, datetime(timestamp));
        CREATE INDEX IF NOT EXISTS idx_traffic_datetime ON traffic(datetime(timestamp));
        CREATE TABLE IF NOT EXISTS router_quarantines (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id),
            mac_address TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('REQUESTED','APPLYING','ACTIVE','FAILED','RELEASED')),
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            before_xml TEXT,
            expected_xml TEXT,
            ownership_json TEXT NOT NULL DEFAULT '[]',
            error_code TEXT,
            message TEXT,
            verified_enforced INTEGER,
            verified_at TEXT,
            client_connected INTEGER,
            updated_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_router_quarantine_mac ON router_quarantines(mac_address);
        CREATE TABLE IF NOT EXISTS router_quarantine_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT NOT NULL,
            device_id INTEGER NOT NULL REFERENCES devices(id),
            mac_address TEXT NOT NULL,
            action TEXT NOT NULL,
            state TEXT NOT NULL,
            actor TEXT NOT NULL,
            message TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS router_operation_lease (
            id INTEGER PRIMARY KEY CHECK(id=1),
            owner TEXT NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS router_quarantine_plans (
            id TEXT PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id),
            mac_address TEXT NOT NULL,
            actor_session TEXT NOT NULL,
            action TEXT NOT NULL,
            before_xml TEXT NOT NULL,
            after_xml TEXT NOT NULL,
            ownership_json TEXT NOT NULL,
            expires_at REAL NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0
        );
    ''')
    plan_columns={row['name'] for row in connection.execute('PRAGMA table_info(router_quarantine_plans)')}
    if 'control_channel' not in plan_columns:
        connection.execute("ALTER TABLE router_quarantine_plans ADD COLUMN control_channel TEXT NOT NULL DEFAULT 'legacy'")
    if 'mode_generation' not in plan_columns:
        connection.execute('ALTER TABLE router_quarantine_plans ADD COLUMN mode_generation INTEGER')
    connection.execute('''CREATE TABLE IF NOT EXISTS protection_mode_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, runtime_id TEXT NOT NULL,
        previous_mode TEXT NOT NULL,new_mode TEXT NOT NULL,actor TEXT NOT NULL,timestamp TEXT NOT NULL
    )''')
    from analytics.baseline_history_v2 import create_history_table_v2
    from analytics.capture_heartbeat import create_heartbeat_table
    from analytics.capture_sessions_v2 import create_session_tables_v2
    create_history_table_v2(connection)
    create_heartbeat_table(connection)
    create_session_tables_v2(connection)
    from detection.evidence_store import create_tables
    create_tables(connection)
    connection.execute('PRAGMA user_version = 5')
    connection.commit()
    connection.close()


def _allow_unassigned_ips(connection):
    """Rebuild only the legacy NOT NULL IP constraint, keeping IDs and schema."""
    columns = connection.execute('PRAGMA table_info(devices)').fetchall()
    if not any(row['name'] == 'ip_address' and row['notnull'] for row in columns):
        return
    sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE name='devices'"
    ).fetchone()[0]
    schema = re.sub(r'(?i)(\bip_address\s+TEXT)\s+NOT\s+NULL', r'\1', sql)
    schema = re.sub(r'(?i)CREATE TABLE\s+(?:"devices"|devices)',
                    'CREATE TABLE devices_migration', schema, count=1)
    extras = connection.execute(
        "SELECT sql FROM sqlite_master WHERE tbl_name='devices' "
        "AND type IN ('index','trigger') AND sql IS NOT NULL"
    ).fetchall()
    connection.execute('PRAGMA foreign_keys = OFF')
    try:
        connection.execute('BEGIN IMMEDIATE')
        connection.execute(schema)
        names = ','.join('"' + row['name'].replace('"', '""') + '"' for row in columns)
        connection.execute(f'INSERT INTO devices_migration ({names}) SELECT {names} FROM devices')
        connection.execute('DROP TABLE devices')
        connection.execute('ALTER TABLE devices_migration RENAME TO devices')
        for extra in extras:
            connection.execute(extra[0])
        if connection.execute('PRAGMA foreign_key_check').fetchall():
            raise RuntimeError('Foreign-key check failed during device migration')
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute('PRAGMA foreign_keys = ON')


if __name__ == "__main__":
    initialize_database()
    print(f"NetGuardian database initialized successfully at: {DB_PATH}")
