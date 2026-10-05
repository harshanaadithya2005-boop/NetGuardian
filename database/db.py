import sqlite3
from pathlib import Path

# Database path inside database directory
DB_PATH = Path(__file__).resolve().parent / "network_monitor.db"


def get_connection(custom_path=None):
    """Create and return an SQLite connection to the NetGuardian database with row access."""
    path = custom_path or DB_PATH
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    # Enable SQLite foreign key enforcement
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    """Create all required NetGuardian tables if they do not already exist."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.executescript("""
        -- Devices inventory table
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
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

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print(f"NetGuardian database initialized successfully at: {DB_PATH}")