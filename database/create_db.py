import sqlite3

DB_NAME = "database/network_monitor.db"

conn = sqlite3.connect(DB_NAME)
conn.execute("PRAGMA foreign_keys = ON")
cur = conn.cursor()

cur.executescript("""
CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT NOT NULL,
    mac_address  TEXT UNIQUE,
    hostname     TEXT,
    device_type  TEXT,
    status       TEXT DEFAULT 'active',
    first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traffic (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER NOT NULL,
    source_ip      TEXT,
    destination_ip TEXT,
    protocol       TEXT,
    packet_size    INTEGER,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    alert_type  TEXT NOT NULL,
    risk_score  INTEGER,
    severity    TEXT,
    description TEXT,
    status      TEXT DEFAULT 'open',
    time        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS behaviour_profiles (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id        INTEGER NOT NULL UNIQUE,
    normal_bandwidth REAL,
    normal_protocols TEXT,
    normal_ports     TEXT,
    active_hours     TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS ai_reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id       INTEGER NOT NULL,
    summary        TEXT,
    recommendation TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);
""")

conn.commit()
conn.close()
print("Database created successfully:", DB_NAME)