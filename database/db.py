import sqlite3
from pathlib import Path


# Store the database inside the database folder
DB_PATH = Path(__file__).parent / "network_monitor.db"


def get_connection():
    """Create and return a connection to the NetGuardian database."""

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    # Enable SQLite foreign key support
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    """Create the devices table if it does not already exist."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            device_name TEXT,
            device_type TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'online',
            trusted INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            packet_size INTEGER,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            severity TEXT,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'New',
            time TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behaviour_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL UNIQUE,
            normal_bandwidth REAL,
            normal_protocols TEXT,
            normal_ports TEXT,
            active_hours TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    """)

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
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print("NetGuardian database initialized successfully.")