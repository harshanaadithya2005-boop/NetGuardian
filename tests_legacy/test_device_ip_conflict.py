import sqlite3
from unittest.mock import patch

from database.models import add_or_update_device


def test_device_ip_conflict():
    # Use an in-memory database, not the real NetGuardian database.
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
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

    connection.executemany("""
        INSERT INTO devices
        (id, ip_address, mac_address, hostname, device_name,
         device_type, first_seen, last_seen, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        (2, "192.168.8.102", "02:11:22:33:44:66",
         "TEST-DESKTOP", "My Desktop", "Desktop",
         "2026-10-05", "2026-10-18", "online"),
        (9, "192.168.8.101", "AUTO-CAPTURED",
         "SYNTHETIC-HOST-TEST-1", "SYNTHETIC-HOST-TEST-1", "IoT Device",
         "2026-10-18", "2026-10-18", "offline")
    ])
    connection.commit()

    # Add historical records for both device identities.
    connection.execute("""
        CREATE TABLE test_history (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL,
            description TEXT NOT NULL
        )
    """)

    connection.executemany(
        "INSERT INTO test_history (device_id, description) VALUES (?, ?)",
        [
            (2, "Original desktop history"),
            (9, "Previously auto-captured history")
        ]
    )
    connection.commit()

    class TestConnection:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, name):
            return getattr(self.db, name)

        def close(self):
            # Keep the test database available for inspection.
            pass

    with patch("database.models.get_connection",
               return_value=TestConnection(connection)):
        try:
            add_or_update_device(
                ip_address="192.168.8.101",
                mac_address="02:11:22:33:44:66",
                hostname="TEST-DESKTOP",
                device_type="Desktop"
            )
            print("No duplicate-IP error")
        except sqlite3.IntegrityError as error:
            print("Conflict reproduced:", error)

    connection.rollback()
    print("Device records:", [
        tuple(row) for row in connection.execute(
            "SELECT id, ip_address FROM devices ORDER BY id"
        )
    ])

    # Verify that both device histories still exist.
    history = [
        tuple(row)
        for row in connection.execute(
            "SELECT device_id, description FROM test_history ORDER BY device_id"
        )
    ]

    print("Preserved history:", history)

        # Verify device 2 is not incorrectly reported as online.
    device_status = connection.execute(
        "SELECT status FROM devices WHERE id = 2"
    ).fetchone()["status"]

    assert device_status == "online", (
    f"Expected device 2 to remain online, got {device_status}"
    )

    print("Conflict status verification: PASSED")

        # Verify that an IP conflict does not overwrite either device's IP.
    device_ips = {
        row["id"]: row["ip_address"]
        for row in connection.execute(
            "SELECT id, ip_address FROM devices"
        )
    }

    assert device_ips[2] == "192.168.8.102", (
        "Device 2's original IP address was changed"
    )

    assert device_ips[9] == "192.168.8.101", (
        "Device 9's original IP address was changed"
    )

    print("IP address preservation: PASSED")

    assert history == [
        (2, "Original desktop history"),
        (9, "Previously auto-captured history")
    ], "Device history was unexpectedly changed"

    print("History preservation: PASSED")

    connection.close()


if __name__ == "__main__":
    test_device_ip_conflict()