
import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.behaviour_windows as bw

print("=" * 60)
print("STEP 396: BEHAVIORAL WINDOW UNIT TEST")
print("=" * 60)

DB_URI = "file:ng_step396?mode=memory&cache=shared"


def connect():
    conn = sqlite3.connect(DB_URI, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


anchor = connect()

try:
    anchor.executescript("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            ip_address TEXT,
            mac_address TEXT,
            device_name TEXT,
            hostname TEXT
        );

        CREATE TABLE traffic (
            id INTEGER PRIMARY KEY,
            device_id INTEGER,
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            packet_size INTEGER,
            dns_query TEXT,
            timestamp TEXT,
            is_simulated INTEGER
        );

        INSERT INTO devices VALUES (
            999999,
            '192.168.8.250',
            '02:AA:BB:CC:DD:EE',
            'Synthetic Device',
            'test-device'
        );
    """)

    packets = [
        # Three valid outbound packets inside the window.
        (1, 999999, "192.168.8.250", "1.1.1.1",
         443, 100, None, "2026-10-25T10:16:00", 0),

        (2, 999999, "192.168.8.250", "8.8.8.8",
         53, 200, "example.com", "2026-10-25T10:17:00", 0),

        (3, 999999, "192.168.8.250", "1.1.1.1",
         443, 1048276, None, "2026-10-25T10:18:00", 0),

        # Inbound packet — must be excluded.
        (4, 999999, "1.1.1.1", "192.168.8.250",
         443, 500, None, "2026-10-25T10:18:30", 0),

        # Simulated packet — must be excluded.
        (5, 999999, "192.168.8.250", "9.9.9.9",
         8080, 500, None, "2026-10-25T10:19:00", 1),

        # Before the five-minute window — excluded.
        (6, 999999, "192.168.8.250", "4.4.4.4",
         80, 500, None, "2026-10-25T10:14:59", 0),

        # Exactly at the window endpoint — excluded.
        (7, 999999, "192.168.8.250", "5.5.5.5",
         22, 500, None, "2026-10-25T10:20:00", 0),
    ]

    anchor.executemany("""
        INSERT INTO traffic (
            id, device_id, source_ip, destination_ip,
            destination_port, packet_size, dns_query,
            timestamp, is_simulated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, packets)

    anchor.commit()

    with patch.object(bw, "get_connection", side_effect=connect):
        metrics = bw.get_device_window_metrics(
            device_id=999999,
            minutes=5,
            end_time=datetime(2026, 10, 25, 10, 20)
        )

        missing = bw.get_device_window_metrics(
            device_id=888888,
            minutes=5,
            end_time=datetime(2026, 10, 25, 10, 20)
        )

    print("\n=== METRICS ===")
    print(metrics)

    checks = {
        "Correct five-minute start":
            metrics["window_start"] == "2026-10-25T10:15:00",

        "Correct five-minute end":
            metrics["window_end"] == "2026-10-25T10:20:00",

        "Only three valid packets counted":
            metrics["packet_count"] == 3,

        "Bandwidth calculated correctly":
            metrics["data_mb"] == 1.0,

        "One DNS query counted":
            metrics["dns_requests"] == 1,

        "Two destination IPs":
            metrics["distinct_ips"] == 2,

        "Two destination ports":
            metrics["distinct_ports"] == 2,

        "Missing device returns None":
            missing is None,
    }

    print("\n=== RESULTS ===")
    for name, success in checks.items():
        print(
            f"{'PASS' if success else 'FAIL'} | {name}"
        )

    passed = sum(checks.values())
    failed = len(checks) - passed

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", failed)
    print("Overall:", "PASS" if failed == 0 else "FAIL")

    if failed:
        raise SystemExit(1)

finally:
    anchor.close()

print("Real NetGuardian database was not modified.")
