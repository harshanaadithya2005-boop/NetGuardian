
import sqlite3
from datetime import datetime
from unittest.mock import patch

import analytics.behaviour_windows as windows
from analytics.baseline_history import (
    create_history_table,
    save_observation,
)

print("=" * 60)
print("STEP 400: BEHAVIOR HISTORY PIPELINE TEST")
print("=" * 60)

DB_URI = "file:ng_step400?mode=memory&cache=shared"


def connect():
    conn = sqlite3.connect(DB_URI, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


anchor = connect()
passed = 0


def check(name, condition):
    global passed
    assert condition, f"FAIL: {name}"
    passed += 1
    print("PASS:", name)


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
            'synthetic-test'
        );
    """)

    create_history_table(anchor)

    # 25 genuine outbound observations in a completed
    # five-minute window, including one DNS request.
    packets = []

    for i in range(25):
        packets.append((
            i + 1,
            999999,
            "192.168.8.250",
            "8.8.8.8" if i % 2 else "1.1.1.1",
            53 if i == 0 else 443,
            100,
            "example.com" if i == 0 else None,
            "2026-10-24T10:02:00",
            0
        ))

    # Additional records that must not be counted.
    packets.extend([
        (
            26, 999999, "1.1.1.1", "192.168.8.250",
            443, 200, None, "2026-10-24T10:02:00", 0
        ),
        (
            27, 999999, "192.168.8.250", "9.9.9.9",
            8080, 200, None, "2026-10-24T10:02:00", 1
        )
    ])

    anchor.executemany("""
        INSERT INTO traffic (
            id, device_id, source_ip, destination_ip,
            destination_port, packet_size, dns_query,
            timestamp, is_simulated
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, packets)

    anchor.commit()

    print("\n=== TEST 1: MEASURE TRAFFIC ===")

    with patch.object(
        windows,
        "get_connection",
        side_effect=connect
    ):
        metrics = windows.get_device_window_metrics(
            device_id=999999,
            minutes=5,
            end_time=datetime(2026, 10, 24, 10, 5)
        )

    print("Measured metrics:", metrics)

    check(
        "Only real outbound packets counted",
        metrics["packet_count"] == 25
    )

    check(
        "DNS and destinations calculated",
        metrics["dns_requests"] == 1
        and metrics["distinct_ips"] == 2
        and metrics["distinct_ports"] == 2
    )

    print("\n=== TEST 2: SAVE OBSERVATION ===")

    inserted = save_observation(
        anchor,
        metrics,
        minimum_packets=20
    )

    anchor.commit()

    check("Observation inserted", inserted is True)

    row = anchor.execute("""
        SELECT *
        FROM behaviour_window_history
        WHERE device_id = 999999
    """).fetchone()

    check(
        "Stored observation matches measurements",
        row["packet_count"] == 25
        and row["dns_requests"] == 1
        and row["distinct_ips"] == 2
        and row["distinct_ports"] == 2
        and row["quality_status"] == "QUALIFIED"
    )

    print("\n=== TEST 3: PREVENT DUPLICATES ===")

    duplicate = save_observation(anchor, metrics)

    check(
        "Repeated observation not inserted",
        duplicate is False
    )

    count = anchor.execute("""
        SELECT COUNT(*) AS total
        FROM behaviour_window_history
    """).fetchone()["total"]

    check("Exactly one historical observation", count == 1)

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print("Passed:", passed)
    print("Failed:", 6 - passed)
    print("Overall:", "PASS" if passed == 6 else "FAIL")

finally:
    anchor.close()

print("Temporary in-memory database closed.")
print("Production profiles and alerts unchanged.")
