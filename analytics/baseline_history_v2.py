
"""
NetGuardian - Behavioral History V2

Stores completed five-minute observations with
device identity and validation metadata.

Operates only on a supplied SQLite connection.
No automatic production database access.
"""

from datetime import datetime, timedelta
from ipaddress import ip_address
import re


MAC_PATTERN = re.compile(
    r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$"
)


def create_history_table_v2(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behaviour_window_history_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            mac_address TEXT NOT NULL,
            observed_ip TEXT NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            packet_count INTEGER NOT NULL
                CHECK(packet_count >= 0),
            data_mb REAL NOT NULL
                CHECK(data_mb >= 0),
            dns_requests INTEGER NOT NULL
                CHECK(dns_requests >= 0),
            distinct_ips INTEGER NOT NULL
                CHECK(distinct_ips >= 0),
            distinct_ports INTEGER NOT NULL
                CHECK(distinct_ports >= 0),
            quality_status TEXT NOT NULL
                CHECK(quality_status IN (
                    'QUALIFIED', 'INSUFFICIENT'
                )),
            UNIQUE(device_id, window_start, window_end)
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS
            idx_behaviour_history_v2_identity
        ON behaviour_window_history_v2(
            device_id, mac_address, window_start
        )
    """)


def save_observation_v2(
    conn,
    metrics,
    mac_address,
    minimum_packets=20
):
    if metrics.get("window_minutes") != 5:
        raise ValueError("Only five-minute windows supported")

    start = datetime.fromisoformat(
        metrics["window_start"]
    )
    end = datetime.fromisoformat(
        metrics["window_end"]
    )

    if end - start != timedelta(minutes=5):
        raise ValueError("Invalid window duration")

    if (
        start.minute % 5 != 0
        or start.second != 0
        or start.microsecond != 0
    ):
        raise ValueError("Window must align to five-minute boundary")

    if end > datetime.now():
        raise ValueError("Incomplete or future window")

    if minimum_packets < 1:
        raise ValueError("Invalid minimum packet requirement")

    mac = str(mac_address).strip().upper()

    if (
        not MAC_PATTERN.fullmatch(mac)
        or mac == "00:00:00:00:00:00"
    ):
        raise ValueError("Invalid verified MAC address")

    observed_ip = str(metrics["ip_address"])

    try:
        ip_address(observed_ip)
    except ValueError:
        raise ValueError("Invalid observed IP address")

    if type(metrics["device_id"]) is not int or metrics["device_id"] <= 0:
        raise ValueError("Invalid device ID")

    for field in (
        "packet_count",
        "dns_requests",
        "distinct_ips",
        "distinct_ports"
    ):
        value = metrics[field]

        if type(value) is not int or value < 0:
            raise ValueError(f"Invalid {field}")

    import math

    bandwidth = metrics["data_mb"]

    if (
        isinstance(bandwidth, bool)
        or not isinstance(bandwidth, (int, float))
        or not math.isfinite(bandwidth)
        or bandwidth < 0
    ):
        raise ValueError("Invalid bandwidth")

    quality = (
        "QUALIFIED"
        if metrics["packet_count"] >= minimum_packets
        else "INSUFFICIENT"
    )

    # Reject conflicting identities for an existing window.
    existing = conn.execute("""
        SELECT mac_address, observed_ip
        FROM behaviour_window_history_v2
        WHERE device_id = ?
          AND window_start = ?
          AND window_end = ?
    """, (
        metrics["device_id"],
        metrics["window_start"],
        metrics["window_end"]
    )).fetchone()

    if existing:
        if (
            existing["mac_address"] != mac
            or existing["observed_ip"] != observed_ip
        ):
            raise ValueError(
                "Conflicting identity for existing observation"
            )
        return False

    cursor = conn.execute("""
        INSERT OR IGNORE INTO behaviour_window_history_v2 (
            device_id, mac_address, observed_ip,
            window_start, window_end, packet_count,
            data_mb, dns_requests, distinct_ips,
            distinct_ports, quality_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        metrics["device_id"],
        mac,
        observed_ip,
        metrics["window_start"],
        metrics["window_end"],
        metrics["packet_count"],
        bandwidth,
        metrics["dns_requests"],
        metrics["distinct_ips"],
        metrics["distinct_ports"],
        quality
    ))

    return cursor.rowcount == 1
