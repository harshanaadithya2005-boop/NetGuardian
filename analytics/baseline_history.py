
"""
NetGuardian - Historical Behavioral Measurements

Stores validated five-minute observations.

No automatic connection to production SQLite.
No automatic profile updates or alert generation.
"""

def create_history_table(conn):
    """Create the observation table in the supplied database."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS behaviour_window_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            packet_count INTEGER NOT NULL
                CHECK (packet_count >= 0),
            data_mb REAL NOT NULL
                CHECK (data_mb >= 0),
            dns_requests INTEGER NOT NULL
                CHECK (dns_requests >= 0),
            distinct_ips INTEGER NOT NULL
                CHECK (distinct_ips >= 0),
            distinct_ports INTEGER NOT NULL
                CHECK (distinct_ports >= 0),
            quality_status TEXT NOT NULL
                CHECK (quality_status IN (
                    'QUALIFIED', 'INSUFFICIENT'
                )),
            UNIQUE(device_id, window_start, window_end)
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_behaviour_history_device
        ON behaviour_window_history(device_id, window_start)
    """)


def save_observation(conn, metrics, minimum_packets=20):
    """
    Save one completed five-minute observation.

    Returns True if inserted, False if already present.
    The caller controls the transaction.
    """

    if metrics.get("window_minutes") != 5:
        raise ValueError("Only five-minute windows are supported")

    start = metrics["window_start"]
    end = metrics["window_end"]

    from datetime import datetime, timedelta

    start_dt = datetime.fromisoformat(start)
    end_dt = datetime.fromisoformat(end)

    if end_dt - start_dt != timedelta(minutes=5):
        raise ValueError("Invalid observation duration")

    if end_dt > datetime.now():
        raise ValueError("Future or incomplete window")

    if minimum_packets < 1:
        raise ValueError("minimum_packets must be positive")

    fields = (
        "packet_count",
        "data_mb",
        "dns_requests",
        "distinct_ips",
        "distinct_ports"
    )

    for field in fields:
        if metrics[field] is None or metrics[field] < 0:
            raise ValueError(f"Invalid value for {field}")

    packet_count = int(metrics["packet_count"])

    if packet_count != metrics["packet_count"]:
        raise ValueError("packet_count must be an integer")

    quality = (
        "QUALIFIED"
        if packet_count >= minimum_packets
        else "INSUFFICIENT"
    )

    cursor = conn.execute("""
        INSERT OR IGNORE INTO behaviour_window_history (
            device_id,
            window_start,
            window_end,
            packet_count,
            data_mb,
            dns_requests,
            distinct_ips,
            distinct_ports,
            quality_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        metrics["device_id"],
        start,
        end,
        packet_count,
        metrics["data_mb"],
        metrics["dns_requests"],
        metrics["distinct_ips"],
        metrics["distinct_ports"],
        quality
    ))

    return cursor.rowcount == 1
