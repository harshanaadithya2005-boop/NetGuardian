
"""
NetGuardian â€” Behavioral Traffic Window Metrics

Calculates observed traffic metrics for an individual device
over a fixed-duration time window.

Read-only: does not update devices, profiles, or alerts.
"""

from datetime import datetime, timedelta
from database.db import get_connection


def get_device_window_metrics(
    device_id,
    minutes=5,
    end_time=None
):
    """
    Calculate observed network behavior for a device.

    Metrics:
        - Outbound packet count
        - Outbound bandwidth in MB
        - Distinct destination IPs
        - Distinct destination ports
        - Conventional DNS query count

    Only real traffic originating from the device is counted.

    Returns None when the device does not exist.
    """

    if minutes <= 0:
        raise ValueError(
            "minutes must be greater than zero"
        )

    end = end_time or datetime.now()

    if not isinstance(end, datetime):
        raise TypeError(
            "end_time must be a datetime object"
        )

    start = end - timedelta(minutes=minutes)

    start_text = start.isoformat(
        timespec="seconds"
    )

    end_text = end.isoformat(
        timespec="seconds"
    )

    conn = get_connection()

    try:
        # Get the device's current IP address.
        device = conn.execute("""
            SELECT
                id,
                ip_address,
                mac_address,
                device_name,
                hostname
            FROM devices
            WHERE id = ?
        """, (device_id,)).fetchone()

        if device is None:
            return None

        ip_address = device["ip_address"]

        # Count outbound real traffic in the selected window.
        row = conn.execute("""
            SELECT
                COUNT(*) AS packet_count,

                COALESCE(
                    SUM(COALESCE(packet_size, 0)),
                    0
                ) AS total_bytes,

                COUNT(DISTINCT destination_ip)
                    AS distinct_ips,

                COUNT(DISTINCT destination_port)
                    AS distinct_ports,

                COALESCE(
                    SUM(
                        CASE
                            WHEN destination_port = 53
                             AND dns_query IS NOT NULL
                             AND TRIM(dns_query) != ''
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS dns_requests

            FROM traffic
            WHERE device_id = ?
              AND source_ip = ?
              AND datetime(timestamp) >= datetime(?)
              AND datetime(timestamp) < datetime(?)
              AND COALESCE(is_simulated, 0) = 0
        """, (
            device_id,
            ip_address,
            start_text,
            end_text
        )).fetchone()

        total_bytes = int(row["total_bytes"])

        return {
            "device_id": device_id,
            "ip_address": ip_address,
            "window_minutes": minutes,
            "window_start": start_text,
            "window_end": end_text,
            "packet_count": int(
                row["packet_count"]
            ),
            "dns_requests": int(
                row["dns_requests"]
            ),
            "distinct_ips": int(
                row["distinct_ips"]
            ),
            "distinct_ports": int(
                row["distinct_ports"]
            ),
            "data_mb": round(
                total_bytes / (1024 * 1024),
                4
            )
        }

    finally:
        conn.close()
