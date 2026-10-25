
"""
NetGuardian - Traffic Attribution Audit

Read-only checks for bidirectional traffic associated
with one device during a completed observation window.
"""

from datetime import timedelta


def audit_device_traffic(
    conn,
    device_id,
    device_ip,
    window_end
):
    """
    Classify real traffic assigned to a device ID.

    Requires an existing SQLite connection and
    a datetime window_end.

    Does not write to the database.
    """

    window_start = window_end - timedelta(minutes=5)

    row = conn.execute("""
        SELECT
            COUNT(*) AS total,

            COALESCE(SUM(
                CASE WHEN source_ip = ?
                THEN 1 ELSE 0 END
            ), 0) AS outbound,

            COALESCE(SUM(
                CASE
                    WHEN (source_ip IS NULL OR source_ip <> ?)
                     AND destination_ip = ?
                    THEN 1 ELSE 0
                END
            ), 0) AS inbound,

            COALESCE(SUM(
                CASE
                    WHEN (source_ip IS NULL OR source_ip <> ?)
                     AND (
                         destination_ip IS NULL
                         OR destination_ip <> ?
                     )
                    THEN 1 ELSE 0
                END
            ), 0) AS unattributed

        FROM traffic
        WHERE device_id = ?
          AND datetime(timestamp) >= datetime(?)
          AND datetime(timestamp) < datetime(?)
          AND COALESCE(is_simulated, 0) = 0
    """, (
        device_ip,
        device_ip,
        device_ip,
        device_ip,
        device_ip,
        device_id,
        window_start.isoformat(timespec="seconds"),
        window_end.isoformat(timespec="seconds")
    )).fetchone()

    result = {
        "device_id": device_id,
        "window_end": window_end.isoformat(
            timespec="seconds"
        ),
        "total": row["total"],
        "outbound": row["outbound"],
        "inbound": row["inbound"],
        "unattributed": row["unattributed"]
    }

    assert (
        result["total"]
        == result["outbound"]
        + result["inbound"]
        + result["unattributed"]
    ), "Packet attribution counts do not reconcile"

    if result["total"] == 0:
        result["status"] = "NO_CAPTURED_PACKETS"
    elif result["unattributed"] > 0:
        result["status"] = "ATTRIBUTION_REVIEW"
    else:
        result["status"] = "ENDPOINTS_CONSISTENT"

    return result
