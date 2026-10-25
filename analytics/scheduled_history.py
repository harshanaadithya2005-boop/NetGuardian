
"""
NetGuardian - Scheduled Behavioral History Collection

Runs one collection cycle for the latest eligible
completed five-minute window.

Does not create a background thread or schedule itself.
The caller supplies the destination SQLite connection.
"""

from datetime import datetime

from analytics.collection_schedule import (
    get_safe_completed_window_end
)
from analytics.safe_history_collector import (
    collect_safe_observation
)


def collect_scheduled_history(
    conn,
    device_ids,
    now=None,
    delay_minutes=2,
    minimum_packets=20
):
    """
    Collect one eligible window per device.

    Returns a summary of collection results.
    """

    current = now if now is not None else datetime.now()

    completed_end = get_safe_completed_window_end(
        now=current,
        delay_minutes=delay_minutes,
        window_minutes=5
    )

    results = []

    for device_id in device_ids:
        result = collect_safe_observation(
            conn=conn,
            device_id=device_id,
            completed_end=completed_end,
            minimum_packets=minimum_packets
        )

        results.append(result)

    return {
        "window_end": completed_end.isoformat(
            timespec="seconds"
        ),
        "total_devices": len(results),
        "stored": sum(
            1 for result in results
            if result.get("status") == "STORED"
        ),
        "already_exists": sum(
            1 for result in results
            if result.get("status") == "ALREADY_EXISTS"
        ),
        "skipped": sum(
            1 for result in results
            if result.get("status") not in {
                "STORED",
                "ALREADY_EXISTS"
            }
        ),
        "results": results
    }
