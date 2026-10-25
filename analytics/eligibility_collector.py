
"""
NetGuardian - Eligibility-Gated History Collector

Requires a successful window eligibility assessment
before invoking the safe history collector.

IMPORTANT:
This is a preliminary collection gate, not approval
for automatic historical learning or unrestricted
backfilling.
"""

from datetime import datetime

from analytics.window_eligibility import (
    assess_window_eligibility
)
from analytics.safe_history_collector import (
    collect_safe_observation
)


def collect_eligible_observation(
    history_conn,
    audit_conn,
    device_id,
    window_end,
    now=None,
    minimum_packets=20,
    max_age_minutes=15
):
    """
    Assess eligibility and conditionally collect.

    history_conn: destination history SQLite connection.
    audit_conn: read-only connection used for traffic audit.

    Returns a summary dictionary.
    """

    current = now if now is not None else datetime.now()

    assessment = assess_window_eligibility(
        conn=audit_conn,
        device_id=device_id,
        window_end=window_end,
        now=current,
        max_age_minutes=max_age_minutes,
        minimum_packets=minimum_packets
    )

    if not assessment["eligible"]:
        return {
            "device_id": device_id,
            "status": assessment["status"],
            "stored": False,
            "eligibility_passed": False
        }

    # The collector performs its own identity checks
    # again before attempting history insertion.
    result = collect_safe_observation(
        conn=history_conn,
        device_id=device_id,
        completed_end=window_end,
        minimum_packets=minimum_packets
    )

    return {
        **result,
        "eligibility_passed": True
    }
