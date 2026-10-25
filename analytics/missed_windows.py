
"""
NetGuardian - Missed Behavioral Window Planner

Plans five-minute collection windows after the last
recorded window, subject to the collection safety delay.

Read-only calculation. Does not access SQLite.
"""

from datetime import datetime, timedelta

from analytics.collection_schedule import (
    get_safe_completed_window_end
)


WINDOW = timedelta(minutes=5)


def plan_missing_windows(
    last_collected_end,
    now=None,
    delay_minutes=2,
    max_windows=12
):
    """
    Return eligible window end times in chronological order.

    last_collected_end:
        End time of the latest collected window for
        ONE device, or None if there is no history.

    If history is empty, returns only the latest
    eligible window, not an unlimited backfill.

    max_windows limits the number returned per run.
    """

    if (
        not isinstance(max_windows, int)
        or isinstance(max_windows, bool)
        or max_windows < 1
    ):
        raise ValueError("max_windows must be positive")

    current = now if now is not None else datetime.now()

    if not isinstance(current, datetime):
        raise TypeError("now must be a datetime")

    if current.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    eligible_end = get_safe_completed_window_end(
        now=current,
        delay_minutes=delay_minutes,
        window_minutes=5
    )

    if last_collected_end is None:
        return [eligible_end]

    if isinstance(last_collected_end, str):
        last_collected_end = datetime.fromisoformat(
            last_collected_end
        )

    if not isinstance(last_collected_end, datetime):
        raise TypeError(
            "last_collected_end must be datetime or ISO string"
        )

    if last_collected_end.tzinfo is not None:
        raise ValueError("Use local naive timestamps")

    if (
        last_collected_end.minute % 5 != 0
        or last_collected_end.second != 0
        or last_collected_end.microsecond != 0
    ):
        raise ValueError(
            "Last window end must align to five minutes"
        )

    if last_collected_end > eligible_end:
        raise ValueError(
            "Last collected window is in the future"
        )

    results = []
    next_end = last_collected_end + WINDOW

    while (
        next_end <= eligible_end
        and len(results) < max_windows
    ):
        results.append(next_end)
        next_end += WINDOW

    return results
