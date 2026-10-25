
"""
NetGuardian - Safe Behavioral Collection Scheduling

Select completed five-minute windows with a safety delay.

Does not access SQLite, create alerts, or schedule jobs.
"""

from datetime import datetime, timedelta


def get_safe_completed_window_end(
    now=None,
    delay_minutes=2,
    window_minutes=5
):
    """
    Return the latest eligible completed window endpoint.

    A window is eligible only after its safety delay
    has elapsed.
    """

    if delay_minutes < 0:
        raise ValueError("Delay cannot be negative")

    if window_minutes != 5:
        raise ValueError("Only five-minute windows supported")

    current = now if now is not None else datetime.now()

    if not isinstance(current, datetime):
        raise TypeError("now must be a datetime")

    eligible_time = current - timedelta(
        minutes=delay_minutes
    )

    return eligible_time.replace(
        minute=(
            eligible_time.minute // window_minutes
        ) * window_minutes,
        second=0,
        microsecond=0
    )
