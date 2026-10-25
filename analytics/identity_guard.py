
"""
NetGuardian - Behavioral Observation Identity Guard

Checks that device identity remains consistent
during a collection operation.

This is a read-only safety check.
"""

import ipaddress
import re

from database.db import get_connection


MAC_PATTERN = re.compile(
    r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$"
)


def get_identity_snapshot(device_id):
    """Retrieve the current verified device identity."""

    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT id, ip_address, mac_address
            FROM devices
            WHERE id = ?
        """, (device_id,)).fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def verify_identity_snapshots(before, after):
    """
    Compare device identity before and after collection.

    Returns (safe, reason).
    """

    if not before or not after:
        return False, "DEVICE_NOT_FOUND"

    if before.get("id") != after.get("id"):
        return False, "DEVICE_ID_CHANGED"

    before_mac = str(
        before.get("mac_address") or ""
    ).strip().upper()

    after_mac = str(
        after.get("mac_address") or ""
    ).strip().upper()

    if (
        not MAC_PATTERN.fullmatch(before_mac)
        or before_mac == "00:00:00:00:00:00"
    ):
        return False, "INVALID_MAC"

    if before_mac != after_mac:
        return False, "MAC_CHANGED"

    try:
        old_ip = ipaddress.ip_address(
            before["ip_address"]
        )
        new_ip = ipaddress.ip_address(
            after["ip_address"]
        )
    except (ValueError, TypeError, KeyError):
        return False, "INVALID_IP"

    if old_ip != new_ip:
        return False, "IP_CHANGED"

    return True, "IDENTITY_VERIFIED"
