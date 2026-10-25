
from database.models import (
    add_or_update_device,
    get_all_devices,
)


def sync_connected_wifi_devices(wifi_devices):
    """
    Synchronize verified Huawei WLAN clients into SQLite.

    - Match devices by MAC address.
    - Preserve existing device IDs.
    - Preserve custom device names.
    - Update current IP addresses.
    - Update hostnames when available.
    - Mark observed clients Online via the existing
      add_or_update_device function.

    IMPORTANT:
    This function does NOT mark missing devices Offline.
    """

    existing_devices = get_all_devices()

    known_by_mac = {
        str(device.get("mac_address") or "").upper(): device
        for device in existing_devices
        if device.get("mac_address")
    }

    updated = []

    for wifi in wifi_devices:
        ip = wifi.get("ip")
        mac = str(wifi.get("mac") or "").upper()

        if not ip or not mac:
            continue

        existing = known_by_mac.get(mac)

        router_hostname = wifi.get("hostname")

        if router_hostname in ("", "Unknown"):
            router_hostname = None

        # Keep custom names and existing device types.
        existing_type = (
            existing.get("device_type")
            if existing else None
        )

        # Do not overwrite saved custom device names.
        result = add_or_update_device(
            ip_address=ip,
            mac_address=mac,
            hostname=router_hostname,
            device_type=existing_type,
        )

        updated.append({
            "ip": ip,
            "mac": mac,
            "hostname": router_hostname,
            "existing_id": (
                existing.get("id") if existing else None
            ),
            "result": result,
        })

    return updated


def mark_disconnected_wifi_devices_offline(disconnected_macs):
    """
    Mark router-confirmed disconnected Wi-Fi clients Offline.

    Uses verified MAC addresses rather than IP addresses.
    Does not delete device records or modify trust, risk,
    quarantine, or device names.
    """
    from database.db import get_connection

    if not disconnected_macs:
        return 0

    normalized_macs = {
        str(mac).strip().upper()
        for mac in disconnected_macs
        if mac
    }

    if not normalized_macs:
        return 0

    conn = get_connection()

    try:
        updated = 0

        for mac in normalized_macs:
            cursor = conn.execute(
                """
                UPDATE devices
                SET status = 'offline'
                WHERE UPPER(mac_address) = ?
                  AND status NOT IN ('offline', 'quarantined')
                """,
                (mac,)
            )

            updated += cursor.rowcount

        conn.commit()

        return updated

    finally:
        conn.close()


def register_huawei_wifi_devices(wifi_devices):
    """
    Remember devices confirmed by the Huawei WLAN API.

    Previously registered MAC addresses are preserved,
    including devices that are currently disconnected.
    """
    from database.db import get_connection

    conn = get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS huawei_wifi_devices (
                mac_address TEXT PRIMARY KEY
            )
        """)

        registered = 0

        for device in wifi_devices:
            mac = str(device.get("mac") or "").strip().upper()

            if not mac:
                continue

            conn.execute("""
                INSERT OR IGNORE INTO huawei_wifi_devices
                (mac_address)
                VALUES (?)
            """, (mac,))

            registered += 1

        conn.commit()
        return registered

    finally:
        conn.close()


def get_huawei_managed_macs():
    """
    Return all previously confirmed Huawei Wi-Fi MACs,
    including currently disconnected clients.
    """
    from database.db import get_connection

    conn = get_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS huawei_wifi_devices (
                mac_address TEXT PRIMARY KEY
            )
        """)

        rows = conn.execute("""
            SELECT mac_address
            FROM huawei_wifi_devices
        """).fetchall()

        conn.commit()

        return {
            str(row["mac_address"]).upper()
            for row in rows
        }

    finally:
        conn.close()
