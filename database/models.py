from database.db import get_connection


def add_or_update_device(
    ip_address,
    mac_address,
    hostname=None,
    device_name=None,
    device_type=None,
    timestamp=None
):
    """Add a new device or update an existing device."""

    connection = get_connection()
    cursor = connection.cursor()

    # Identify the device by MAC address
    cursor.execute(
        "SELECT id FROM devices WHERE mac_address = ?",
        (mac_address,)
    )

    existing_device = cursor.fetchone()

    if existing_device:
        # Device already exists - update its current network information
        cursor.execute("""
            UPDATE devices
            SET ip_address = ?,
                mac_address = ?,
                hostname = ?,
                device_type = ?,
                last_seen = ?,
                status = 'online'
            WHERE id = ?
        """, (
            ip_address,
            mac_address,
            hostname,
            device_type,
            timestamp,
            existing_device["id"]
        ))
    else:
        # New device
        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                hostname,
                device_name,
                device_type,
                first_seen,
                last_seen,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'online')
        """, (
            ip_address,
            mac_address,
            hostname,
            device_name,
            device_type,
            timestamp,
            timestamp
        ))

    connection.commit()
    connection.close()


def mark_missing_devices_offline(discovered_ips):
    """Mark devices not found in the latest scan as offline."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT ip_address FROM devices")
    stored_devices = cursor.fetchall()

    for device in stored_devices:
        ip_address = device["ip_address"]

        if ip_address not in discovered_ips:
            cursor.execute("""
                UPDATE devices
                SET status = 'offline'
                WHERE ip_address = ?
            """, (ip_address,))

    connection.commit()
    connection.close()
    