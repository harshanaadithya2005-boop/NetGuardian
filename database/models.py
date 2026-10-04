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

    # Check whether this IP address already exists
    cursor.execute(
        "SELECT id FROM devices WHERE ip_address = ?",
        (ip_address,)
    )

    existing_device = cursor.fetchone()

    if existing_device:
        # Device already exists
        cursor.execute("""
            UPDATE devices
            SET mac_address = ?,
                hostname = ?,
                last_seen = ?,
                status = 'online'
            WHERE ip_address = ?
        """, (
            mac_address,
            hostname,
            timestamp,
            ip_address
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