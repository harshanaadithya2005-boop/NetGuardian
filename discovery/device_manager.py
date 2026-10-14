from database.db import get_connection


def set_device_name(mac_address, device_name):
    """Assign a user-friendly name to a device using its MAC address."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE devices
        SET device_name = ?
        WHERE mac_address = ?
    """, (
        device_name,
        mac_address
    ))

    connection.commit()
    connection.close()