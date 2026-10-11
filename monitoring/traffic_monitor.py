from database.db import get_connection


def create_traffic_table():
    """Create the traffic statistics table if it does not already exist."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            packet_size INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_traffic_record(
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    packet_size,
    timestamp
):
    """Save captured packet metadata to the traffic statistics table."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO traffic_statistics (
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        timestamp
    ))

    connection.commit()
    connection.close()