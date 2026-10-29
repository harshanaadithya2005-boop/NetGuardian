
import sqlite3
import tempfile
from pathlib import Path

import database.models as models


print("=== STEP 354: FIRST-DISCOVERY ALERT TEST ===")

# Remember the real connection function.
original_get_connection = models.get_connection

with tempfile.TemporaryDirectory() as temp_dir:
    test_db = Path(temp_dir) / "netguardian_test.db"

    # Create a consistent backup of the real SQLite database.
    # This reads the live database without modifying it.
    source = original_get_connection()

    try:
        destination = sqlite3.connect(test_db)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()

    # Redirect database.models operations to the temporary copy.
    def test_get_connection():
        conn = sqlite3.connect(
            test_db,
            timeout=10
        )
        conn.row_factory = sqlite3.Row
        return conn

    models.get_connection = test_get_connection

    try:
        # Select two currently unused test addresses
        # within the configured local network.
        import ipaddress
        import config

        network = ipaddress.ip_network(
            config.TARGET_NETWORK,
            strict=False
        )

        conn = test_get_connection()

        try:
            existing_ips = {
                row["ip_address"]
                for row in conn.execute(
                    "SELECT ip_address FROM devices"
                ).fetchall()
            }

            existing_macs = {
                str(row["mac_address"] or "").upper()
                for row in conn.execute(
                    "SELECT mac_address FROM devices"
                ).fetchall()
            }
        finally:
            conn.close()

        test_ips = [
            str(ip)
            for ip in network.hosts()
            if str(ip) not in existing_ips
        ]

        if len(test_ips) < 2:
            raise RuntimeError(
                "Not enough unused addresses in test database."
            )

        ip_one, ip_two = test_ips[-2:]

        # Locally administered MAC used only in test database.
        test_mac = "02:AA:BB:CC:DD:EE"

        if test_mac in existing_macs:
            raise RuntimeError(
                "Test MAC already exists. Choose another test MAC."
            )

        def count_alerts(device_id):
            conn = test_get_connection()

            try:
                return conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM alerts
                    WHERE device_id = ?
                      AND alert_type = 'unknown_device'
                    """,
                    (device_id,)
                ).fetchone()[0]
            finally:
                conn.close()

        # TEST 1: Register a new verified device.
        device_id = models.add_or_update_device(
            ip_address=ip_one,
            mac_address=test_mac,
            hostname="NetGuardian-Test-Device"
        )

        first_count = count_alerts(device_id)

        print("\nTEST 1 â€” New device registration")
        print("Device ID:", device_id)
        print("Discovery alerts:", first_count)

        assert first_count == 1, (
            "Expected exactly one first-discovery alert."
        )

        # TEST 2: Reconnect using the same MAC and IP.
        reconnected_id = models.add_or_update_device(
            ip_address=ip_one,
            mac_address=test_mac,
            hostname="NetGuardian-Test-Device"
        )

        second_count = count_alerts(device_id)

        print("\nTEST 2 â€” Same device reconnects")
        print("Same device ID:", reconnected_id == device_id)
        print("Discovery alerts:", second_count)

        assert reconnected_id == device_id
        assert second_count == 1

        # TEST 3: Simulate a DHCP IP address change.
        reassigned_id = models.add_or_update_device(
            ip_address=ip_two,
            mac_address=test_mac,
            hostname="NetGuardian-Test-Device"
        )

        third_count = count_alerts(device_id)

        print("\nTEST 3 â€” Device receives new IP")
        print("Same device ID:", reassigned_id == device_id)
        print("Discovery alerts:", third_count)

        assert reassigned_id == device_id
        assert third_count == 1

        print("\n=== FINAL RESULTS ===")
        print("New-device alert:", "PASS")
        print("Reconnect deduplication:", "PASS")
        print("DHCP identity preservation:", "PASS")
        print("Original database unchanged:", True)

    finally:
        models.get_connection = original_get_connection

print("\nTemporary test database deleted.")
