
import sqlite3
from unittest.mock import patch

import config
import database.models as models
import risk.risk_engine as risk
import app as netguardian


print("=" * 60)
print("STEP 373: DETECTION-TO-ALERT PIPELINE TEST")
print("=" * 60)

# An isolated SQLite database stored only in memory.
DB_URI = "file:ng_alert_test_373?mode=memory&cache=shared"


def test_connection():
    conn = sqlite3.connect(
        DB_URI,
        uri=True,
        timeout=10
    )
    conn.row_factory = sqlite3.Row
    return conn


# Keep one connection open so the in-memory DB persists.
anchor = test_connection()

try:
    anchor.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            timestamp TEXT NOT NULL
        )
    """)
    anchor.commit()

    TEST_IP = "192.168.8.250"
    DEVICE_ID = 999999

    synthetic_device = {
        "id": DEVICE_ID,
        "ip_address": TEST_IP,
        "mac_address": "02:AA:BB:CC:DD:EE",
        "hostname": "Synthetic-Test-Device",
        "trusted": 1,
        "status": "online",
        "risk_score": 0
    }

    # Real detector receives synthetic packet records.
    synthetic_traffic = [
        {
            "source_ip": TEST_IP,
            "destination_ip": "192.168.8.254",
            "protocol": "TCP",
            "tcp_flags": "S",
            "destination_port": 1000 + i,
            "packet_size": 60,
            "dns_query": None
        }
        for i in range(config.PORT_SCAN_THRESHOLD)
    ]

    def fake_traffic(*args, **kwargs):
        # DNS-specific one-minute query returns no DNS traffic.
        if kwargs.get("minutes") == 1:
            return []
        return synthetic_traffic

    def read_test_alerts():
        conn = test_connection()
        try:
            rows = conn.execute("""
                SELECT *
                FROM alerts
                ORDER BY id DESC
            """).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_api_alerts(*args, **kwargs):
        return [
            {**alert, "ip_address": TEST_IP}
            for alert in read_test_alerts()
        ]

    with (
        patch.object(
            models,
            "get_connection",
            side_effect=test_connection
        ),
        patch.object(risk, "get_recent_tcp_syn_traffic", return_value=synthetic_traffic),
        patch.object(risk, "get_recent_dns_queries", return_value=[]),
        patch.object(
            risk,
            "get_recent_traffic",
            side_effect=fake_traffic
        ),
        patch.object(
            risk,
            "check_behaviour_drift_for_device",
            return_value={
                "detected": False,
                "drift_score": 0.0,
                "traffic_spike": False
            }
        ),
        patch.object(
            risk,
            "update_device_risk"
        ) as mock_update,
        patch.object(
            risk,
            "quarantine_device"
        ) as mock_quarantine,
        patch.object(
            netguardian,
            "get_recent_alerts",
            side_effect=get_api_alerts
        ),
        patch.object(
            netguardian,
            "get_alert_reset_id",
            return_value=0
        )
    ):
        print("\n=== TEST 1: REAL PORT-SCAN DETECTION ===")

        result = risk.evaluate_device_risk(
            synthetic_device,
            auto_quarantine=False
        )

        print("Risk score:", result["risk_score"])
        print("Risk level:", result["risk_level"])
        print("Detected indicators:", result["indicators"])

        assert "port_scan" in result["indicators"]
        assert result["risk_score"] == 30
        assert result["risk_level"] == "LOW"
        assert mock_update.called
        assert not mock_quarantine.called

        print("PASS: Synthetic port scan detected")

        print("\n=== TEST 2: SQLITE ALERT CREATION ===")

        alerts = read_test_alerts()

        print("Database alerts:", len(alerts))

        assert len(alerts) == 1
        assert alerts[0]["device_id"] == DEVICE_ID
        assert alerts[0]["alert_type"] == "port_scan"
        assert alerts[0]["status"] == "open"
        assert alerts[0]["severity"] == "HIGH"

        print("PASS: Real alert creation saved to isolated SQLite")

        print("\n=== TEST 3: DUPLICATE PREVENTION ===")

        risk.evaluate_device_risk(
            synthetic_device,
            auto_quarantine=False
        )

        alerts_after = read_test_alerts()

        print("Alerts after second evaluation:", len(alerts_after))

        assert len(alerts_after) == 1

        print("PASS: No duplicate open alert created")

        print("\n=== TEST 4: SECURITY ALERT API ===")

        client = netguardian.app.test_client()
        response = client.get("/api/alerts")

        print("HTTP status:", response.status_code)

        assert response.status_code == 200

        api_alerts = response.get_json()

        print("API alerts:", len(api_alerts))

        assert len(api_alerts) == 1
        assert api_alerts[0]["alert_type"] == "port_scan"
        assert api_alerts[0]["device_id"] == DEVICE_ID

        print("PASS: Alert successfully returned through Flask API")

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    print("Port-scan detection: PASS")
    print("SQLite alert creation: PASS")
    print("Duplicate prevention: PASS")
    print("Flask alert API: PASS")
    print("Real database modified: No")
    print("Router operations: None")
    print("Automatic quarantine: Not triggered")
    print("\nOVERALL RESULT: PASS")

finally:
    anchor.close()

print("In-memory test database released.")
