
from unittest.mock import patch
import app as netguardian

print("=" * 60)
print("STEP 371: SECURITY ALERT API INTEGRATION")
print("=" * 60)

# Synthetic records — not inserted into SQLite.
synthetic_alerts = [
    {
        "id": 105,
        "device_id": 4,
        "ip_address": "192.168.8.101",
        "alert_type": "port_scan",
        "severity": "HIGH",
        "status": "open",
        "risk_score": 30,
        "description": "Synthetic port scan detected",
        "timestamp": "2026-10-25T09:00:00"
    },
    {
        "id": 104,
        "device_id": 4,
        "ip_address": "192.168.8.101",
        "alert_type": "dns_anomaly",
        "severity": "MEDIUM",
        "status": "resolved",
        "risk_score": 20,
        "description": "Synthetic DNS anomaly",
        "timestamp": "2026-10-25T08:59:00"
    },
    {
        "id": 103,
        "device_id": 99,
        "ip_address": "8.8.8.8",
        "alert_type": "port_scan",
        "severity": "HIGH",
        "status": "open",
        "risk_score": 30,
        "description": "Nonlocal test record",
        "timestamp": "2026-10-25T08:58:00"
    },
    {
        "id": 99,
        "device_id": 4,
        "ip_address": "192.168.8.101",
        "alert_type": "unknown_device",
        "severity": "MEDIUM",
        "status": "ignored",
        "risk_score": 20,
        "description": "Alert from before reset",
        "timestamp": "2026-10-25T08:00:00"
    }
]

# The last alert reset was at ID 100.
with patch.object(
    netguardian,
    "get_alert_reset_id",
    return_value=100
), patch.object(
    netguardian,
    "get_recent_alerts",
    return_value=synthetic_alerts
):
    client = netguardian.app.test_client()
    response = client.get("/api/alerts")

    assert response.status_code == 200
    alerts = response.get_json()
    assert isinstance(alerts, list)

    returned_ids = {alert["id"] for alert in alerts}

    checks = {
        "API returns HTTP 200":
            response.status_code == 200,

        "Local port-scan alert visible":
            105 in returned_ids,

        "Resolved DNS alert retained":
            104 in returned_ids,

        "Public-IP alert excluded":
            103 not in returned_ids,

        "Previously reset alert excluded":
            99 not in returned_ids,

        "Exactly two relevant alerts":
            len(alerts) == 2
    }

print("\n=== RESULTS ===")

for name, passed in checks.items():
    print(f"{'PASS' if passed else 'FAIL'} | {name}")

print("\nReturned alert IDs:", sorted(returned_ids))

total_passed = sum(checks.values())

print("\n=== FINAL RESULTS ===")
print("Passed:", total_passed)
print("Failed:", len(checks) - total_passed)
print("Overall:", "PASS" if all(checks.values()) else "FAIL")
print("SQLite writes: None")
print("Router operations: None")

if not all(checks.values()):
    raise SystemExit(1)
