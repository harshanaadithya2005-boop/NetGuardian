
from contextlib import ExitStack
from unittest.mock import patch

import risk.risk_engine as risk

print("=" * 60)
print("STEP 384: DNS-ANOMALY INTEGRATION TEST")
print("=" * 60)

DEVICE_ID = 999999
DEVICE_IP = "192.168.8.250"

device = {
    "id": DEVICE_ID,
    "ip_address": DEVICE_IP,
    "mac_address": "02:AA:BB:CC:DD:EE",
    "trusted": 1,
    "status": "online",
    "risk_score": 0,
}

def dns_record(domain, timestamp):
    return {
        "source_ip": DEVICE_IP,
        "destination_ip": "192.168.8.1",
        "destination_port": 53,
        "protocol": "UDP",
        "dns_query": domain,
        "timestamp": timestamp,
    }

normal_queries = [
    dns_record(
        "example.com",
        "2026-10-25T10:00:00"
    )
]

suspicious_queries = [
    dns_record(
        ("a" * 60) + ".example.com",
        "2026-10-25T10:00:01"
    )
]

with ExitStack() as stack:

    # Mock regular packet retrieval.
    stack.enter_context(
        patch.object(
            risk,
            "get_recent_traffic",
            return_value=[]
        )
    )

    # Mock the dedicated TCP SYN query.
    stack.enter_context(
        patch.object(
            risk,
            "get_recent_tcp_syn_traffic",
            return_value=[]
        )
    )

    # Mock only DNS retrieval, keeping the REAL DNS detector.
    mock_dns = stack.enter_context(
        patch.object(
            risk,
            "get_recent_dns_queries",
            return_value=normal_queries
        )
    )

    # Isolate behavioral drift.
    stack.enter_context(
        patch.object(
            risk,
            "check_behaviour_drift_for_device",
            return_value={
                "detected": False,
                "drift_score": 0.0,
                "traffic_spike": False
            }
        )
    )

    # Block real database writes.
    mock_alert = stack.enter_context(
        patch.object(risk, "create_alert")
    )

    mock_update = stack.enter_context(
        patch.object(risk, "update_device_risk")
    )

    # Block any router quarantine operation.
    mock_quarantine = stack.enter_context(
        patch.object(risk, "quarantine_device")
    )

    print("\n=== TEST 1: NORMAL DNS ACTIVITY ===")

    normal = risk.evaluate_device_risk(
        device,
        auto_quarantine=False
    )

    assert normal["risk_score"] == 0
    assert "dns_anomaly" not in normal["indicators"]
    assert mock_alert.call_count == 0

    print("PASS: Normal DNS activity produces no alert")

    print("\n=== TEST 2: SUSPICIOUS DNS ACTIVITY ===")

    mock_dns.return_value = suspicious_queries

    suspicious = risk.evaluate_device_risk(
        device,
        auto_quarantine=False
    )

    assert suspicious["risk_score"] == 20
    assert suspicious["risk_level"] == "LOW"
    assert "dns_anomaly" in suspicious["indicators"]

    print("PASS: Suspicious domain detected")
    print("Risk score:", suspicious["risk_score"])

    print("\n=== TEST 3: DNS ALERT GENERATION ===")

    dns_alerts = [
        call
        for call in mock_alert.call_args_list
        if call.kwargs.get("alert_type") == "dns_anomaly"
    ]

    assert len(dns_alerts) == 1
    assert dns_alerts[0].kwargs["severity"] == "MEDIUM"
    assert dns_alerts[0].kwargs["device_id"] == DEVICE_ID

    print("PASS: Correct DNS-anomaly alert generated")

    print("\n=== TEST 4: DEDICATED QUERY USED ===")

    assert mock_dns.call_count == 2

    mock_dns.assert_called_with(
        device_id=DEVICE_ID,
        minutes=1,
        limit=5000
    )

    print("PASS: Dedicated DNS query function used")

    print("\n=== TEST 5: DATABASE AND ROUTER SAFETY ===")

    assert mock_update.call_count == 2
    assert not mock_quarantine.called

    print("PASS: Database writes were mocked")
    print("PASS: Router quarantine was not triggered")

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Total test groups: 5")
print("Passed: 5")
print("Failed: 0")
print("OVERALL RESULT: PASS")
