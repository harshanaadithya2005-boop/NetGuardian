
from unittest.mock import patch
from contextlib import ExitStack

import config
import risk.risk_engine as risk

print("=" * 60)
print("STEP 380: UPDATED PORT-SCAN INTEGRATION TEST")
print("=" * 60)

DEVICE_IP = "192.168.8.250"

device = {
    "id": 999999,
    "ip_address": DEVICE_IP,
    "mac_address": "02:AA:BB:CC:DD:EE",
    "trusted": 1,
    "status": "online",
    "risk_score": 0
}

syn_packets = [
    {
        "source_ip": DEVICE_IP,
        "destination_ip": "192.168.8.254",
        "protocol": "TCP",
        "tcp_flags": "S",
        "destination_port": 1000 + i
    }
    for i in range(config.PORT_SCAN_THRESHOLD)
]

with ExitStack() as stack:
    # Prevent real database reads and writes.
    stack.enter_context(
        patch.object(risk, "get_recent_traffic", return_value=[])
    )

    mock_syn = stack.enter_context(
        patch.object(
            risk,
            "get_recent_tcp_syn_traffic",
            return_value=[]
        )
    )

    stack.enter_context(
        patch.object(
            risk,
            "check_dns_anomaly",
            return_value={"detected": False}
        )
    )

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

    mock_update = stack.enter_context(
        patch.object(risk, "update_device_risk")
    )

    mock_alert = stack.enter_context(
        patch.object(risk, "create_alert")
    )

    mock_quarantine = stack.enter_context(
        patch.object(risk, "quarantine_device")
    )

    print("\n=== TEST 1: NORMAL TRAFFIC ===")

    normal = risk.evaluate_device_risk(
        device,
        auto_quarantine=False
    )

    assert normal["risk_score"] == 0
    assert "port_scan" not in normal["indicators"]
    assert mock_alert.call_count == 0

    print("PASS: Normal traffic produces no port-scan alert")

    print("\n=== TEST 2: SYN PORT SCAN ===")

    mock_syn.return_value = syn_packets

    suspicious = risk.evaluate_device_risk(
        device,
        auto_quarantine=False
    )

    assert suspicious["risk_score"] == 30
    assert suspicious["risk_level"] == "LOW"
    assert "port_scan" in suspicious["indicators"]

    print("PASS: Eight distinct SYN ports detected")
    print("Risk score:", suspicious["risk_score"])

    print("\n=== TEST 3: ALERT GENERATION ===")

    port_alerts = [
        call for call in mock_alert.call_args_list
        if call.kwargs.get("alert_type") == "port_scan"
    ]

    assert len(port_alerts) == 1
    assert port_alerts[0].kwargs["severity"] == "HIGH"

    print("PASS: Correct HIGH-severity port-scan alert")

    print("\n=== TEST 4: DEDICATED QUERY USED ===")

    assert mock_syn.call_count == 2
    mock_syn.assert_called_with(
        device_id=999999,
        minutes=5,
        limit=5000
    )

    print("PASS: New dedicated SYN query is used")

    print("\n=== TEST 5: DATABASE AND ROUTER SAFETY ===")

    assert mock_update.call_count == 2
    assert not mock_quarantine.called

    print("PASS: Database writes mocked")
    print("PASS: Router quarantine not triggered")

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print("Total test groups: 5")
print("Passed: 5")
print("Failed: 0")
print("OVERALL RESULT: PASS")
