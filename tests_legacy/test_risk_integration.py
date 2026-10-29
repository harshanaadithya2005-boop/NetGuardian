
from contextlib import ExitStack
from unittest.mock import patch

import risk.risk_engine as risk

print("=" * 60)
print("STEP 369: NETGUARDIAN RISK INTEGRATION TESTS")
print("=" * 60)

passed = 0
failed = 0


def check(name, actual, expected):
    global passed, failed

    success = actual == expected

    if success:
        passed += 1
    else:
        failed += 1

    print(
        f"{'PASS' if success else 'FAIL'} | "
        f"{name} | Expected: {expected} | Actual: {actual}"
    )


# --------------------------------------------------------
# TEST 1: RISK SCORE CALCULATIONS
# --------------------------------------------------------

print("\n=== RISK SCORING ===")

check(
    "No detections",
    risk.calculate_risk([]),
    0
)

check(
    "Unknown device",
    risk.calculate_risk(["unknown_device"]),
    20
)

check(
    "Port scan + DNS anomaly",
    risk.calculate_risk(["port_scan", "dns_anomaly"]),
    50
)

check(
    "All five detections",
    risk.calculate_risk([
        "unknown_device",
        "port_scan",
        "dns_anomaly",
        "traffic_spike",
        "behaviour_drift"
    ]),
    100
)

check(
    "Score capped at 100",
    risk.calculate_risk(["port_scan"] * 10),
    30
)


# --------------------------------------------------------
# TEST 2: RISK LEVEL CLASSIFICATION
# --------------------------------------------------------

print("\n=== RISK LEVELS ===")

for score, expected in [
    (0, "LOW"),
    (39, "LOW"),
    (40, "MEDIUM"),
    (69, "MEDIUM"),
    (70, "HIGH"),
    (100, "HIGH"),
]:
    check(
        f"Risk level at {score}",
        risk.get_risk_level(score),
        expected
    )


# --------------------------------------------------------
# TEST 3: DETECTION-TO-RISK INTEGRATION
# --------------------------------------------------------

print("\n=== DETECTION PIPELINE ===")

# Synthetic device. This device is NOT inserted into SQLite.
device = {
    "id": 999999,
    "ip_address": "192.168.8.250",
    "mac_address": "02:AA:BB:CC:DD:EE",
    "trusted": 0,
    "status": "online",
    "risk_score": 0
}

# Force all five detectors to report a detection.
# These mocks prevent live database and router operations.
with ExitStack() as stack:
    mock_traffic = stack.enter_context(
        patch.object(
            risk,
            "get_recent_traffic",
            return_value=[]
        )
    )

    stack.enter_context(
        patch.object(
            risk,
            "check_unknown_device",
            return_value={
                "detected": True,
                "classification": "known_untrusted",
                "type": "unknown_device"
            }
        )
    )

    stack.enter_context(
        patch.object(
            risk,
            "check_port_scan",
            return_value={
                "detected": True,
                "unique_ports_count": 12
            }
        )
    )

    stack.enter_context(
        patch.object(
            risk,
            "check_dns_anomaly",
            return_value={
                "detected": True,
                "message": "Synthetic DNS anomaly"
            }
        )
    )

    stack.enter_context(
        patch.object(
            risk,
            "check_behaviour_drift_for_device",
            return_value={
                "detected": True,
                "traffic_spike": True,
                "drift_score": 80.0
            }
        )
    )

    mock_alert = stack.enter_context(
        patch.object(risk, "create_alert")
    )

    mock_update = stack.enter_context(
        patch.object(risk, "update_device_risk")
    )

    mock_quarantine = stack.enter_context(
        patch.object(risk, "quarantine_device")
    )

    result = risk.evaluate_device_risk(
        device,
        auto_quarantine=False
    )

    check("Integrated risk score", result["risk_score"], 100)
    check("Integrated risk level", result["risk_level"], "HIGH")
    check("Five active indicators", len(result["indicators"]), 5)

    check(
        "Risk saved through database function",
        mock_update.call_args.args,
        (999999, 100)
    )

    alert_types = [
        call.kwargs.get("alert_type")
        for call in mock_alert.call_args_list
    ]

    check(
        "Port-scan alert generated",
        "port_scan" in alert_types,
        True
    )

    check(
        "DNS-anomaly alert generated",
        "dns_anomaly" in alert_types,
        True
    )

    check(
        "Traffic-spike alert generated",
        "traffic_spike" in alert_types,
        True
    )

    check(
        "Behavioral-drift alert generated",
        "behaviour_drift" in alert_types,
        True
    )

    check(
        "Known-device discovery alert suppressed",
        "unknown_device" in alert_types,
        False
    )

    check(
        "Automatic quarantine NOT triggered",
        mock_quarantine.called,
        False
    )


# --------------------------------------------------------
# FINAL RESULTS
# --------------------------------------------------------

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Passed:", passed)
print("Failed:", failed)
print("Overall:", "PASS" if failed == 0 else "FAIL")
print("SQLite writes: Mocked")
print("Router operations: None")

if failed:
    raise SystemExit(1)
