
from unittest.mock import patch
import analytics.behaviour_shadow as shadow

print("=" * 60)
print("STEP 398: BEHAVIORAL SHADOW INTEGRATION TEST")
print("=" * 60)

baseline = {
    "normal_bandwidth": 0.8912,
    "normal_dns_rate": 39,
    "normal_dest_ips": 26,
    "normal_ports": "80,443,53,22,25,110,993,8080"
}

def metrics(packets, dns, ips, ports, mb):
    return {
        "device_id": 999999,
        "ip_address": "192.168.8.250",
        "window_minutes": 5,
        "packet_count": packets,
        "dns_requests": dns,
        "distinct_ips": ips,
        "distinct_ports": ports,
        "data_mb": mb
    }

passed = 0

def check(name, condition):
    global passed
    assert condition, f"FAIL: {name}"
    passed += 1
    print("PASS:", name)


# Test 1: Normal activity
with patch.object(
    shadow,
    "get_device_window_metrics",
    return_value=metrics(500, 10, 20, 5, 0.5)
):
    result = shadow.evaluate_behaviour_shadow(
        999999, baseline
    )

    check(
        "Normal activity",
        result["status"] == "EVALUATED"
        and not result["detected"]
    )


# Test 2: Traffic spike
with patch.object(
    shadow,
    "get_device_window_metrics",
    return_value=metrics(1000, 10, 20, 5, 4.0)
):
    result = shadow.evaluate_behaviour_shadow(
        999999, baseline
    )

    check(
        "Traffic spike detected",
        result["traffic_spike"] is True
        and result["detected"] is True
    )


# Test 3: Significant behavioral drift
with patch.object(
    shadow,
    "get_device_window_metrics",
    return_value=metrics(2000, 240, 160, 50, 6.0)
):
    result = shadow.evaluate_behaviour_shadow(
        999999, baseline
    )

    check(
        "Behavioral drift detected",
        result["behaviour_drift"] is True
        and result["drift_score"] >= 50
    )


# Test 4: Insufficient captured traffic
with patch.object(
    shadow,
    "get_device_window_metrics",
    return_value=metrics(5, 0, 1, 1, 0.001)
):
    result = shadow.evaluate_behaviour_shadow(
        999999, baseline
    )

    check(
        "Insufficient observation safely skipped",
        result["status"] == "INSUFFICIENT_OBSERVATION"
        and not result["detected"]
    )


# Test 5: Missing device
with patch.object(
    shadow,
    "get_device_window_metrics",
    return_value=None
):
    result = shadow.evaluate_behaviour_shadow(
        999999, baseline
    )

    check(
        "Missing device safely handled",
        result["status"] == "DEVICE_NOT_FOUND"
        and not result["detected"]
    )


# Test 6: Reject incompatible window duration
try:
    shadow.evaluate_behaviour_shadow(
        999999, baseline, minutes=30
    )
except ValueError:
    check("Incompatible measurement window rejected", True)
else:
    check("Incompatible measurement window rejected", False)


print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print("Passed:", passed)
print("Failed:", 6 - passed)
print("Overall:", "PASS" if passed == 6 else "FAIL")
print("No database writes or router operations.")
