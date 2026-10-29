
from detection.behaviour_drift import (
    calculate_behaviour_drift
)

print("=" * 60)
print("STEP 394: LEARNED BASELINE SENSITIVITY TEST")
print("=" * 60)

# Provisional baselines from Step 393.
# These are test data only, NOT database updates.

devices = {
    "Huawei Router": {
        "normal_bandwidth": 0.4638,
        "normal_dns_rate": 1,
        "normal_dest_ips": 1,
        "normal_ports": ",".join(
            str(i) for i in range(110)
        )
    },
    "My Desktop": {
        "normal_bandwidth": 0.8912,
        "normal_dns_rate": 39,
        "normal_dest_ips": 26,
        "normal_ports": ",".join(
            str(i) for i in range(8)
        )
    },
    "Device 30": {
        "normal_bandwidth": 0.0337,
        "normal_dns_rate": 1,
        "normal_dest_ips": 2,
        "normal_ports": ",".join(
            str(i) for i in range(6)
        )
    }
}

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
        f"{name} | Actual: {actual}"
    )


for name, baseline in devices.items():

    print("\n" + "-" * 60)
    print("DEVICE:", name)
    print("-" * 60)

    base_dns = baseline["normal_dns_rate"]
    base_ips = baseline["normal_dest_ips"]
    base_ports = len(
        baseline["normal_ports"].split(",")
    )
    base_mb = baseline["normal_bandwidth"]

    # Scenario 1: Activity at the learned baseline.
    normal = {
        "dns_requests": base_dns,
        "distinct_ips": base_ips,
        "distinct_ports": base_ports,
        "data_mb": base_mb
    }

    score, breakdown = calculate_behaviour_drift(
        normal, baseline
    )

    check(
        f"{name}: Normal behavior",
        score < 50 and not breakdown[
            "bandwidth_mb"
        ]["traffic_spike"],
        True
    )

    # Scenario 2: Bandwidth reaches 4x baseline.
    spike = dict(normal)
    spike["data_mb"] = base_mb * 4

    score, breakdown = calculate_behaviour_drift(
        spike, baseline
    )

    check(
        f"{name}: Traffic spike",
        breakdown["bandwidth_mb"]["traffic_spike"],
        True
    )

    # Scenario 3: All observed metrics increase 6x.
    abnormal = {
        "dns_requests": base_dns * 6,
        "distinct_ips": base_ips * 6,
        "distinct_ports": base_ports * 6,
        "data_mb": base_mb * 6
    }

    score, breakdown = calculate_behaviour_drift(
        abnormal, baseline
    )

    check(
        f"{name}: Major behavioral drift",
        score >= 50,
        True
    )

    print("Major drift score:", score)

    # Scenario 4: Small increases should not
    # exceed the behavioral-drift threshold.
    moderate = {
        "dns_requests": base_dns * 2,
        "distinct_ips": base_ips * 2,
        "distinct_ports": base_ports * 2,
        "data_mb": base_mb * 2
    }

    score, breakdown = calculate_behaviour_drift(
        moderate, baseline
    )

    check(
        f"{name}: Moderate increase",
        score < 50 and not breakdown[
            "bandwidth_mb"
        ]["traffic_spike"],
        True
    )


print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Total tests:", passed + failed)
print("Passed:", passed)
print("Failed:", failed)
print(
    "Overall:",
    "PASS" if failed == 0 else "FAIL"
)

print("\nNo SQLite database modifications.")
print("No router operations.")
print("No network attacks generated.")

if failed:
    raise SystemExit(1)
