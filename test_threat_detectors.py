
import config

from detection.port_scan import check_port_scan
from detection.dns_anomaly import check_dns_anomaly
from detection.behaviour_drift import (
    calculate_behaviour_drift,
    detect_traffic_spike,
)

print("=" * 60)
print("NETGUARDIAN — THREAT DETECTOR TESTS")
print("=" * 60)

results = []


def check(name, actual, expected):
    passed = actual == expected
    results.append((name, passed))

    print(
        f"{'PASS' if passed else 'FAIL'} | "
        f"{name} | "
        f"Expected: {expected} | Actual: {actual}"
    )


# ========================================================
# TEST 1: PORT SCAN DETECTION
# ========================================================

print("\n=== PORT SCAN TESTS ===")

source = "192.168.8.250"
threshold = config.PORT_SCAN_THRESHOLD


def tcp_record(port, flags="S"):
    return {
        "source_ip": source,
        "destination_ip": "192.168.8.254",
        "protocol": "TCP",
        "destination_port": port,
        "tcp_flags": flags,
    }


normal_tcp = [
    tcp_record(port)
    for port in range(1000, 1000 + threshold - 1)
]

suspicious_tcp = [
    tcp_record(port)
    for port in range(1000, 1000 + threshold)
]

syn_ack_tcp = [
    tcp_record(port, "SA")
    for port in range(1000, 1000 + threshold)
]

check(
    "Normal TCP activity",
    check_port_scan(normal_tcp, source_ip=source)["detected"],
    False
)

check(
    "Potential port scan",
    check_port_scan(suspicious_tcp, source_ip=source)["detected"],
    True
)

check(
    "SYN-ACK responses excluded",
    check_port_scan(syn_ack_tcp, source_ip=source)["detected"],
    False
)


# ========================================================
# TEST 2: DNS ANOMALY DETECTION
# ========================================================

print("\n=== DNS ANOMALY TESTS ===")

check(
    "Normal domain",
    check_dns_anomaly(["example.com"])["detected"],
    False
)

long_domain = (
    "a" * (config.DNS_MAX_DOMAIN_LENGTH + 1)
    + ".example.com"
)

check(
    "Unusually long domain",
    check_dns_anomaly([long_domain])["detected"],
    True
)

check(
    "Repeated DNS failures",
    check_dns_anomaly(
        [],
        failed_queries=5
    )["detected"],
    True
)


# ========================================================
# TEST 3: TRAFFIC SPIKE DETECTION
# ========================================================

print("\n=== TRAFFIC SPIKE TESTS ===")

baseline_mb = 50.0
multiplier = config.TRAFFIC_SPIKE_MULTIPLIER

check(
    "Normal bandwidth",
    detect_traffic_spike(
        baseline_mb,
        baseline_mb
    ),
    False
)

check(
    "Four-times threshold spike",
    detect_traffic_spike(
        baseline_mb,
        baseline_mb * multiplier
    ),
    True
)


# ========================================================
# TEST 4: BEHAVIORAL DRIFT
# ========================================================

print("\n=== BEHAVIORAL DRIFT TESTS ===")

baseline = {
    "normal_dns_rate": 40,
    "normal_dest_ips": 12,
    "normal_ports": "80,443,53",
    "normal_bandwidth": 50.0,
}

normal_metrics = {
    "dns_requests": 40,
    "distinct_ips": 12,
    "distinct_ports": 3,
    "data_mb": 50.0,
}

abnormal_metrics = {
    "dns_requests": 240,
    "distinct_ips": 72,
    "distinct_ports": 18,
    "data_mb": 300.0,
}

normal_drift, _ = calculate_behaviour_drift(
    normal_metrics,
    baseline
)

abnormal_drift, _ = calculate_behaviour_drift(
    abnormal_metrics,
    baseline
)

check(
    "Normal behavior drift score",
    normal_drift,
    0.0
)

check(
    "Significant behavioral drift",
    abnormal_drift >= 50.0,
    True
)


# ========================================================
# FINAL RESULTS
# ========================================================

passed = sum(ok for _, ok in results)
failed = len(results) - passed

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Total tests:", len(results))
print("Passed:", passed)
print("Failed:", failed)
print("Normal drift score:", normal_drift)
print("Abnormal drift score:", abnormal_drift)

print(
    "Overall result:",
    "PASS" if failed == 0 else "FAIL"
)

if failed:
    raise SystemExit(1)

print("\nNo router requests or SQLite writes performed.")
