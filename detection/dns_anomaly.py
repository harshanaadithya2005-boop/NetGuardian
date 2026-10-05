import sys
import math
from pathlib import Path
from collections import Counter

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config


def is_unusually_long_domain(domain, max_length=config.DNS_MAX_DOMAIN_LENGTH):
    """Check if a domain name exceeds the suspicious length threshold (common in DNS tunneling/DGA)."""
    if not domain:
        return False
    return len(domain) > max_length


def detect_repeated_failures(failed_queries, threshold=5):
    """Check if number of failed DNS queries exceeds normal threshold."""
    return failed_queries >= threshold


def calculate_entropy(text):
    """Shannon entropy to detect randomly generated DGA domains or encoded tunneling payloads."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def check_dns_anomaly(dns_queries_or_traffic, failed_queries=0, source_ip=None, max_length=config.DNS_MAX_DOMAIN_LENGTH):
    """
    Analyze DNS queries for anomalies:
    1. Unusually long domain strings (DNS exfiltration/tunneling)
    2. High Shannon entropy (DGA / C2 domains)
    3. Excessive query volume or repeated failures
    """
    if not dns_queries_or_traffic and failed_queries == 0:
        return {"detected": False, "type": "dns_anomaly", "risk_weight": 0}

    # Extract domains whether passed as list of strings or traffic record dicts
    queries = []
    if dns_queries_or_traffic:
        if isinstance(dns_queries_or_traffic[0], dict):
            queries = [r.get("dns_query") for r in dns_queries_or_traffic if r.get("dns_query")]
            if not source_ip and dns_queries_or_traffic:
                source_ip = dns_queries_or_traffic[0].get("source_ip")
        else:
            queries = [str(q) for q in dns_queries_or_traffic if q]

    anomalies = []

    for domain in queries:
        clean_domain = domain.strip().lower()
        # Check domain length
        if is_unusually_long_domain(clean_domain, max_length):
            anomalies.append(f"Excessive domain length ({len(clean_domain)} chars): {clean_domain[:40]}...")
            continue

        # Check entropy (e.g. above 3.8 on subdomains is typical for hex/base32 tunneling)
        subdomains = clean_domain.split(".")[:-2]
        if subdomains:
            main_sub = subdomains[0]
            if len(main_sub) > 15 and calculate_entropy(main_sub) > 3.6:
                anomalies.append(f"High entropy DGA/Tunneling pattern: {clean_domain}")

    # Check query count burst
    if len(queries) >= config.DNS_QUERY_RATE_THRESHOLD:
        anomalies.append(f"Abnormal DNS query burst: {len(queries)} queries in window")

    # Check repeated NXDOMAIN / failure counter
    if detect_repeated_failures(failed_queries):
        anomalies.append(f"High DNS resolution failure count ({failed_queries} NXDOMAINs)")

    if anomalies:
        return {
            "detected": True,
            "type": "dns_anomaly",
            "risk_weight": config.RISK_WEIGHTS.get("dns_anomaly", 20),
            "severity": "MEDIUM",
            "source_ip": source_ip,
            "anomaly_count": len(anomalies),
            "reasons": anomalies,
            "message": f"DNS Anomaly detected: {'; '.join(anomalies[:2])}"
        }

    return {
        "detected": False,
        "type": "dns_anomaly",
        "risk_weight": 0,
        "query_count": len(queries)
    }


if __name__ == "__main__":
    test_domain = "this-is-a-very-long-example-domain-name-for-testing-dns-tunneling-anomaly.example.com"
    test_dga = "a8f9c1b27e8a93bf81d942e5.attacker-c2.net"

    print("Testing DNS Anomaly Detection:")
    print("Testing normal domain : google.com ->", check_dns_anomaly(["google.com"]))
    print("Testing long domain   :", check_dns_anomaly([test_domain]))
    print("Testing DGA domain    :", check_dns_anomaly([test_dga]))