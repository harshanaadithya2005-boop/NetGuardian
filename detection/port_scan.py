import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config


def detect_port_scan(ports, threshold=config.PORT_SCAN_THRESHOLD):
    """Check if the number of unique target ports exceeds the port scanning threshold."""
    if not ports:
        return False
    unique_ports = set(ports)
    return len(unique_ports) >= threshold


def check_port_scan(traffic_or_ports, threshold=config.PORT_SCAN_THRESHOLD, source_ip=None):
    """
    Evaluate port scanning from a list of ports or a list of traffic record dicts.
    Returns structured detection details.
    """
    if not traffic_or_ports:
        return {"detected": False, "type": "port_scan", "risk_weight": 0}

    # Extract port numbers whether passed as ints or dicts
    if isinstance(traffic_or_ports[0], dict):
        ports = [r.get("destination_port") for r in traffic_or_ports if r.get("destination_port")]
        if not source_ip and traffic_or_ports:
            source_ip = traffic_or_ports[0].get("source_ip")
    else:
        ports = list(traffic_or_ports)

    unique_ports = sorted(list(set(ports)))
    is_scan = len(unique_ports) >= threshold

    if is_scan:
        return {
            "detected": True,
            "type": "port_scan",
            "risk_weight": config.RISK_WEIGHTS.get("port_scan", 30),
            "severity": "HIGH",
            "source_ip": source_ip,
            "unique_ports_count": len(unique_ports),
            "scanned_ports": unique_ports[:15],
            "message": f"Port scan activity detected: {len(unique_ports)} distinct ports targeted"
        }

    return {
        "detected": False,
        "type": "port_scan",
        "risk_weight": 0,
        "unique_ports_count": len(unique_ports)
    }


if __name__ == "__main__":
    sample_ports = [21, 22, 23, 25, 53, 80, 443, 445, 8080]
    print("Testing Port Scan Detection:")
    print("Sample ports:", sample_ports)
    result = check_port_scan(sample_ports, source_ip="192.168.1.20")
    print("Result:", result)