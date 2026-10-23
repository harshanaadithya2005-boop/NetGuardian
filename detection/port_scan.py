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



def check_port_scan(
    traffic_or_ports,
    threshold=config.PORT_SCAN_THRESHOLD,
    source_ip=None
):
    """
    Detect potential TCP port scans by counting distinct
    destination ports receiving initial SYN packets.

    SYN-ACK responses, established connections, and non-TCP
    traffic are excluded.
    """

    if not traffic_or_ports:
        return {
            "detected": False,
            "type": "port_scan",
            "risk_weight": 0,
            "unique_ports_count": 0
        }

    if isinstance(traffic_or_ports[0], dict):
        records = traffic_or_ports

        ports = []

        for record in records:
            if source_ip and record.get("source_ip") != source_ip:
                continue

            if str(record.get("protocol", "")).upper() != "TCP":
                continue

            # Only count initial TCP SYN packets.
            # Excludes SYN-ACK and other TCP packets.
            if str(record.get("tcp_flags", "")).upper() != "S":
                continue

            destination_port = record.get("destination_port")

            try:
                port = int(destination_port)
            except (TypeError, ValueError):
                continue

            if 1 <= port <= 65535:
                ports.append(port)

    else:
        # Preserve compatibility with existing tests that pass
        # a simple list of destination ports.
        ports = list(traffic_or_ports)

    unique_ports = sorted({
        int(port)
        for port in ports
        if str(port).isdigit() and 1 <= int(port) <= 65535
    })

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
            "message": (
                f"Potential TCP port scan detected: "
                f"SYN attempts to {len(unique_ports)} "
                f"distinct destination ports"
            )
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