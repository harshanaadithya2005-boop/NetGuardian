import os
import socket
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database" / "network_monitor.db"

# Flask Server Config
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
SECRET_KEY = os.environ.get("SECRET_KEY", "netguardian-secret-key-2026")

# Risk Engine Weights (as defined in Project Proposal Section 8.3)
RISK_WEIGHTS = {
    "port_scan": 30,
    "unknown_device": 20,
    "dns_anomaly": 20,
    "traffic_spike": 15,
    "behaviour_drift": 15,
}

# Risk Threshold Bands
RISK_THRESHOLD_MEDIUM = 40
RISK_THRESHOLD_HIGH = 70  # Triggers automatic quarantine

# Detection Thresholds
PORT_SCAN_THRESHOLD = 8             # Distinct ports within window
DNS_MAX_DOMAIN_LENGTH = 45          # Character length for DGA / long domain
DNS_QUERY_RATE_THRESHOLD = 20       # Queries per minute anomaly
TRAFFIC_SPIKE_MULTIPLIER = 4.0      # Multiplier over baseline bandwidth


def get_local_ip():
    """Detect local IP address used for outbound communication."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_default_network():
    """Estimate default subnet based on detected local IP."""
    local_ip = get_local_ip()
    if local_ip.startswith("127."):
        return "192.168.1.0/24"
    parts = local_ip.split(".")
    # Standard class C subnet representation
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# Default target network (can be overridden by environment variable)
TARGET_NETWORK = os.environ.get("TARGET_NETWORK", get_default_network())
