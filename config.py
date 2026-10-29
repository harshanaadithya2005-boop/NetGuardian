import os
import socket
import secrets
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")
DATABASE_PATH = BASE_DIR / "database" / "network_monitor.db"

# Flask Server Config
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

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
RISK_THRESHOLD_HIGH = 70  # Advisory high risk; never triggers quarantine

RISK_THRESHOLD_CRITICAL = 90
RISK_BASELINE = 0
RISK_WEIGHTS.update(suspicious_connection=15, sustained_flood=25)
PORT_SCAN_WINDOW_MINUTES = 5
PORT_SCAN_TARGET_THRESHOLD = 12
DNS_WINDOW_MINUTES = 1
FLOOD_BUCKET_SECONDS = 10
FLOOD_MIN_BUCKETS = 3
FLOOD_PACKETS_PER_SECOND = 100
FLOOD_BYTES_PER_SECOND = 1000000
AUTO_RESPONSE_POLICY = {'enabled': True, 'min_risk': 70, 'min_confidence': 0.8,
                        'min_independent_indicators': 2, 'max_evidence_age_seconds': 120}
# Simulation decisions are supported; physical automatic enforcement has no implementation.
AUTOMATIC_PHYSICAL_ENFORCEMENT = False
VIVA_DATABASE_PATH = BASE_DIR / '.test-work' / 'viva-lab.db'

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

# NetGuardian Protection Modes
# DEMO = Simulated quarantine without firewall changes
# LIVE = Manually authorized Huawei WLAN MAC filtering

# The normal dashboard starts in DEMO every time. Only its authenticated
# runtime switch enables manual LIVE actions; environment variables cannot.
PROTECTION_MODE = "DEMO"
AUTO_QUARANTINE = False
# Locally administered/private MACs cannot establish durable physical identity.
# Populate only after a separately authorized verification; never infer from a name.
# MAC -> {device_id, ip, hostname, ssid_indices}; empty in production.
STABLE_WIFI_IDENTITY_BINDINGS = {}
SEED_DEMO_DEVICES = False
GATEWAY_IP = os.environ.get("NETGUARDIAN_GATEWAY", "")
ROUTER_URL = "http://192.168.8.1"
# These gates stay off until a separately approved spare-device/recovery test.
ROUTER_WRITES_ENABLED = os.environ.get("NETGUARDIAN_ROUTER_WRITES_ENABLED") == "1"
RECOVERY_CONFIRMED = os.environ.get("NETGUARDIAN_RECOVERY_CONFIRMED") == "1"
AUTHORIZED_TEST_MACS = frozenset(x.strip().upper() for x in os.environ.get("NETGUARDIAN_AUTHORIZED_TEST_MACS", "").split(",") if x.strip())
PROTECTED_MANAGEMENT_MACS = frozenset(x.strip().upper() for x in os.environ.get("NETGUARDIAN_PROTECTED_MACS", "").split(",") if x.strip())
PROTECTED_MANAGEMENT_IPS = frozenset(x.strip() for x in os.environ.get("NETGUARDIAN_PROTECTED_IPS", "").split(",") if x.strip())
ADMIN_PASSWORD_HASH = os.environ.get("NETGUARDIAN_ADMIN_PASSWORD_HASH", "")
