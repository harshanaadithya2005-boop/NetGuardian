import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config


def is_unknown_device(device_ip, known_devices):
    """Check if device IP is not in known devices list."""
    return device_ip not in known_devices


def is_trusted_device(device_ip, trusted_devices):
    """Check if device IP is in trusted devices list."""
    return device_ip in trusted_devices


def check_unknown_device(device_ip, trusted_devices=None):
    """
    Evaluate if a device is unknown / untrusted.
    If trusted_devices is None, checks against NetGuardian database trusted status.
    """
    if trusted_devices is not None:
        if not is_trusted_device(device_ip, trusted_devices):
            return {
                "detected": True,
                "type": "unknown_device",
                "risk_weight": config.RISK_WEIGHTS.get("unknown_device", 20),
                "severity": "MEDIUM",
                "ip_address": device_ip,
                "message": f"Unrecognized / untrusted device detected: {device_ip}"
            }
        return {"detected": False, "type": "unknown_device", "risk_weight": 0}

    # Database integration
    try:
        from database.models import get_device_by_ip
        device = get_device_by_ip(device_ip)
        if device and device.get("trusted") == 1:
            return {"detected": False, "type": "unknown_device", "risk_weight": 0}
        
        return {
            "detected": True,
            "type": "unknown_device",
            "risk_weight": config.RISK_WEIGHTS.get("unknown_device", 20),
            "severity": "MEDIUM",
            "ip_address": device_ip,
            "message": f"New or untrusted device active on network: {device_ip}"
        }
    except Exception as e:
        return {
            "detected": True,
            "type": "unknown_device",
            "risk_weight": config.RISK_WEIGHTS.get("unknown_device", 20),
            "severity": "MEDIUM",
            "ip_address": device_ip,
            "message": f"Unknown device status ({e}): {device_ip}"
        }


if __name__ == "__main__":
    test_known = ["192.168.1.1", "192.168.1.5", "192.168.1.8"]
    test_dev = "192.168.1.20"

    print("Testing Unknown Device Detection:")
    print(f"Known devices : {test_known}")
    print(f"Testing IP    : {test_dev}")
    result = check_unknown_device(test_dev, test_known)
    print("Result:", result)