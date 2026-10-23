
import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config


def is_unknown_device(device_ip, known_devices):
    """Return True if the IP is missing from the known-device list."""
    return device_ip not in known_devices


def is_trusted_device(device_ip, trusted_devices):
    """Return True if the IP is in the trusted-device list."""
    return device_ip in trusted_devices


def check_unknown_device(device_ip, trusted_devices=None):
    """
    Classify a device as:
      - trusted
      - known_untrusted
      - newly_discovered
      - lookup_error

    Preserve compatibility with explicit trusted-device lists.
    """

    risk_weight = config.RISK_WEIGHTS.get("unknown_device", 20)

    if trusted_devices is not None:
        trusted = is_trusted_device(device_ip, trusted_devices)

        return {
            "detected": not trusted,
            "type": "unknown_device",
            "classification": (
                "trusted" if trusted else "untrusted"
            ),
            "risk_weight": 0 if trusted else risk_weight,
            "severity": "MEDIUM" if not trusted else "LOW",
            "ip_address": device_ip,
            "message": (
                f"Device {device_ip} is trusted."
                if trusted else
                f"Device {device_ip} is not in the trusted list."
            )
        }

    try:
        from database.models import get_device_by_ip

        device = get_device_by_ip(device_ip)

    except Exception as e:
        # A database failure must not automatically
        # become a security detection.
        return {
            "detected": False,
            "type": "unknown_device",
            "classification": "lookup_error",
            "risk_weight": 0,
            "severity": "UNKNOWN",
            "ip_address": device_ip,
            "message": f"Device lookup failed: {e}"
        }

    if device is None:
        return {
            "detected": True,
            "type": "unknown_device",
            "classification": "newly_discovered",
            "risk_weight": risk_weight,
            "severity": "MEDIUM",
            "ip_address": device_ip,
            "message": (
                f"Previously unrecorded device detected: {device_ip}"
            )
        }

    if bool(device.get("trusted", 0)):
        return {
            "detected": False,
            "type": "unknown_device",
            "classification": "trusted",
            "risk_weight": 0,
            "severity": "LOW",
            "ip_address": device_ip,
            "message": f"Trusted device: {device_ip}"
        }

    return {
        "detected": True,
        "type": "unknown_device",
        "classification": "known_untrusted",
        "risk_weight": risk_weight,
        "severity": "MEDIUM",
        "ip_address": device_ip,
        "message": (
            f"Previously discovered device {device_ip} "
            "has not been approved by the administrator."
        )
    }


if __name__ == "__main__":
    print("Testing Unknown Device Detection")

    for ip in ["192.168.8.101", "192.168.8.1"]:
        print(ip, check_unknown_device(ip))
