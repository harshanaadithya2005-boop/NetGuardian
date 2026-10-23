import sys
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.models import set_device_status, log_quarantine, create_alert, get_device_by_id
import config


def apply_firewall_isolation(ip_address):
    """
    Apply host/network firewall block rule for quarantined device.
    Attempts native Windows Firewall rule; falls back cleanly to simulated enforcement if non-admin.
    """
    # DEMO mode: simulate isolation without changing Windows Firewall
    if config.PROTECTION_MODE == "DEMO":
        return (
            False,
            f"[DEMO MODE] Simulated quarantine for {ip_address}. "
            "No Windows Firewall rules were created."
        )

    rule_name_in = f"NetGuardian_Block_In_{ip_address}"
    rule_name_out = f"NetGuardian_Block_Out_{ip_address}"
    success = False
    details = ""

    try:
        # Windows netsh command to block all inbound traffic from this host
        cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule",
                  f"name={rule_name_in}", "dir=in", "action=block", f"remoteip={ip_address}"]
        cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={rule_name_out}", "dir=out", "action=block", f"remoteip={ip_address}"]

        subprocess.run(cmd_in, capture_output=True, check=True)
        subprocess.run(cmd_out, capture_output=True, check=True)
        success = True
        details = f"Active Windows Firewall rule created blocking {ip_address}"
    except Exception as e:
        # Non-admin or non-Windows environment fallback to simulated ACL isolation
        details = f"Simulated Cisco ACL / iptables isolation applied (Host: {ip_address}): {e}"

    return success, details


def remove_firewall_isolation(ip_address):
    """Remove firewall isolation rules when a device is released."""

    # DEMO mode: do not modify Windows Firewall
    if config.PROTECTION_MODE == "DEMO":
        return

    rule_name_in = f"NetGuardian_Block_In_{ip_address}"
    rule_name_out = f"NetGuardian_Block_Out_{ip_address}"
    try:
        cmd_in = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"]
        cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"]
        subprocess.run(cmd_in, capture_output=True)
        subprocess.run(cmd_out, capture_output=True)
    except Exception:
        pass


def quarantine_device(device_id, ip_address=None, reason="High Risk Score threshold exceeded (>= 70)", performed_by="NetGuardian Auto-Engine"):
    """
    Isolate device:
    1. Update status to 'quarantined' in database
    2. Enforce firewall / network isolation rule
    3. Log audit event to quarantine_logs
    4. Issue critical alert on dashboard
    """
    if not ip_address:
        dev = get_device_by_id(device_id)
        if dev:
            ip_address = dev["ip_address"]
        else:
            return False, "Device not found"

            # Safety check: Only quarantine devices on our local network
    try:
        local_network = ipaddress.ip_network(
            config.TARGET_NETWORK, strict=False
        )
        device_ip = ipaddress.ip_address(ip_address)

        if device_ip not in local_network:
            return False, (
                f"Quarantine blocked: {ip_address} is outside "
                f"the local network {local_network}."
            )

    except ValueError:
        return False, (
            f"Quarantine blocked: Invalid IP address or network configuration."
        )

    # Protect the network gateway from accidental quarantine.
    # This check applies to both DEMO and enforcement modes.
    if ip_address == "192.168.8.1":
        return False, (
            "Quarantine blocked: the network gateway requires "
            "separate administrator approval."
        )

    print(f"\n[QUARANTINE TRIGGERED] Isolating Device ID {device_id} ({ip_address})")
    print(f"Reason: {reason} | By: {performed_by}")

    # 1. Update DB Status
    set_device_status(device_id, "quarantined")

    # 2. Network Enforcement
    applied, net_msg = apply_firewall_isolation(ip_address)

    # 3. Audit Log
    log_quarantine(device_id, action="quarantined", reason=f"{reason} | {net_msg}", performed_by=performed_by)

    # 4. Quarantine Alert
    if config.PROTECTION_MODE == "DEMO":
        alert_type = "quarantine_simulated"
        alert_description = (
            f"[DEMO MODE] Quarantine simulated for {ip_address}. "
            f"Reason: {reason}. No firewall rules were applied."
        )
    else:
        alert_type = "quarantine_enforced" if applied else "quarantine_failed"
        alert_description = (
            f"Device {ip_address}: {net_msg}. Reason: {reason}."
        )

    create_alert(
        device_id=device_id,
        alert_type=alert_type,
        risk_score=95,
        severity="CRITICAL" if applied else "WARNING",
        description=alert_description
    )

    return True, net_msg


def release_device(device_id, ip_address=None, performed_by="Administrator"):
    """
    Release device from quarantine:
    1. Restore status to 'online' in database
    2. Remove firewall / network isolation rule
    3. Log audit event
    """
    if not ip_address:
        dev = get_device_by_id(device_id)
        if dev:
            ip_address = dev["ip_address"]
        else:
            return False, "Device not found"

    print(f"\n[QUARANTINE RELEASE] Releasing Device ID {device_id} ({ip_address})")

    set_device_status(device_id, "online")
    remove_firewall_isolation(ip_address)
    log_quarantine(device_id, action="released", reason="Manual administrator release", performed_by=performed_by)

    return True, f"Device {ip_address} released from quarantine."


if __name__ == "__main__":
    print("Testing Quarantine Response Module:")
    success, msg = apply_firewall_isolation("192.168.1.99")
    print(f"Result: {msg}")
    remove_firewall_isolation("192.168.1.99")
