"""DEMO-only markers. LIVE operations are in response.router_quarantine."""
import ipaddress
from datetime import datetime

import config
from database.db import get_connection


def apply_firewall_isolation(ip_address):
    return False, f"[DEMO MODE] Quarantine simulated for {ip_address}. No router or firewall rules were created."


def remove_firewall_isolation(ip_address):
    return False, "[DEMO MODE] No router or firewall rules were changed."


def _validate_target(device, supplied_ip):
    address = device["ip_address"]
    if supplied_ip is not None and supplied_ip != address:
        return "Quarantine blocked: supplied IP does not match device identity."
    try:
        ip = ipaddress.ip_address(address)
        network = ipaddress.ip_network(config.TARGET_NETWORK, strict=False)
        if ip not in network or ip in (network.network_address, network.broadcast_address):
            return "Quarantine blocked: target is outside the monitored host range."
    except (ValueError, TypeError):
        return "Quarantine blocked: invalid IP or network configuration."
    gateways = {config.GATEWAY_IP, "192.168.8.1", str(next(network.hosts()))}
    if address in gateways or "router" in str(device["device_type"]).lower() or "gateway" in str(device["device_type"]).lower():
        return "Quarantine blocked: gateway devices are protected."
    if address == config.get_local_ip():
        return "Quarantine blocked: the NetGuardian monitoring host is protected."
    return None


def quarantine_device(device_id, ip_address=None, reason="Manual administrator action", performed_by="Administrator"):
    """Atomically mark, audit and alert a manual DEMO quarantine."""
    if config.PROTECTION_MODE != "DEMO":
        return False, "LIVE quarantine requires an authenticated, confirmed router plan."
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if dev is None:
            return False, "Device not found"
        problem = _validate_target(dev, ip_address)
        if problem:
            return False, problem
        if dev["status"] == "quarantined":
            return True, "[DEMO MODE] Device is already marked quarantined; no blocking is active."
        now = datetime.now().isoformat(timespec="seconds")
        _, message = apply_firewall_isolation(dev["ip_address"])
        conn.execute("INSERT OR REPLACE INTO quarantine_state (device_id, previous_status, observed_ip, mode) VALUES (?, ?, ?, 'DEMO')",
                     (device_id, dev["status"], dev["ip_address"]))
        conn.execute("UPDATE devices SET status='quarantined' WHERE id=?", (device_id,))
        conn.execute("INSERT INTO quarantine_logs (device_id,action,reason,performed_by,timestamp) VALUES (?, 'quarantined', ?, ?, ?)",
                     (device_id, f"{reason} | {message}", performed_by, now))
        conn.execute("INSERT INTO alerts (device_id,alert_type,risk_score,severity,description,status,timestamp) VALUES (?, 'quarantine_simulated', ?, 'MEDIUM', ?, 'open', ?)",
                     (device_id, dev["risk_score"], f"{message} Reason: {reason}", now))
        conn.commit()
        return True, message
    finally:
        conn.close()


def release_device(device_id, ip_address=None, performed_by="Administrator"):
    """Reverse a DEMO quarantine without claiming a device is currently online."""
    if config.PROTECTION_MODE != "DEMO":
        return False, "LIVE release requires an authenticated, confirmed router plan."
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        dev = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if dev is None:
            return False, "Device not found"
        if ip_address is not None and ip_address != dev["ip_address"]:
            return False, "Release blocked: supplied IP does not match device identity."
        if dev["status"] != "quarantined":
            return True, "Device is already released."
        state = conn.execute("SELECT * FROM quarantine_state WHERE device_id=?", (device_id,)).fetchone()
        # Legacy quarantine records have no verified recovery metadata. Release
        # their marker, leaving discovery to establish current online presence.
        if state and state["mode"] != "DEMO":
            return False, "Release requires the tested recovery path for the recorded enforcement mode."
        status = state["previous_status"] if state else "offline"
        if status not in {"online", "offline"}:
            status = "offline"
        conn.execute("UPDATE devices SET status=? WHERE id=?", (status, device_id))
        conn.execute("DELETE FROM quarantine_state WHERE device_id=?", (device_id,))
        conn.execute("UPDATE alerts SET status='resolved' WHERE device_id=? AND alert_type='quarantine_simulated' AND status='open'", (device_id,))
        conn.execute("INSERT INTO quarantine_logs (device_id,action,reason,performed_by,timestamp) VALUES (?, 'released', ?, ?, ?)",
                     (device_id, "Manual DEMO release; no network rules changed", performed_by, datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        return True, f"[DEMO MODE] Device {dev['ip_address']} released; no network rules changed."
    finally:
        conn.close()
