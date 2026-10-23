import ipaddress
import config
from datetime import datetime
from database.db import get_connection

def is_local_device_ip(ip_address):
    """Return True only for valid IP addresses in the configured network."""
    try:
        network = ipaddress.ip_network(
            config.TARGET_NETWORK,
            strict=False
        )
        return ipaddress.ip_address(ip_address) in network
    except (ValueError, TypeError):
        return False

def add_or_update_device(
    ip_address,
    mac_address,
    hostname=None,
    device_name=None,
    device_type=None,
    timestamp=None
):
    """Add a new device or update an existing device."""
    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    connection = get_connection()
    cursor = connection.cursor()

    existing_device = None

    # Identify by MAC address if valid, otherwise by IP address
    if mac_address and mac_address not in ["UNKNOWN", "AUTO-CAPTURED", "LOCAL-HOST"]:
        cursor.execute(
            "SELECT id, status, device_name, device_type FROM devices WHERE mac_address = ?",
            (mac_address,)
        )
        existing_device = cursor.fetchone()

    if not existing_device:
        cursor.execute(
            "SELECT id, status, device_name, device_type FROM devices WHERE ip_address = ?",
            (ip_address,)
        )
        existing_device = cursor.fetchone()

    if existing_device:
        device_id = existing_device["id"]
        # Maintain existing status if quarantined, otherwise set online
        current_status = existing_device["status"]
        new_status = "quarantined" if current_status == "quarantined" else "online"

        cursor.execute("""
            UPDATE devices
            SET ip_address = ?,
                mac_address = COALESCE(?, mac_address),
                hostname = COALESCE(?, hostname),
                device_type = COALESCE(?, device_type),
                last_seen = ?,
                status = ?
            WHERE id = ?
        """, (
            ip_address,
            mac_address,
            hostname,
            device_type,
            timestamp,
            new_status,
            device_id
        ))
    else:
        # Infer default device name / type if not provided
        inferred_name = device_name or (hostname if hostname and hostname != "Unknown" else f"Device-{ip_address.split('.')[-1]}")
        inferred_type = device_type or infer_device_type(inferred_name, mac_address)

        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                hostname,
                device_name,
                device_type,
                first_seen,
                last_seen,
                status,
                trusted,
                risk_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'online', 0, 20)
        """, (
            ip_address,
            mac_address,
            hostname,
            inferred_name,
            inferred_type,
            timestamp,
            timestamp
        ))
        device_id = cursor.lastrowid

        # Also initialize a default baseline profile for this new device
        init_default_profile(device_id, inferred_type, cursor)

    connection.commit()
    connection.close()
    return device_id


def mark_missing_devices_offline(discovered_ips):
    """Mark devices not found in the latest scan as offline (excluding quarantined ones)."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT ip_address, status FROM devices")
    stored_devices = cursor.fetchall()

    for device in stored_devices:
        ip_address = device["ip_address"]
        status = device["status"]

        if ip_address not in discovered_ips and status != "quarantined":
            cursor.execute("""
                UPDATE devices
                SET status = 'offline'
                WHERE ip_address = ?
            """, (ip_address,))

    connection.commit()
    connection.close()


def infer_device_type(name_or_host, mac):
    """Heuristic identification of device type based on hostname/MAC."""
    target = (name_or_host or "").lower()
    if any(k in target for k in ["printer", "hp-print", "epson", "canon"]):
        return "Printer"
    elif any(k in target for k in ["cam", "cctv", "dvr", "nvr"]):
        return "CCTV / Camera"
    elif any(k in target for k in ["iphone", "android", "galaxy", "phone", "mobile"]):
        return "Mobile"
    elif any(k in target for k in ["laptop", "desktop", "pc", "macbook", "workstation"]):
        return "Workstation"
    elif any(k in target for k in ["router", "gateway", "switch", "ap"]):
        return "Gateway/Router"
    return "IoT Device"


def init_default_profile(device_id, device_type, cursor):
    """Set realistic baseline behavior profiles according to device type (Proposal Section 8.1)."""
    now = datetime.now().isoformat(timespec="seconds")
    if device_type == "Printer":
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id, normal_bandwidth, normal_protocols, normal_ports,
                normal_dns_rate, normal_dest_ips, active_hours, updated_at
            ) VALUES (?, 5.0, 'TCP', '9100,515,631', 10, 3, '08:00-18:00', ?)
        """, (device_id, now))
    elif device_type == "CCTV / Camera":
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id, normal_bandwidth, normal_protocols, normal_ports,
                normal_dns_rate, normal_dest_ips, active_hours, updated_at
            ) VALUES (?, 100.0, 'TCP,UDP', '554,80,443', 5, 2, '00:00-23:59', ?)
        """, (device_id, now))
    else:  # Workstation / Laptop / General
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id, normal_bandwidth, normal_protocols, normal_ports,
                normal_dns_rate, normal_dest_ips, active_hours, updated_at
            ) VALUES (?, 50.0, 'TCP,UDP', '80,443,53', 40, 12, '08:00-20:00', ?)
        """, (device_id, now))


def get_all_devices():
    """Retrieve all devices ordered by risk score descending."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY risk_score DESC, id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_device_by_id(device_id):
    """Retrieve a single device by its primary key ID."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_device_by_ip(ip_address):
    """Retrieve a single device by its IP address."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE ip_address = ?", (ip_address,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_device_risk(device_id, risk_score):
    """Update risk score for a device."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET risk_score = ? WHERE id = ?", (risk_score, device_id))
    conn.commit()
    conn.close()


def set_device_trusted(device_id, trusted):
    """Toggle or update device trusted status."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET trusted = ? WHERE id = ?", (1 if trusted else 0, device_id))
    conn.commit()
    conn.close()


def set_device_status(device_id, status):
    """Set status ('online', 'offline', 'quarantined')."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))
    conn.commit()
    conn.close()


def log_traffic(
    device_id,
    source_ip,
    destination_ip,
    protocol="TCP",
    destination_port=None,
    packet_size=0,
    dns_query=None,
    timestamp=None
):
    """Record a traffic flow packet/session."""
    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO traffic (
            device_id, source_ip, destination_ip, protocol,
            destination_port, packet_size, dns_query, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        device_id,
        source_ip,
        destination_ip,
        protocol,
        destination_port,
        packet_size,
        dns_query,
        timestamp
    ))
    conn.commit()
    conn.close()


def get_recent_traffic(limit=50, device_id=None):
    """Get the most recent traffic records."""
    conn = get_connection()
    cur = conn.cursor()
    if device_id:
        cur.execute("""
            SELECT t.*, d.hostname, d.device_name
            FROM traffic t
            JOIN devices d ON t.device_id = d.id
            WHERE t.device_id = ?
            ORDER BY t.id DESC LIMIT ?
        """, (device_id, limit))
    else:
        cur.execute("""
            SELECT t.*, d.hostname, d.device_name
            FROM traffic t
            JOIN devices d ON t.device_id = d.id
            ORDER BY t.id DESC LIMIT ?
        """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def create_alert(device_id, alert_type, risk_score, severity, description, timestamp=None):
    """Record a security alert."""
    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id FROM alerts
        WHERE device_id = ? AND alert_type = ? AND status = 'open'
    """, (device_id, alert_type))
    existing = cur.fetchone()

    if not existing:
        cur.execute("""
            INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, timestamp)
            VALUES (?, ?, ?, ?, ?, 'open', ?)
        """, (device_id, alert_type, risk_score, severity, description, timestamp))
        alert_id = cur.lastrowid
    else:
        alert_id = existing["id"]

    conn.commit()
    conn.close()
    return alert_id


def get_recent_alerts(limit=50, status=None):
    """Get recent alerts, optionally filtered by status ('open', 'resolved')."""
    conn = get_connection()
    cur = conn.cursor()
    if status:
        cur.execute("""
            SELECT a.*, d.ip_address, d.hostname, d.device_name
            FROM alerts a
            JOIN devices d ON a.device_id = d.id
            WHERE a.status = ?
            ORDER BY a.id DESC LIMIT ?
        """, (status, limit))
    else:
        cur.execute("""
            SELECT a.*, d.ip_address, d.hostname, d.device_name
            FROM alerts a
            JOIN devices d ON a.device_id = d.id
            ORDER BY a.id DESC LIMIT ?
        """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


def get_device_profile(device_id):
    """Fetch baseline behaviour profile for a device."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM behaviour_profiles WHERE device_id = ?", (device_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def log_quarantine(device_id, action, reason, performed_by="NetGuardian Auto-Engine"):
    """Audit log for device quarantine and release actions."""
    now = datetime.now().isoformat(timespec="seconds")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO quarantine_logs (device_id, action, reason, performed_by, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (device_id, action, reason, performed_by, now))
    conn.commit()
    conn.close()


def get_quarantine_logs(limit=20):
    """Retrieve audit history of quarantine actions."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT q.*, d.ip_address, d.hostname, d.device_name
        FROM quarantine_logs q
        JOIN devices d ON q.device_id = d.id
        ORDER BY q.id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_network_stats():
    """Aggregate statistics for the configured local network."""
    conn = get_connection()
    cur = conn.cursor()


    # Retrieve device records without deleting historical data
    cur.execute("SELECT ip_address, status, risk_score FROM devices")
    all_devices = cur.fetchall()

    local_devices = [
        device for device in all_devices
        if is_local_device_ip(device["ip_address"])
    ]

    total_devices = len(local_devices)

    online_devices = sum(
        1 for device in local_devices
        if device["status"] == "online"
    )

    quarantined_devices = sum(
        1 for device in local_devices
        if device["status"] == "quarantined"
    )

    high_risk_devices = sum(
        1 for device in local_devices
        if device["risk_score"] >= 70
    )

    # Preserve the existing global alert count for now
    cur.execute("""
        SELECT a.status, d.ip_address
        FROM alerts a
        JOIN devices d ON a.device_id = d.id
        WHERE a.status = 'open'
    """)

    open_alerts = sum(
        1 for alert in cur.fetchall()
        if is_local_device_ip(alert["ip_address"])
    )

    conn.close()

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "quarantined_devices": quarantined_devices,
        "open_alerts": open_alerts,
        "high_risk_devices": high_risk_devices
    }