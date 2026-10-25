
import sqlite3
import ipaddress
import config

from datetime import datetime, timedelta
from database.db import get_connection


PLACEHOLDER_MACS = {
    None,
    "",
    "UNKNOWN",
    "AUTO-CAPTURED",
    "LOCAL-HOST",
    "00:00:00:00:00:00",
    "FF:FF:FF:FF:FF:FF"
}


def is_placeholder_mac(mac_address):
    """Check whether a MAC address is missing or temporary."""
    return (
        mac_address is None
        or str(mac_address).strip().upper() in PLACEHOLDER_MACS
    )


def is_local_device_ip(ip_address):
    """Return True if the IP belongs to the configured network."""
    try:
        network = ipaddress.ip_network(
            config.TARGET_NETWORK,
            strict=False
        )
        return ipaddress.ip_address(ip_address) in network
    except (ValueError, TypeError):
        return False


# ==========================================================
# DEVICE DISCOVERY AND IDENTITY MANAGEMENT
# ==========================================================


def add_or_update_device(
    ip_address,
    mac_address,
    hostname=None,
    device_name=None,
    device_type=None,
    timestamp=None
):
    """
    Save a discovered device using its verified MAC identity.

    Safely handle DHCP IP reassignment while preserving device IDs,
    trust settings, quarantine status and historical records.
    """

    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    if not ip_address:
        raise ValueError("An IP address is required for discovery.")

    normalized_mac = (
        str(mac_address).strip().upper()
        if not is_placeholder_mac(mac_address)
        else None
    )
    valid_mac = normalized_mac is not None

    connection = get_connection()

    try:
        # Keep lookup and reassignment in one write transaction.
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.cursor()

        existing_device = None

        # Find a previously registered verified MAC identity.
        if valid_mac:
            existing_device = cursor.execute("""
                SELECT id, status, mac_address
                FROM devices
                WHERE UPPER(mac_address) = ?
                ORDER BY id
                LIMIT 1
            """, (normalized_mac,)).fetchone()

        # Find the record currently occupying this IP address.
        ip_owner = cursor.execute("""
            SELECT id, status, mac_address
            FROM devices
            WHERE ip_address = ?
        """, (ip_address,)).fetchone()

        # Handle IP ownership conflicts.
        if ip_owner is not None:
            owner_mac = ip_owner["mac_address"]
            owner_has_verified_mac = (
                not is_placeholder_mac(owner_mac)
            )

            # A placeholder observation must never take ownership
            # away from a verified device identity.
            if not valid_mac and owner_has_verified_mac:
                print(
                    "[DeviceDiscovery] Unverified MAC observation "
                    f"ignored for {ip_address}. "
                    "Verified device identity preserved."
                )
                connection.rollback()
                return None

            # Two different verified MACs observed at one IP.
            if (
                valid_mac
                and owner_has_verified_mac
                and str(owner_mac).strip().upper() != normalized_mac
            ):
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS
                    device_identity_conflicts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        existing_device_id INTEGER,
                        existing_mac TEXT NOT NULL,
                        observed_mac TEXT NOT NULL,
                        detected_at TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        FOREIGN KEY (existing_device_id)
                            REFERENCES devices(id)
                    )
                """)

                previous = cursor.execute("""
                    SELECT id
                    FROM device_identity_conflicts
                    WHERE ip_address = ?
                      AND existing_mac = ?
                      AND observed_mac = ?
                      AND status = 'open'
                    LIMIT 1
                """, (
                    ip_address,
                    owner_mac,
                    normalized_mac
                )).fetchone()

                if previous is None:
                    cursor.execute("""
                        INSERT INTO device_identity_conflicts (
                            ip_address,
                            existing_device_id,
                            existing_mac,
                            observed_mac,
                            detected_at,
                            status
                        )
                        VALUES (?, ?, ?, ?, ?, 'open')
                    """, (
                        ip_address,
                        ip_owner["id"],
                        owner_mac,
                        normalized_mac,
                        timestamp
                    ))

                connection.commit()

                print(
                    "[DeviceDiscovery] Verified MAC conflict: "
                    f"IP {ip_address}, "
                    f"existing MAC {owner_mac}, "
                    f"observed MAC {normalized_mac}. "
                    "No device identities changed."
                )
                return None

            # A verified observation may replace stale IP ownership
            # belonging to a placeholder-MAC record.
            if (
                valid_mac
                and not owner_has_verified_mac
            ):
                # If the verified MAC already owns this record,
                # there is nothing to release.
                same_identity = (
                    existing_device is not None
                    and existing_device["id"] == ip_owner["id"]
                )

                if not same_identity:
                    # Preserve the historical row and foreign keys.
                    # NULL releases the unique IP assignment.
                    cursor.execute("""
                        UPDATE devices
                        SET
                            ip_address = NULL,
                            status = CASE
                                WHEN status = 'quarantined'
                                THEN status
                                ELSE 'offline'
                            END
                        WHERE id = ?
                    """, (ip_owner["id"],))

                    print(
                        "[DeviceDiscovery] Released stale IP "
                        f"{ip_address} from placeholder device "
                        f"{ip_owner['id']}."
                    )

                    ip_owner = None

        # Use the verified MAC record if one exists.
        if existing_device is None and ip_owner is not None:
            existing_device = ip_owner

        if existing_device is not None:
            device_id = existing_device["id"]

            new_status = (
                "quarantined"
                if existing_device["status"] == "quarantined"
                else "online"
            )

            cursor.execute("""
                UPDATE devices
                SET
                    ip_address = ?,
                    mac_address = COALESCE(?, mac_address),
                    hostname = COALESCE(?, hostname),
                    device_type = COALESCE(?, device_type),
                    last_seen = ?,
                    status = ?,
                    missed_scans = 0
                WHERE id = ?
            """, (
                ip_address,
                normalized_mac,
                hostname,
                device_type,
                timestamp,
                new_status,
                device_id
            ))

        else:
            inferred_name = (
                device_name
                or (
                    hostname
                    if hostname
                    and hostname.strip().lower() != "unknown"
                    else f"Device-{ip_address.split('.')[-1]}"
                )
            )

            inferred_type = (
                device_type
                or infer_device_type(
                    inferred_name,
                    normalized_mac
                )
            )

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
                    risk_score,
                    missed_scans
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'online', 0, 20, 0)
            """, (
                ip_address,
                normalized_mac,
                hostname,
                inferred_name,
                inferred_type,
                timestamp,
                timestamp
            ))

            device_id = cursor.lastrowid

            init_default_profile(
                device_id,
                inferred_type,
                cursor
            )


            # Create one first-discovery security alert.
            #
            # Only newly inserted devices with verified MAC
            # identities on our monitored local network qualify.
            #
            # This runs inside the existing transaction so the
            # device registration and alert are committed together.

            if valid_mac and is_local_device_ip(ip_address):
                cursor.execute("""
                    INSERT INTO alerts (
                        device_id,
                        alert_type,
                        risk_score,
                        severity,
                        description,
                        status,
                        timestamp
                    )
                    VALUES (?, ?, ?, ?, ?, 'open', ?)
                """, (
                    device_id,
                    "unknown_device",
                    20,
                    "MEDIUM",
                    (
                        "New network device discovered: "
                        f"{ip_address} "
                        f"(MAC: {normalized_mac}). "
                        "Administrator approval required."
                    ),
                    timestamp
                ))

                print(
                    "[DeviceDiscovery] NEW DEVICE ALERT: "
                    f"Device ID {device_id} | "
                    f"IP {ip_address} | "
                    f"MAC {normalized_mac}",
                    flush=True
                )


        connection.commit()

        return device_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



# ==========================================================
# DEVICE ONLINE / OFFLINE TRACKING
# ==========================================================

def mark_missing_devices_offline(discovered_ips, excluded_macs=None):
    """
    Mark devices offline after three consecutive missed scans.

    A discovered device resets its counter to zero.
    Quarantined devices retain their quarantine status.
    Only devices in TARGET_NETWORK are evaluated.
    """

    connection = get_connection()

    try:
        cursor = connection.cursor()

        columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(devices)"
            ).fetchall()
        }

        if "missed_scans" not in columns:
            cursor.execute("""
                ALTER TABLE devices
                ADD COLUMN missed_scans INTEGER NOT NULL DEFAULT 0
            """)

        local_network = ipaddress.ip_network(
            config.TARGET_NETWORK,
            strict=False
        )

        detected_ips = set(discovered_ips)


        # Devices monitored by the Huawei router must not
        # have their presence status changed by Scapy.
        excluded_macs = {
            str(mac).strip().upper()
            for mac in (excluded_macs or [])
            if mac
        }



        stored_devices = cursor.execute("""
            SELECT id, ip_address, mac_address,
                   status, missed_scans
            FROM devices
        """).fetchall()


        for device in stored_devices:
            device_id = device["id"]
            ip_address = device["ip_address"]
            status = device["status"]


            mac_address = str(
                device["mac_address"] or ""
            ).strip().upper()

            # Huawei controls the Online/Offline status
            # of these Wi-Fi devices.
            if mac_address in excluded_macs:
                continue


            try:
                device_ip = ipaddress.ip_address(ip_address)
            except (ValueError, TypeError):
                continue

            if device_ip not in local_network:
                continue

            # Device found during this scan.
            if ip_address in detected_ips:
                if status == "quarantined":
                    cursor.execute("""
                        UPDATE devices
                        SET missed_scans = 0
                        WHERE id = ?
                    """, (device_id,))
                else:
                    cursor.execute("""
                        UPDATE devices
                        SET missed_scans = 0,
                            status = 'online'
                        WHERE id = ?
                    """, (device_id,))

                continue

            # Never overwrite quarantine status.
            if status == "quarantined":
                continue

            new_count = int(device["missed_scans"] or 0) + 1

            if new_count >= 3:
                cursor.execute("""
                    UPDATE devices
                    SET missed_scans = ?,
                        status = 'offline'
                    WHERE id = ?
                """, (new_count, device_id))
            else:
                cursor.execute("""
                    UPDATE devices
                    SET missed_scans = ?
                    WHERE id = ?
                """, (new_count, device_id))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ==========================================================
# DEVICE TYPE AND BEHAVIOUR PROFILES
# ==========================================================

def infer_device_type(name_or_host, mac):
    """Estimate device type using its hostname or name."""

    target = (name_or_host or "").lower()

    if any(k in target for k in [
        "printer", "hp-print", "epson", "canon"
    ]):
        return "Printer"

    elif any(k in target for k in [
        "cam", "cctv", "dvr", "nvr"
    ]):
        return "CCTV / Camera"

    elif any(k in target for k in [
        "iphone", "android", "galaxy", "phone", "mobile"
    ]):
        return "Mobile"

    elif any(k in target for k in [
        "laptop", "desktop", "pc", "macbook", "workstation"
    ]):
        return "Workstation"

    elif any(k in target for k in [
        "router", "gateway", "switch", "ap"
    ]):
        return "Gateway/Router"

    return "IoT Device"


def init_default_profile(device_id, device_type, cursor):
    """Initialize device-specific behavioural baselines."""

    now = datetime.now().isoformat(timespec="seconds")

    if device_type == "Printer":
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id,
                normal_bandwidth,
                normal_protocols,
                normal_ports,
                normal_dns_rate,
                normal_dest_ips,
                active_hours,
                updated_at
            )
            VALUES (
                ?, 5.0, 'TCP', '9100,515,631',
                10, 3, '08:00-18:00', ?
            )
        """, (device_id, now))

    elif device_type == "CCTV / Camera":
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id,
                normal_bandwidth,
                normal_protocols,
                normal_ports,
                normal_dns_rate,
                normal_dest_ips,
                active_hours,
                updated_at
            )
            VALUES (
                ?, 100.0, 'TCP,UDP', '554,80,443',
                5, 2, '00:00-23:59', ?
            )
        """, (device_id, now))

    else:
        cursor.execute("""
            INSERT OR IGNORE INTO behaviour_profiles (
                device_id,
                normal_bandwidth,
                normal_protocols,
                normal_ports,
                normal_dns_rate,
                normal_dest_ips,
                active_hours,
                updated_at
            )
            VALUES (
                ?, 50.0, 'TCP,UDP', '80,443,53',
                40, 12, '08:00-20:00', ?
            )
        """, (device_id, now))


# ==========================================================
# DEVICE DATABASE OPERATIONS
# ==========================================================

def get_all_devices():
    """Retrieve all devices, ordered by risk score."""

    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT *
            FROM devices
            ORDER BY risk_score DESC, id ASC
        """).fetchall()

        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_device_by_mac(mac_address):
    """Find a device using its verified MAC address."""

    if is_placeholder_mac(mac_address):
        return None

    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT *
            FROM devices
            WHERE LOWER(mac_address) = LOWER(?)
        """, (mac_address,)).fetchone()

        return dict(row) if row else None
    finally:
        conn.close()


def get_device_by_id(device_id):
    """Retrieve a device by its primary key."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()

        return dict(row) if row else None
    finally:
        conn.close()


def get_device_by_ip(ip_address):
    """Retrieve a device using its IP address."""

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM devices WHERE ip_address = ?",
            (ip_address,)
        ).fetchone()

        return dict(row) if row else None
    finally:
        conn.close()


def update_device_risk(device_id, risk_score):
    """Update a device's risk score."""

    conn = get_connection()
    try:
        conn.execute("""
            UPDATE devices
            SET risk_score = ?
            WHERE id = ?
        """, (risk_score, device_id))
        conn.commit()
    finally:
        conn.close()


def set_device_trusted(device_id, trusted):
    """Update the trusted flag for a device."""

    conn = get_connection()
    try:
        conn.execute("""
            UPDATE devices
            SET trusted = ?
            WHERE id = ?
        """, (1 if trusted else 0, device_id))
        conn.commit()
    finally:
        conn.close()


def set_device_status(device_id, status):
    """Update a device's network status."""

    conn = get_connection()
    try:
        conn.execute("""
            UPDATE devices
            SET status = ?
            WHERE id = ?
        """, (status, device_id))
        conn.commit()
    finally:
        conn.close()


# ==========================================================
# TRAFFIC LOGGING AND RETRIEVAL
# ==========================================================

def log_traffic(
    device_id,
    source_ip,
    destination_ip,
    protocol="TCP",
    destination_port=None,
    packet_size=0,
    dns_query=None,
    timestamp=None,
    is_simulated=False,
    tcp_flags=None
):
    """Store real or simulated traffic, including optional TCP flags."""

    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO traffic (
                device_id,
                source_ip,
                destination_ip,
                protocol,
                destination_port,
                packet_size,
                dns_query,
                timestamp,
                is_simulated,
                tcp_flags
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            source_ip,
            destination_ip,
            protocol,
            destination_port,
            packet_size,
            dns_query,
            timestamp,
            int(is_simulated),
            tcp_flags
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_recent_tcp_syn_traffic(
    device_id,
    minutes=5,
    limit=5000
):
    """
    Retrieve initial TCP SYN packets for a device.

    Used specifically for port-scan detection.
    Excludes SYN-ACK, ACK, and established TCP traffic.
    """

    if minutes <= 0:
        raise ValueError("minutes must be greater than zero")

    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    cutoff = (
        datetime.now() - timedelta(minutes=minutes)
    ).isoformat(timespec="seconds")

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                t.id,
                t.device_id,
                t.source_ip,
                t.destination_ip,
                t.protocol,
                t.destination_port,
                t.tcp_flags,
                t.timestamp
            FROM traffic t
            WHERE t.device_id = ?
              AND t.protocol = 'TCP'
              AND t.tcp_flags = 'S'
              AND datetime(t.timestamp) >= datetime(?)
              AND datetime(t.timestamp) <= datetime('now','localtime')
              AND COALESCE(t.is_simulated, 0) = 0
            ORDER BY t.id DESC
            LIMIT ?
        """, (
            device_id,
            cutoff,
            limit
        )).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_recent_dns_queries(
    device_id,
    minutes=1,
    limit=5000
):
    """
    Retrieve conventional DNS query packets.

    Only port 53 queries are included.
    DNS responses and mDNS traffic are excluded.
    """

    if minutes <= 0:
        raise ValueError("minutes must be greater than zero")

    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    cutoff = (
        datetime.now() - timedelta(minutes=minutes)
    ).isoformat(timespec="seconds")

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                t.id,
                t.device_id,
                t.source_ip,
                t.destination_ip,
                t.destination_port,
                t.protocol,
                t.dns_query,
                t.timestamp
            FROM traffic t
            WHERE t.device_id = ?
              AND t.destination_port = 53
              AND t.dns_query IS NOT NULL
              AND TRIM(t.dns_query) != ''
              AND datetime(t.timestamp) >= datetime(?)
              AND datetime(t.timestamp) <= datetime('now','localtime')
              AND COALESCE(t.is_simulated, 0) = 0
            ORDER BY t.id DESC
            LIMIT ?
        """, (
            device_id,
            cutoff,
            limit
        )).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_recent_traffic(
    limit=50,
    device_id=None,
    minutes=None,
    is_simulated=None
):
    """Retrieve recent traffic with optional filters."""

    conn = get_connection()

    try:
        query = """
            SELECT t.*, d.hostname, d.device_name
            FROM traffic t
            JOIN devices d ON t.device_id = d.id
            WHERE 1 = 1
        """

        params = []

        if device_id is not None:
            query += " AND t.device_id = ?"
            params.append(device_id)

        if is_simulated is not None:
            query += " AND t.is_simulated = ?"
            params.append(int(is_simulated))

        if minutes is not None:
            if minutes <= 0:
                raise ValueError("minutes must be greater than zero")

            cutoff = (
                datetime.now() - timedelta(minutes=minutes)
            ).isoformat(timespec="seconds")

            query += " AND datetime(t.timestamp) >= datetime(?) AND datetime(t.timestamp) <= datetime('now','localtime')"
            params.append(cutoff)

        query += " ORDER BY t.id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    finally:
        conn.close()


# ==========================================================
# ALERT MANAGEMENT
# ==========================================================

def create_alert(
    device_id,
    alert_type,
    risk_score,
    severity,
    description,
    timestamp=None,
    refresh_open=False
):
    """Create an alert unless an identical open alert already exists."""

    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    conn = get_connection()

    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.cursor()

        existing = cur.execute("""
            SELECT id
            FROM alerts
            WHERE device_id = ?
              AND alert_type = ?
              AND status = 'open'
        """, (device_id, alert_type)).fetchone()

        if existing:
            alert_id = existing["id"]
            if refresh_open:
                cur.execute('UPDATE alerts SET risk_score=?,severity=?,description=? WHERE id=? AND status=\'open\'',(risk_score,severity,description,alert_id))
        else:
            cur.execute("""
                INSERT INTO alerts (
                    device_id,
                    alert_type,
                    risk_score,
                    severity,
                    description,
                    status,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, 'open', ?)
            """, (
                device_id,
                alert_type,
                risk_score,
                severity,
                description,
                timestamp
            ))

            alert_id = cur.lastrowid

        conn.commit()
        return alert_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_recent_alerts(limit=50, status=None):
    """Retrieve alerts, optionally filtered by status."""

    conn = get_connection()

    try:
        query = """
            SELECT
                a.*,
                d.ip_address,
                d.hostname,
                d.device_name
            FROM alerts a
            JOIN devices d ON a.device_id = d.id
        """

        params = []

        if status:
            query += " WHERE a.status = ?"
            params.append(status)

        query += " ORDER BY a.id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    finally:
        conn.close()


def resolve_alert(alert_id):
    """Mark a security alert as resolved."""

    conn = get_connection()

    try:
        conn.execute("""
            UPDATE alerts
            SET status = 'resolved'
            WHERE id = ?
        """, (alert_id,))
        conn.commit()

    finally:
        conn.close()


# ==========================================================
# BEHAVIOURAL PROFILES
# ==========================================================

def get_device_profile(device_id):
    """Retrieve a device's behavioural baseline profile."""

    conn = get_connection()

    try:
        row = conn.execute("""
            SELECT *
            FROM behaviour_profiles
            WHERE device_id = ?
        """, (device_id,)).fetchone()

        return dict(row) if row else None

    finally:
        conn.close()


# ==========================================================
# QUARANTINE LOGGING
# ==========================================================

def log_quarantine(
    device_id,
    action,
    reason,
    performed_by="NetGuardian Auto-Engine"
):
    """Record quarantine and release actions."""

    now = datetime.now().isoformat(timespec="seconds")

    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO quarantine_logs (
                device_id,
                action,
                reason,
                performed_by,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            device_id,
            action,
            reason,
            performed_by,
            now
        ))

        conn.commit()

    finally:
        conn.close()


def get_quarantine_logs(limit=20):
    """Retrieve recent quarantine audit records."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                q.*,
                d.ip_address,
                d.hostname,
                d.device_name
            FROM quarantine_logs q
            JOIN devices d ON q.device_id = d.id
            ORDER BY q.id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


# ==========================================================
# NETWORK DASHBOARD STATISTICS
# ==========================================================

def get_network_stats():
    """Aggregate monitoring statistics for local devices."""

    conn = get_connection()

    try:

        all_devices = conn.execute("""
            SELECT ip_address, mac_address,
                   status, risk_score
            FROM devices
        """).fetchall()


        invalid_macs = {
            "",
            "AUTO-CAPTURED",
            "UNKNOWN",
            "00:00:00:00:00:00",
        }

        local_devices = [
            device
            for device in all_devices
            if is_local_device_ip(device["ip_address"])
            and str(
                device["mac_address"] or ""
            ).strip().upper() not in invalid_macs
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
            if (device["risk_score"] or 0) >= 70
        )

        alert_rows = conn.execute("""
            SELECT a.status, d.ip_address
            FROM alerts a
            JOIN devices d ON a.device_id = d.id
            WHERE a.status = 'open'
        """).fetchall()

        open_alerts = sum(
            1 for alert in alert_rows
            if is_local_device_ip(alert["ip_address"])
        )

        return {
            "total_devices": total_devices,
            "online_devices": online_devices,
            "quarantined_devices": quarantined_devices,
            "open_alerts": open_alerts,
            "high_risk_devices": high_risk_devices
        }

    finally:
        conn.close()
