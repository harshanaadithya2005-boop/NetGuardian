import sys
import random
from pathlib import Path
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.models import (
    get_all_devices,
    get_device_by_ip,
    add_or_update_device,
    log_traffic,
    get_connection
)
from risk.risk_engine import evaluate_device_risk, evaluate_all_devices


def get_target_device(ip_address=None):
    """Find a target device for attack simulation, or create a test victim/attacker."""
    if ip_address:
        dev = get_device_by_ip(ip_address)
        if dev:
            return dev

    devices = get_all_devices()
    # Pick a non-router workstation or laptop if available
    for d in devices:
        if d["ip_address"] not in ["192.168.1.1", "127.0.0.1"] and d.get("device_type") in ["Workstation", "IoT Device", "Test"]:
            return d

    # If no devices exist, create a dedicated test host
    test_ip = "192.168.1.42"
    dev_id = add_or_update_device(
        ip_address=test_ip,
        mac_address="00:11:22:33:44:42",
        hostname="laptop-04-dev.lan",
        device_name="Dev Workstation Laptop-04",
        device_type="Workstation"
    )
    return get_device_by_ip(test_ip)


def simulate_benign_traffic(device_ip=None):
    """Generates normal web browsing and DNS lookup traffic."""
    device = get_target_device(device_ip)
    now = datetime.now().isoformat(timespec="seconds")
    normal_sites = ["google.com", "github.com", "microsoft.com", "wikipedia.org", "cloudflare.com"]

    for _ in range(5):
        domain = random.choice(normal_sites)
        log_traffic(
            device_id=device["id"],
            source_ip=device["ip_address"],
            destination_ip=f"142.250.{random.randint(1,254)}.{random.randint(1,254)}",
            protocol="TCP",
            destination_port=443,
            packet_size=random.randint(500, 4500),
            dns_query=domain,
            timestamp=now
        )
    return f"Logged normal traffic for {device['ip_address']}"


def simulate_port_scan(device_ip=None):
    """Simulates reconnaissance activity targeting 12 distinct common ports."""
    device = get_target_device(device_ip)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    now = datetime.now().isoformat(timespec="seconds")
    target_host = "192.168.1.1"

    for port in scan_ports:
        log_traffic(
            device_id=device["id"],
            source_ip=device["ip_address"],
            destination_ip=target_host,
            protocol="TCP",
            destination_port=port,
            packet_size=64,
            timestamp=now
        )

    res = evaluate_device_risk(device["id"])
    return f"Port scan simulated from {device['ip_address']} across {len(scan_ports)} ports. Risk Score: {res['risk_score']}"


def simulate_dns_anomaly(device_ip=None):
    """Simulates DNS data exfiltration / tunneling and DGA command-and-control lookups."""
    device = get_target_device(device_ip)
    now = datetime.now().isoformat(timespec="seconds")
    malicious_domains = [
        "c2-tunnel-payload-exfiltration-data-chunk-0192837465.darknet-relay.org",
        "a9f4c3b2e1d087654321fedcba.attacker-botnet-c2.net",
        "exfil-passwords-secret-keys-archive-chunk99182.dns-tunnel.internal-bad.xyz",
        "random-dga-domain-kx981273918273918273918273.biz"
    ]

    for domain in malicious_domains:
        log_traffic(
            device_id=device["id"],
            source_ip=device["ip_address"],
            destination_ip="8.8.8.8",
            protocol="DNS",
            destination_port=53,
            packet_size=random.randint(120, 350),
            dns_query=domain,
            timestamp=now
        )

    res = evaluate_device_risk(device["id"])
    return f"DNS Anomaly simulated on {device['ip_address']}. Risk Score: {res['risk_score']}"


def simulate_traffic_spike(device_ip=None):
    """Simulates massive data exfiltration and connection to dozens of unfamiliar external IPs."""
    device = get_target_device(device_ip)
    now = datetime.now().isoformat(timespec="seconds")

    # Generate 40 traffic entries each with 15MB to trigger massive bandwidth spike
    for i in range(25):
        ext_ip = f"198.51.{random.randint(1,250)}.{random.randint(1,250)}"
        log_traffic(
            device_id=device["id"],
            source_ip=device["ip_address"],
            destination_ip=ext_ip,
            protocol="TCP",
            destination_port=443,
            packet_size=15 * 1024 * 1024,  # 15 MB per flow
            timestamp=now
        )

    res = evaluate_device_risk(device["id"])
    return f"Traffic volume spike simulated for {device['ip_address']}. Risk Score: {res['risk_score']}"


def simulate_unknown_rogue_device():
    """Simulates an unauthorized attacker device plugging into the network."""
    now = datetime.now().isoformat(timespec="seconds")
    rogue_ip = f"192.168.1.{random.randint(180, 240)}"
    rogue_mac = f"DE:AD:BE:EF:{random.randint(10,99)}:{random.randint(10,99)}"

    dev_id = add_or_update_device(
        ip_address=rogue_ip,
        mac_address=rogue_mac,
        hostname="kali-attacker.local",
        device_name="Unauthorized Rogue Laptop",
        device_type="Workstation",
        timestamp=now
    )

    res = evaluate_device_risk(dev_id)
    return f"Rogue device {rogue_ip} injected on network. Risk Score: {res['risk_score']}"


def simulate_critical_incident(device_ip=None):
    """
    Combined attack scenario (Port Scan + DNS Tunneling + Bandwidth Exfiltration)
    that pushes risk score >= 70, triggering AUTOMATIC QUARANTINE!
    """
    device = get_target_device(device_ip)
    ip = device["ip_address"]

    simulate_port_scan(ip)
    simulate_dns_anomaly(ip)
    simulate_traffic_spike(ip)

    res = evaluate_device_risk(device["id"], auto_quarantine=True)
    status = "QUARANTINED" if res["quarantined"] else "ACTIVE"
    return f"Multi-vector attack simulated on {ip}. Final Risk Score: {res['risk_score']}/100 ({res['risk_level']}). Device Status: {status}!"


def reset_simulation():
    """Clear traffic logs and reset device risk scores and quarantine states."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM traffic")
    cur.execute("DELETE FROM alerts")
    cur.execute("DELETE FROM quarantine_logs")
    cur.execute("UPDATE devices SET risk_score = 0, status = 'online' WHERE status = 'quarantined'")
    conn.commit()
    conn.close()
    evaluate_all_devices()
    return "Simulation data cleared. Network state reset to baseline."


if __name__ == "__main__":
    print("Testing Simulation Scenarios:")
    print(simulate_benign_traffic())
    print(simulate_port_scan())
    print(simulate_dns_anomaly())
