import sys
import os
from pathlib import Path
import re
import socket
import subprocess
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.models import add_or_update_device

try:
    from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def detect_active_interface():
    """Find the best active Scapy network interface matching the local IP."""
    if not SCAPY_AVAILABLE:
        return None

    local_ip = config.get_local_ip()
    if local_ip != "127.0.0.1":
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip == local_ip:
                    return iface
            except Exception:
                continue

    # Fallback to Scapy default interface
    return getattr(conf, "iface", None)


def get_hostname(ip_address):
    """Try to find the hostname of a device via reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return None


def scan_via_system_arp():
    """Fallback scanner: Read the operating system's ARP table ('arp -a')."""
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        # Match lines like: 192.168.1.1   00-11-22-33-44-55   dynamic
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)")
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac, entry_type = match.groups()
                # Skip broadcast and multicast addresses
                if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                    formatted_mac = mac.replace("-", ":").upper()
                    devices.append({
                        "ip": ip,
                        "mac": formatted_mac,
                        "hostname": get_hostname(ip)
                    })
    except Exception as e:
        print(f"[Discovery] System ARP scan notice: {e}")
    return devices


def discover_devices(target_network=None, iface=None, allow_fallback=True):
    """
    Discover devices and save them to the database.
    Tries Scapy ARP scan first; if unavailable or no responses, falls back to system ARP cache.
    """
    target = target_network or config.TARGET_NETWORK
    interface = iface or detect_active_interface()
    discovered = []
    current_time = datetime.now().isoformat(timespec="seconds")

    print("=" * 60)
    print("Starting NetGuardian Device Discovery...")
    print(f"Scanning target network: {target}")
    if interface:
        print(f"Active interface       : {interface}")
    print("=" * 60)

    # 1. Try Scapy ARP scan
    if SCAPY_AVAILABLE and interface:
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(packet, timeout=2, verbose=0, iface=interface)

            for _, received in answered:
                ip_address = received.psrc
                mac_address = received.hwsrc.upper()
                hostname = get_hostname(ip_address)
                discovered.append({
                    "ip": ip_address,
                    "mac": mac_address,
                    "hostname": hostname
                })
        except Exception as e:
            print(f"[Discovery] Scapy ARP scan failed: {e}")

    # 2. If Scapy produced 0 results or failed, use system ARP table fallback
    if not discovered and allow_fallback:
        print("[Discovery] Using OS ARP table fallback...")
        discovered = scan_via_system_arp()

    # Always ensure local host machine is recorded
    local_ip = config.get_local_ip()
    if local_ip != "127.0.0.1" and not any(d["ip"] == local_ip for d in discovered):
        discovered.append({
            "ip": local_ip,
            "mac": "LOCAL-HOST",
            "hostname": socket.gethostname()
        })

    # Save all discovered devices to database
    print("\nDevices Discovered and Saved to Database:")
    print("-" * 60)
    for dev in discovered:
        ip = dev["ip"]
        mac = dev.get("mac", "UNKNOWN")
        host = dev.get("hostname") or "Unknown"

        print(f"IP Address : {ip}")
        print(f"MAC Address: {mac}")
        print(f"Hostname   : {host}")
        print("-" * 60)

        add_or_update_device(
            ip_address=ip,
            mac_address=mac,
            hostname=host,
            timestamp=current_time
        )

    print(f"Total devices discovered: {len(discovered)}\n")
    return discovered


def seed_demo_devices():
    """Seeds typical lab network devices for demonstration and testing (Proposal Section 8.1)."""
    now = datetime.now().isoformat(timespec="seconds")
    demo_devices = [
        {
            "ip_address": "192.168.1.1",
            "mac_address": "00:1A:2B:3C:4D:01",
            "hostname": "gateway.lan",
            "device_name": "Main Office Router",
            "device_type": "Gateway/Router",
            "trusted": 1,
            "risk_score": 0
        },
        {
            "ip_address": "192.168.1.15",
            "mac_address": "00:1A:2B:3C:4D:15",
            "hostname": "hp-printer-lab.lan",
            "device_name": "HP LaserJet Pro Lab",
            "device_type": "Printer",
            "trusted": 1,
            "risk_score": 5
        },
        {
            "ip_address": "192.168.1.42",
            "mac_address": "00:1A:2B:3C:4D:42",
            "hostname": "laptop-04-dev.lan",
            "device_name": "Dev Workstation Laptop-04",
            "device_type": "Workstation",
            "trusted": 1,
            "risk_score": 15
        },
        {
            "ip_address": "192.168.1.88",
            "mac_address": "00:1A:2B:3C:4D:88",
            "hostname": "cctv-cam-entrance.lan",
            "device_name": "Hikvision CCTV Entrance",
            "device_type": "CCTV / Camera",
            "trusted": 1,
            "risk_score": 0
        },
    ]

    for d in demo_devices:
        add_or_update_device(
            ip_address=d["ip_address"],
            mac_address=d["mac_address"],
            hostname=d["hostname"],
            device_name=d["device_name"],
            device_type=d["device_type"],
            timestamp=now
        )
    print(f"[Seed] Successfully seeded {len(demo_devices)} standard lab devices.")


if __name__ == "__main__":
    discover_devices()