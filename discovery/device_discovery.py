import sys
import os
from pathlib import Path
import re
import socket
import subprocess
import ipaddress
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.models import add_or_update_device, mark_missing_devices_offline

try:
    from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def is_target_network_ip(ip_address, target_network=None):
    """
    Check whether an IP belongs to NetGuardian's
    configured local network.
    """

    try:
        network = ipaddress.ip_network(
            target_network or config.TARGET_NETWORK,
            strict=False
        )

        address = ipaddress.ip_address(ip_address)

        return (
            address in network
            and address != network.network_address
            and address != network.broadcast_address
        )

    except (ValueError, TypeError):
        return False


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


def get_device_type(hostname, ip_address):
    """Estimate a basic device type using available network information."""
    if ip_address == "192.168.8.1" or ip_address.endswith(".1"):
        return "Gateway/Router"

    if hostname:
        hostname_lower = hostname.lower()
        if "desktop" in hostname_lower:
            return "Desktop"
        if "laptop" in hostname_lower:
            return "Laptop"
        if "iphone" in hostname_lower or "android" in hostname_lower or "phone" in hostname_lower:
            return "Mobile"
        if "printer" in hostname_lower:
            return "Printer"
        if "cam" in hostname_lower or "cctv" in hostname_lower:
            return "CCTV / Camera"

    return "IoT Device"


def scan_via_system_arp():
    """Fallback scanner: Read the operating system's ARP table ('arp -a')."""
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)")
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac, entry_type = match.groups()

                if not is_target_network_ip(ip):
                    continue

                if entry_type.lower() != "dynamic":
                    continue

                # Skip broadcast and multicast addresses
                if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                    formatted_mac = mac.replace("-", ":").upper()
                    hostname = get_hostname(ip)
                    devices.append({
                        "ip": ip,
                        "mac": formatted_mac,
                        "hostname": hostname,
                        "device_type": get_device_type(hostname, ip)
                    })
    except Exception as e:
        print(f"[Discovery] System ARP scan notice: {e}")
    return devices







def discover_devices(
    target_network=None,
    iface=None,
    allow_fallback=True,
    full_sweep=True,
    excluded_macs=None
):

    """
    Discover local devices using fresh ARP responses.

    Features:
    - Initial subnet scan
    - Targeted retry of known devices
    - Targeted recovery sweep for new devices
    - MAC-based identity handling
    - Safe offline tracking
    """

    import ipaddress
    from database.models import get_all_devices

    target = target_network or config.TARGET_NETWORK
    interface = iface or detect_active_interface()

    network = ipaddress.ip_network(target, strict=False)

    discovered_by_ip = {}
    confirmed_ips = []


    # MAC addresses whose Online/Offline status is
    # controlled by the Huawei router monitor.

    # Load all Wi-Fi identities confirmed by the Huawei router.
    # Keep disconnected Wi-Fi clients protected as well.
    from router.router_sync import get_huawei_managed_macs

    huawei_managed_macs = get_huawei_managed_macs()

    excluded_macs = {
        str(mac).strip().upper()
        for mac in (excluded_macs or [])
        if mac
    }

    # The persistent registry is always applied, including
    # startup scans and manual dashboard scans.
    excluded_macs.update(huawei_managed_macs)

    print(
        f"[Discovery] Huawei-protected devices: "
        f"{len(excluded_macs)}",
        flush=True
    )


    scan_succeeded = False
    current_time = datetime.now().isoformat(timespec="seconds")

    print("=" * 60)
    print("Starting NetGuardian Device Discovery...")
    print(f"Scanning target network: {target}")
    print(f"Active interface: {interface}")
    print("=" * 60)

    if not SCAPY_AVAILABLE or not interface:
        print("[Discovery] Active Scapy scanning unavailable.")
        return []

    # Restrict recovery sweeps to small local networks.
    # NetGuardian's configured /24 network is supported.
    if network.num_addresses > 512:
        print(
            "[Discovery] Network too large for targeted recovery. "
            "Use a subnet containing 512 addresses or fewer."
        )
        return []

    def record_responses(answered, source):
        """Keep only fresh, valid local ARP responses."""

        for _, response in answered:
            ip = str(response.psrc)
            mac = str(response.hwsrc).upper()

            if not is_target_network_ip(ip, target):
                continue

            if mac in {
                "",
                "00:00:00:00:00:00",
                "FF:FF:FF:FF:FF:FF"
            }:
                continue

            if ip not in discovered_by_ip:
                discovered_by_ip[ip] = mac
                print(f"[{source}] FOUND {ip} -> {mac}")

            elif discovered_by_ip[ip] != mac:
                print(
                    f"[Discovery] Conflicting ARP responses "
                    f"for {ip}. Keeping first observation "
                    "for this scan."
                )

    def active_probe(addresses, source, timeout=2, retry=0):
        """Actively request ARP responses from specified IPs."""

        if not addresses:
            return

        packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / ARP(pdst=addresses)
        )

        answered, _ = srp(
            packet,
            timeout=timeout,
            retry=retry,
            verbose=False,
            iface=interface
        )

        record_responses(answered, source)

    # --------------------------------------------------
    # 1. Initial full subnet ARP scan
    # --------------------------------------------------
    try:
        print("\n[Discovery] Phase 1: Initial subnet scan")

        active_probe(
            target,
            "SUBNET",
            timeout=2
        )

        scan_succeeded = True

    except Exception as error:
        print(f"[Discovery] Initial scan failed: {error}")

    # --------------------------------------------------
    # 2. Retry known device addresses
    # --------------------------------------------------
    known_ips = set()

    try:
        for device in get_all_devices():
            ip = device.get("ip_address")

            if ip and is_target_network_ip(ip, target):
                known_ips.add(ip)

    except Exception as error:
        print(f"[Discovery] Known device lookup: {error}")

    # Windows ARP cache supplies candidate IPs only.
    # Cached entries are NOT treated as proof of being online.
    if allow_fallback:
        try:
            for device in scan_via_system_arp():
                ip = device.get("ip")

                if ip and is_target_network_ip(ip, target):
                    known_ips.add(ip)

        except Exception as error:
            print(f"[Discovery] ARP candidate lookup: {error}")

    # Include the configured gateway.
    gateway_ip = str(next(network.hosts()))
    known_ips.add(gateway_ip)

    pending_known = sorted(
        known_ips - set(discovered_by_ip),
        key=lambda ip: ipaddress.ip_address(ip)
    )

    print("\n[Discovery] Phase 2: Known device recovery")


    if pending_known:
        try:
            active_probe(
                pending_known,
                "KNOWN",
                timeout=2,
                retry=1
            )
        except Exception as error:
            print(
                "[Discovery] Known-device recovery failed: "
                f"{error}"
            )


    # --------------------------------------------------
    # 3. Targeted recovery sweep
    # --------------------------------------------------
    # This sends individual ARP queries for IPs that
    # were not found during the initial scan.
    # It is slower, but helps recover phones missed
    # by a single subnet broadcast.

    print("\n[Discovery] Phase 3: Targeted recovery sweep")


    if full_sweep:
        remaining = [
            str(ip)
            for ip in network.hosts()
            if str(ip) not in discovered_by_ip
            and str(ip) not in known_ips
        ]
    else:
        remaining = []
        print(
            "[Discovery] Full recovery sweep skipped "
            "(fast presence scan)."
        )


    batch_size = 32

    for start in range(0, len(remaining), batch_size):
        batch = remaining[start:start + batch_size]

        try:
            active_probe(
                batch,
                "RECOVERY",
                timeout=1.5
            )

        except Exception as error:
            print(
                "[Discovery] Recovery batch failed: "
                f"{error}"
            )

    # --------------------------------------------------
    # 4. Preserve local computer identity
    # --------------------------------------------------
    local_ip = config.get_local_ip()

    if (
        local_ip != "127.0.0.1"
        and is_target_network_ip(local_ip, target)
        and local_ip not in discovered_by_ip
    ):
        # Local interface addresses can be validated
        # directly without an ARP reply to ourselves.
        try:
            from scapy.all import get_if_hwaddr

            local_mac = get_if_hwaddr(interface).upper()

            if local_mac not in {
                "00:00:00:00:00:00",
                "FF:FF:FF:FF:FF:FF"
            }:
                discovered_by_ip[local_ip] = local_mac
                print(
                    f"[LOCAL] FOUND {local_ip} -> {local_mac}"
                )

        except Exception as error:
            print(f"[Discovery] Local MAC lookup: {error}")

    # --------------------------------------------------
    # 5. Save confirmed devices
    # --------------------------------------------------
    discovered = []

    print("\nDevices Discovered:")
    print("-" * 70)


    # Reuse previously discovered names during FAST scans.
    # Resolve hostnames only during FULL scans.
    known_devices_by_mac = {}

    for known in get_all_devices():
        known_mac = str(known.get("mac_address") or "").upper()

        if known_mac:
            known_devices_by_mac[known_mac] = known

    for ip in sorted(
        discovered_by_ip,
        key=lambda address: ipaddress.ip_address(address)
    ):
        mac = discovered_by_ip[ip]

        existing = known_devices_by_mac.get(mac)

        if ip == local_ip:
            hostname = socket.gethostname()

        elif full_sweep:
            hostname = get_hostname(ip)

        elif existing:
            hostname = existing.get("hostname")

        else:
            hostname = None

        if existing and not full_sweep:
            device_type = existing.get("device_type")
        else:
            device_type = get_device_type(hostname, ip)


        device = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "device_type": device_type
        }

        discovered.append(device)

        print(f"IP Address : {ip}")
        print(f"MAC Address: {mac}")
        print(f"Hostname   : {hostname}")
        print(f"Device Type: {device_type}")

        try:

            if mac in excluded_macs:
                # Huawei owns this Wi-Fi device's presence status.
                # Scapy can observe it but must not overwrite
                # Huawei-confirmed Online/Offline information.
                confirmed_ips.append(ip)

                print(
                    f"[Discovery] Huawei-managed device observed: "
                    f"{ip} ({mac}). Status update skipped."
                )

                continue

            device_id = add_or_update_device(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                device_type=device_type,
                timestamp=current_time
            )

            if device_id is not None:
                confirmed_ips.append(ip)
                print(
                    f"[Discovery] Confirmed device ID: "
                    f"{device_id}"
                )
            else:
                print(
                    f"[Discovery] Identity conflict at {ip}. "
                    "Existing identities preserved."
                )

        except Exception as error:
            print(
                f"[Discovery] Database update failed "
                f"for {ip}: {error}"
            )

        print("-" * 70)

    # --------------------------------------------------
    # 6. Update online/offline tracking
    # --------------------------------------------------
    if (
        scan_succeeded
        and gateway_ip in confirmed_ips
    ):
        try:
            mark_missing_devices_offline(
                confirmed_ips,
                excluded_macs=excluded_macs
            )

            print(
                "[Discovery] Offline tracking updated "
                "(gateway confirmed)."
            )

        except Exception as error:
            print(
                "[Discovery] Offline tracking error: "
                f"{error}"
            )
    else:
        print(
            "[Discovery] Offline tracking skipped: "
            "gateway not confirmed or scan failed."
        )

    print(f"Total devices observed: {len(discovered)}")
    print(f"Database identities confirmed: {len(confirmed_ips)}")

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
