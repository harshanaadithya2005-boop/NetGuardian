from scapy.all import ARP, Ether, srp
from database.models import add_or_update_device, mark_missing_devices_offline
from datetime import datetime
import socket


# Authorized test network
TARGET_NETWORK = "192.168.8.0/24"

# Active Scapy interface
INTERFACE = r"\Device\NPF_{B6782096-0312-4A4E-B1DF-CC38D37385A3}"


def get_hostname(ip_address):
    """Try to find the hostname of a device."""

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname

    except (socket.herror, socket.timeout, OSError):
        return None

def get_device_type(hostname, ip_address):
    """Estimate a basic device type using available network information."""

    # The default gateway/router on the authorized test network
    if ip_address == "192.168.8.1":
        return "Router"

    if hostname:
        hostname_lower = hostname.lower()

        if "desktop" in hostname_lower:
            return "Desktop"

        if "laptop" in hostname_lower:
            return "Laptop"

        if "iphone" in hostname_lower or "android" in hostname_lower:
            return "Mobile"

    return "Unknown"

def discover_devices():
    """Discover devices and save them to the database."""

    print("Starting NetGuardian device discovery...")
    print(f"Scanning network: {TARGET_NETWORK}")
    print()

    # Create ARP discovery packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        pdst=TARGET_NETWORK
    )

    # Send packet and receive responses
    answered, unanswered = srp(
        packet,
        timeout=3,
        verbose=0,
        iface=INTERFACE
    )

    current_time = datetime.now().isoformat(timespec="seconds")

    print("Devices discovered:")
    print("-" * 70)
    discovered_ips = []
    for sent, received in answered:

        ip_address = received.psrc
        discovered_ips.append(ip_address)
        mac_address = received.hwsrc

        # Try to find hostname
        hostname = get_hostname(ip_address)

        # Estimate device type
        device_type = get_device_type(hostname, ip_address)

        print(f"IP Address : {ip_address}")
        print(f"MAC Address: {mac_address}")
        print(f"Hostname   : {hostname}")
        print(f"Device Type: {device_type}")
        print("-" * 70)

        # Save device to database
        add_or_update_device(
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname,
            device_type=device_type,
            timestamp=current_time
        )
    # Mark devices not found in this scan as offline
    mark_missing_devices_offline(discovered_ips)
    
    print(f"Total devices discovered: {len(answered)}")


if __name__ == "__main__":
    discover_devices()