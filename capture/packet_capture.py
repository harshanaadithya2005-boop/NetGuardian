
import sys
import socket
import threading
import time
import ipaddress
from pathlib import Path
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.models import (
    get_device_by_ip,
    get_device_by_mac,
    add_or_update_device,
    log_traffic
)
from discovery.device_discovery import detect_active_interface
from monitoring.traffic_monitor import (
    create_traffic_table,
    save_traffic_record
)

try:
    from scapy.all import (
        sniff,
        Ether,
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        get_if_hwaddr,
        get_if_addr
    )
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# Active interface with dynamic fallback
INTERFACE = detect_active_interface()


# Traffic statistics tracking
traffic_stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

device_traffic = {}


def get_local_mac():
    """Return the MAC address of the active capture interface."""
    if not SCAPY_AVAILABLE or INTERFACE is None:
        return None

    try:
        return get_if_hwaddr(INTERFACE).lower()
    except Exception:
        return None


def get_local_ip():
    """Return the IPv4 address of the active capture interface."""
    if not SCAPY_AVAILABLE or INTERFACE is None:
        return None

    try:
        address = get_if_addr(INTERFACE)
        if address and address != "0.0.0.0":
            return address
    except Exception:
        pass

    return None


# Background thread control
_capture_thread = None
_stop_capture = threading.Event()


def get_protocol(packet):
    """Identify the main protocol used by an IP packet."""
    if not SCAPY_AVAILABLE:
        return "OTHER"

    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"

    return "OTHER"


def process_packet(packet):
    """Callback function executed on every intercepted packet."""
    if not SCAPY_AVAILABLE or not packet.haslayer(IP):
        return

    try:
        ip_layer = packet.getlayer(IP)
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        # Extract Ethernet addresses when available.
        if packet.haslayer(Ether):
            ethernet_layer = packet[Ether]
            source_mac = ethernet_layer.src
            destination_mac = ethernet_layer.dst
        else:
            source_mac = None
            destination_mac = None

        packet_size = len(packet)
        protocol = get_protocol(packet)

        # Update running in-memory statistics.
        traffic_stats["total_packets"] += 1
        traffic_stats["total_bytes"] += packet_size
        traffic_stats[protocol] += 1

        if source_ip not in device_traffic:
            device_traffic[source_ip] = {
                "packets": 0,
                "bytes": 0
            }

        device_traffic[source_ip]["packets"] += 1
        device_traffic[source_ip]["bytes"] += packet_size

        # Extract port and DNS information.
        source_port = None
        destination_port = None
        dns_query = None
        tcp_flags = None

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                protocol = "DNS"

                try:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        dns_query = qname.decode(
                            "utf-8"
                        ).rstrip(".")
                    else:
                        dns_query = str(qname).rstrip(".")
                except Exception:
                    dns_query = None

        timestamp = datetime.now().isoformat(timespec="seconds")

        # 1. Save traffic to Member 1's statistics table.
        try:
            save_traffic_record(
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port,
                packet_size=packet_size,
                timestamp=timestamp
            )
        except Exception as e:
            print(
                f"[PacketCapture] save_traffic_record failed: "
                f"{type(e).__name__}: {e}"
            )

        # Ignore loopback traffic in the core device database.
        if (
            source_ip.startswith("127.")
            or destination_ip.startswith("127.")
        ):
            return

        # 2. Only associate devices within the target network.
        try:
            local_network = ipaddress.ip_network(
                config.TARGET_NETWORK,
                strict=False
            )
            source_address = ipaddress.ip_address(source_ip)
            destination_address = ipaddress.ip_address(
                destination_ip
            )
        except ValueError:
            return

        if source_address in local_network:
            # Outgoing traffic: local source device.
            source_ip_for_device = source_ip
            candidate_mac = source_mac

        elif destination_address in local_network:
            # Incoming traffic: local destination device.
            source_ip_for_device = destination_ip
            candidate_mac = destination_mac

        else:
            return

        # 3. Verify whether this packet belongs to the
        # computer running NetGuardian.
        local_ip = get_local_ip()
        local_mac = get_local_mac()

        is_local_desktop = (
            local_ip is not None
            and local_mac is not None
            and candidate_mac is not None
            and source_ip_for_device == local_ip
            and candidate_mac.lower() == local_mac
        )

        # 4. Prefer the verified local MAC identity.
        if is_local_desktop:
            dev = get_device_by_mac(local_mac)

            if dev:
                print(
                    "[PacketCapture] Local desktop identified "
                    f"as device {dev['id']}"
                )
            else:
                # Do not assume a missing MAC record is safe.
                dev = get_device_by_ip(source_ip_for_device)

        else:
            # For other devices, use the existing IP lookup.
            # Their identity is not verified by this lookup.
            dev = get_device_by_ip(source_ip_for_device)

        # 5. Register an unknown IP only when no record exists.

        if not dev:
            # Do not create placeholder devices from observed traffic.
            # Device discovery is responsible for registering devices.
            print(
                "[PacketCapture] Unregistered local device observed: "
                f"{source_ip_for_device}. "
                "Traffic statistics were collected, but device-specific "
                "logging was skipped."
            )
            return
        else:
            dev_id = dev["id"]


        # 6. Log traffic with its original source and destination.
        log_traffic(
            device_id=dev_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            destination_port=destination_port,
            packet_size=packet_size,
            dns_query=dns_query,
            timestamp=timestamp,
            tcp_flags=tcp_flags
        )

    except Exception as e:
        print(f"[PacketCapture] Packet processing error: {e}")


def _sniff_worker(interface):
    """Background packet capture worker."""
    print(
        "[PacketCapture] Passive sniffing started "
        f"on interface: {interface}"
    )

    create_traffic_table()

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: _stop_capture.is_set()
        )
    except Exception as e:
        print(f"[PacketCapture] Sniffing error: {e}")

    print("[PacketCapture] Sniffing stopped.")


def start_capture(interface=None, packet_count=None):
    """
    Start packet capture.

    packet_count specified:
        Capture a limited number of packets synchronously.

    packet_count None:
        Run continuously in a background daemon thread.
    """
    global _capture_thread, _stop_capture

    if not SCAPY_AVAILABLE:
        print(
            "[PacketCapture] Scapy not available. "
            "Sniffing cannot start."
        )
        return False

    iface = interface or detect_active_interface()

    if iface is None:
        print("[PacketCapture] No active interface found.")
        return False

    create_traffic_table()

    # Synchronous limited capture mode.
    if packet_count is not None:
        print("Starting NetGuardian packet capture...")
        print(f"Capturing {packet_count} packets on {iface}...")
        print("-" * 70)

        sniff(
            iface=iface,
            prn=process_packet,
            count=packet_count,
            store=False
        )

        print("-" * 70)
        print("Packet capture completed.\n")
        print("Traffic Statistics")
        print("-" * 70)
        print(
            f"Total IP Packets : "
            f"{traffic_stats['total_packets']}"
        )
        print(
            f"Total Bytes      : "
            f"{traffic_stats['total_bytes']}"
        )
        print(f"TCP Packets      : {traffic_stats['TCP']}")
        print(f"UDP Packets      : {traffic_stats['UDP']}")
        print(f"ICMP Packets     : {traffic_stats['ICMP']}")
        print(f"Other IP Packets : {traffic_stats['OTHER']}")

        print("\nTraffic by Source IP")
        print("-" * 70)

        for ip, stats in device_traffic.items():
            print(
                f"IP: {ip} | "
                f"Packets Sent: {stats['packets']} | "
                f"Bytes Sent: {stats['bytes']}"
            )

        return True

    # Continuous background daemon capture mode.
    if _capture_thread and _capture_thread.is_alive():
        print("[PacketCapture] Capture is already running.")
        return True

    _stop_capture.clear()

    _capture_thread = threading.Thread(
        target=_sniff_worker,
        args=(iface,),
        daemon=True
    )
    _capture_thread.start()

    return True


def stop_capture():
    """Request that the background packet sniffer stop."""
    global _stop_capture
    _stop_capture.set()


def is_capturing():
    """Check whether the sniffer thread is running."""
    return (
        _capture_thread is not None
        and _capture_thread.is_alive()
    )


if __name__ == "__main__":
    start_capture(packet_count=10)
