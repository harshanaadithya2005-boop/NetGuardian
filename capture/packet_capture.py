import sys
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
from database.models import get_device_by_ip, add_or_update_device, log_traffic
from discovery.device_discovery import detect_active_interface
from monitoring.traffic_monitor import create_traffic_table, save_traffic_record

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
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
        packet_size = len(packet)
        protocol = get_protocol(packet)

        # Update running in-memory stats
        traffic_stats["total_packets"] += 1
        traffic_stats["total_bytes"] += packet_size
        traffic_stats[protocol] += 1

        if source_ip not in device_traffic:
            device_traffic[source_ip] = {"packets": 0, "bytes": 0}
        device_traffic[source_ip]["packets"] += 1
        device_traffic[source_ip]["bytes"] += packet_size

        # Extract port information
        source_port = None
        destination_port = None
        dns_query = None

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                protocol = "DNS"
                try:
                    qname = packet[DNSQR].qname
                    dns_query = qname.decode("utf-8").rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
                except Exception:
                    dns_query = None

        timestamp = datetime.now().isoformat(timespec="seconds")

        # 1. Save to Member 1's traffic_statistics table
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
        except Exception:
            pass

        # Ignore loopback traffic for core NetGuardian device database
        if source_ip.startswith("127.") or destination_ip.startswith("127."):
            return

        # 2. Only register devices from the configured local network
        try:
            local_network = ipaddress.ip_network(config.TARGET_NETWORK, strict=False)
            source_address = ipaddress.ip_address(source_ip)
        except ValueError:
            return

        if source_address not in local_network:
            try:
                destination_address = ipaddress.ip_address(destination_ip)
            except ValueError:
                return

            if destination_address not in local_network:
                return

            # Incoming traffic: associate with local destination
            source_ip_for_device = destination_ip
        else:
            # Outgoing traffic: associate with local source
            source_ip_for_device = source_ip

        # Check if the associated local device exists
        dev = get_device_by_ip(source_ip_for_device)

        if not dev:
            dev_id = add_or_update_device(
                ip_address=source_ip_for_device,
                mac_address="AUTO-CAPTURED",
                hostname=f"Host-{source_ip_for_device.split('.')[-1]}"
            )
        else:
            dev_id = dev["id"]

        # Log traffic using the ORIGINAL source and destination IPs
        log_traffic(
            device_id=dev_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            destination_port=destination_port,
            packet_size=packet_size,
            dns_query=dns_query,
            timestamp=timestamp
        )

    except Exception as e:
        print(f"[PacketCapture] Packet processing error: {e}")


def _sniff_worker(interface):
    """Background sniffer loop."""
    print(f"[PacketCapture] Passive sniffing started on interface: {interface}")
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
    Start packet capture:
    - If packet_count is specified, captures that many packets synchronously (Member 1 mode)
    - If packet_count is None, runs continuously in background daemon thread (NetGuardian engine mode)
    """
    global _capture_thread, _stop_capture

    if not SCAPY_AVAILABLE:
        print("[PacketCapture] Scapy not available. Sniffing cannot start.")
        return False

    iface = interface or detect_active_interface()
    create_traffic_table()

    # Synchronous limited capture mode (Member 1 CLI test)
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
        print(f"Total IP Packets : {traffic_stats['total_packets']}")
        print(f"Total Bytes      : {traffic_stats['total_bytes']}")
        print(f"TCP Packets      : {traffic_stats['TCP']}")
        print(f"UDP Packets      : {traffic_stats['UDP']}")
        print(f"ICMP Packets     : {traffic_stats['ICMP']}")
        print(f"Other IP Packets : {traffic_stats['OTHER']}")
        print("\nTraffic by Source IP")
        print("-" * 70)
        for ip, stats in device_traffic.items():
            print(f"IP: {ip} | Packets Sent: {stats['packets']} | Bytes Sent: {stats['bytes']}")
        return True

    # Continuous background daemon capture mode
    if _capture_thread and _capture_thread.is_alive():
        print("[PacketCapture] Capture is already running.")
        return True

    _stop_capture.clear()
    _capture_thread = threading.Thread(target=_sniff_worker, args=(iface,), daemon=True)
    _capture_thread.start()
    return True


def stop_capture():
    """Stop the background packet sniffer."""
    global _stop_capture
    _stop_capture.set()


def is_capturing():
    """Check if sniffer is running."""
    return _capture_thread is not None and _capture_thread.is_alive()


if __name__ == "__main__":
    start_capture(packet_count=10)
