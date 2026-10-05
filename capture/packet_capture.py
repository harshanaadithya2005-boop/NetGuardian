import sys
import threading
import time
from pathlib import Path
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.models import get_device_by_ip, add_or_update_device, log_traffic
from discovery.device_discovery import detect_active_interface

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Global state control
_capture_thread = None
_stop_capture = threading.Event()


def process_packet(packet):
    """Callback function executed on every intercepted packet."""
    if not SCAPY_AVAILABLE or not packet.haslayer(IP):
        return

    try:
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_size = len(packet)
        protocol = "IP"
        dst_port = None
        dns_query = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dst_port = packet[UDP].dport
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                protocol = "DNS"
                try:
                    qname = packet[DNSQR].qname
                    dns_query = qname.decode("utf-8").rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
                except Exception:
                    dns_query = None

        # Ignore loopback traffic
        if src_ip.startswith("127.") or dst_ip.startswith("127."):
            return

        # Check if source device exists in our database
        dev = get_device_by_ip(src_ip)
        if not dev:
            # Auto-register newly active IP
            dev_id = add_or_update_device(
                ip_address=src_ip,
                mac_address="AUTO-CAPTURED",
                hostname=f"Host-{src_ip.split('.')[-1]}"
            )
        else:
            dev_id = dev["id"]

        # Log traffic flow record
        now = datetime.now().isoformat(timespec="seconds")
        log_traffic(
            device_id=dev_id,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=protocol,
            destination_port=dst_port,
            packet_size=pkt_size,
            dns_query=dns_query,
            timestamp=now
        )
    except Exception:
        pass


def _sniff_worker(interface):
    """Background sniffer loop."""
    print(f"[PacketCapture] Passive sniffing started on interface: {interface}")
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


def start_capture(interface=None):
    """Start passive packet sniffing in a background daemon thread."""
    global _capture_thread, _stop_capture

    if not SCAPY_AVAILABLE:
        print("[PacketCapture] Scapy not available. Sniffing cannot start.")
        return False

    if _capture_thread and _capture_thread.is_alive():
        print("[PacketCapture] Capture is already running.")
        return True

    iface = interface or detect_active_interface()
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
    print("Testing Packet Capture for 5 seconds...")
    start_capture()
    time.sleep(5)
    stop_capture()
    print("Finished.")
