from scapy.all import ARP, Ether, srp
import config
from discovery.device_discovery import detect_active_interface

# Target network (auto-detected or configured)
target_network = config.TARGET_NETWORK

# Active network interface (auto-detected)
interface = detect_active_interface()

print("Starting network discovery...")
print(f"Scanning : {target_network}")
print(f"Interface: {interface}")
print()

try:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_network)
    answered, unanswered = srp(
        packet,
        timeout=2,
        verbose=0,
        iface=interface
    )

    print("Devices found:")
    print("-" * 50)

    for sent, received in answered:
        print(f"IP Address : {received.psrc}")
        print(f"MAC Address: {received.hwsrc}")
        print("-" * 50)

    print(f"Total devices found: {len(answered)}")
except Exception as e:
    print(f"Discovery test notice: {e}")