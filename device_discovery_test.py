from scapy.all import ARP, Ether, srp

# Our authorized test network
target_network = "192.168.8.0/24"

# Your active network interface
interface = r"\Device\NPF_{B6782096-0312-4A4E-B1DF-CC38D37385A3}"

print("Starting network discovery...")
print(f"Scanning: {target_network}")
print()

packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_network)

answered, unanswered = srp(
    packet,
    timeout=3,
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