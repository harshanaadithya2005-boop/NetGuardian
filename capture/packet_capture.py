from scapy.all import sniff, IP, TCP, UDP, ICMP


# Active Scapy/Npcap interface
INTERFACE = r"\Device\NPF_{B6782096-0312-4A4E-B1DF-CC38D37385A3}"

traffic_stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

device_traffic = {}

def get_protocol(packet):
    """Identify the main protocol used by an IP packet."""

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    if ICMP in packet:
        return "ICMP"

    return "OTHER"


def process_packet(packet):
    """Display information about captured IP packets."""

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)
        protocol = get_protocol(packet)

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

        source_port = "-"
        destination_port = "-"

        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        print(
            f"Source: {source_ip}:{source_port} | "
            f"Destination: {destination_ip}:{destination_port} | "
            f"Protocol: {protocol} | "
            f"Size: {packet_size} bytes"
        )


def start_capture(packet_count=10):
    """Capture a limited number of packets from the authorized interface."""

    print("Starting NetGuardian packet capture...")
    print(f"Capturing {packet_count} packets...")
    print("-" * 70)

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        count=packet_count,
        store=False
    )

    print("-" * 70)
    print("Packet capture completed.")
    print()
    print("Traffic Statistics")
    print("-" * 70)
    print(f"Total IP Packets : {traffic_stats['total_packets']}")
    print(f"Total Bytes      : {traffic_stats['total_bytes']}")
    print(f"TCP Packets      : {traffic_stats['TCP']}")
    print(f"UDP Packets      : {traffic_stats['UDP']}")
    print(f"ICMP Packets     : {traffic_stats['ICMP']}")
    print(f"Other IP Packets : {traffic_stats['OTHER']}")

    print()
    print("Traffic by Source IP")
    print("-" * 70)

    for ip_address, stats in device_traffic.items():
        print(
            f"IP: {ip_address} | "
            f"Packets Sent: {stats['packets']} | "
            f"Bytes Sent: {stats['bytes']}"
        )

    print()
    print("Top Talkers")
    print("-" * 70)

    sorted_devices = sorted(
        device_traffic.items(),
        key=lambda item: item[1]["bytes"],
        reverse=True
    )

    for position, (ip_address, stats) in enumerate(sorted_devices, start=1):
        print(
            f"{position}. {ip_address} | "
            f"Packets Sent: {stats['packets']} | "
            f"Bytes Sent: {stats['bytes']}"
        )

if __name__ == "__main__":
    start_capture()