ports = [21, 22, 23, 25, 53, 80, 443, 445]

def detect_port_scan(ports, threshold=8):
    unique_ports = set(ports)

    if len(unique_ports) >= threshold:
        return True

    return False
ports = [21, 22, 23, 25, 53, 80, 443, 445]

if detect_port_scan(ports):
    print("Possible Port Scan")

    {
    "source_ip": "192.168.1.20",
    "destination_port": 443,
    "protocol": "TCP"
}