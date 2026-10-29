import socket

ip_address = "192.168.8.102"

try:
    hostname = socket.gethostbyaddr(ip_address)[0]
    print(f"IP Address: {ip_address}")
    print(f"Hostname: {hostname}")

except socket.herror:
    print(f"IP Address: {ip_address}")
    print("Hostname: Not available")