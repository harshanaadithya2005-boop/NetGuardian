from scapy.all import get_if_list, get_if_addr

print("Scapy network interfaces:\n")

for interface in get_if_list():
    try:
        ip_address = get_if_addr(interface)
        print(f"{interface}  -->  {ip_address}")
    except Exception:
        print(f"{interface}  -->  Unable to determine IP")
