import sqlite3

connection = sqlite3.connect("netguardian.db")
connection.row_factory = sqlite3.Row

cursor = connection.cursor()

cursor.execute("SELECT * FROM devices")

devices = cursor.fetchall()

print("Devices currently stored in NetGuardian:")
print("-" * 60)

for device in devices:
    print(f"ID          : {device['id']}")
    print(f"IP Address  : {device['ip_address']}")
    print(f"MAC Address : {device['mac_address']}")
    print(f"Hostname    : {device['hostname']}")
    print(f"Device Name : {device['device_name']}")
    print(f"Device Type : {device['device_type']}")
    print(f"First Seen  : {device['first_seen']}")
    print(f"Last Seen   : {device['last_seen']}")
    print(f"Status      : {device['status']}")
    print(f"Trusted     : {device['trusted']}")
    print(f"Risk Score  : {device['risk_score']}")
    print("-" * 60)

connection.close()