from database.db import get_connection
from database.models import add_or_update_device
from datetime import datetime

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Sample devices
add_or_update_device("192.168.8.101", "AA:BB:CC:DD:EE:11", "Office-PC", "Office-PC", "PC", now)
add_or_update_device("192.168.8.102", "AA:BB:CC:DD:EE:12", "Phone-01", "Phone-01", "Phone", now)
add_or_update_device("192.168.8.105", "AA:BB:CC:DD:EE:15", "Unknown", "Unknown", "Unknown", now)

conn = get_connection()
cur = conn.cursor()

# Sample alerts (only if none exist yet)
cur.execute("SELECT COUNT(*) FROM alerts")
if cur.fetchone()[0] == 0:
    dev = cur.execute("SELECT id FROM devices WHERE ip_address = '192.168.8.105'").fetchone()["id"]
    cur.execute(
        "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (dev, "Unknown Device", 40, "Medium", "A new unknown device joined the network.", "New", now),
    )
    cur.execute(
        "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (dev, "Traffic Spike", 60, "High", "Unusual traffic volume detected.", "New", now),
    )
# Sample traffic (only if none exist yet)
cur.execute("SELECT COUNT(*) FROM traffic")
if cur.fetchone()[0] == 0:
    from datetime import timedelta
    dev_id = cur.execute("SELECT id FROM devices ORDER BY id LIMIT 1").fetchone()["id"]
    protocols = ["HTTPS", "HTTPS", "HTTPS", "HTTPS", "HTTPS", "HTTPS", "HTTPS", "DNS", "DNS", "HTTP", "Other"]
    for i in range(60):
        ts = (datetime.now() - timedelta(days=i % 7)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO traffic (device_id, source_ip, destination_ip, protocol, packet_size, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (dev_id, "192.168.8.101", "8.8.8.8", protocols[i % len(protocols)], 200 + (i * 37) % 1200, ts),
        )
conn.commit()
conn.close()
print("Sample data inserted.")