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

conn.commit()
conn.close()
print("Sample data inserted.")