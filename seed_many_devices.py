import random
from datetime import datetime, timedelta
from database.db import get_connection

random.seed(7)
conn = get_connection()
cur = conn.cursor()

TYPES = ["IoT Device", "Laptop", "Phone", "Server", "Printer", "Router", "Smart TV", "Camera"]
STATUSES = ["online"] * 8 + ["offline"] * 2

def stamp(minutes_ago=0):
    return (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")

def rand_mac():
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))

# --- Devices ---
added = 0
for i in range(1, 201):
    ip = f"10.193.201.{i}" if i <= 150 else f"192.168.8.{i - 100}"
    exists = cur.execute("SELECT 1 FROM devices WHERE ip_address = ?", (ip,)).fetchone()
    if exists:
        continue
    risk = random.choice([0, 0, 5, 10, 15, 20, 35, 45, 60, 70, 85])
    trusted = 1 if risk <= 10 and random.random() < 0.6 else 0
    status = random.choice(STATUSES)
    if risk >= 70 and random.random() < 0.4:
        status = "quarantined"
    cur.execute(
        "INSERT INTO devices (ip_address, mac_address, hostname, device_name, device_type, "
        "first_seen, last_seen, status, trusted, risk_score) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (ip, rand_mac(), f"Host-{i}", f"Device-{i}", random.choice(TYPES),
         stamp(random.randint(60, 5000)), stamp(random.randint(0, 60)), status, trusted, risk),
    )
    added += 1

# --- Alerts for risky devices ---
ALERT_TYPES = [
    ("Unknown Device", "Medium", 35),
    ("Port Scan", "High", 65),
    ("DNS Anomaly", "Medium", 40),
    ("Traffic Spike", "High", 60),
    ("Rogue Device", "Critical", 85),
]
risky = cur.execute("SELECT id, ip_address FROM devices WHERE risk_score >= 30").fetchall()
for d in risky[:60]:
    a_type, sev, score = random.choice(ALERT_TYPES)
    cur.execute(
        "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) "
        "VALUES (?,?,?,?,?,?,?)",
        (d["id"], a_type, score, sev, f"Device {d['ip_address']} triggered {a_type}.", "New",
         stamp(random.randint(0, 300))),
    )

conn.commit()
conn.close()
print(f"Added {added} devices and alerts for risky ones.")
