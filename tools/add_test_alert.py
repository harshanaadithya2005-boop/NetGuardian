from database.db import get_connection

conn = get_connection()
conn.execute(
    "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) "
    "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
    (1, "Unknown Device", 35, "Medium", "Test alert", "New"),
)
conn.commit()
conn.close()
print("Test alert added.")