from database.db import get_connection


def create_alert(device_id, alert_type, risk_score, description=""):
    """Insert an alert. Severity is worked out from the risk score."""
    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 60:
        severity = "High"
    elif risk_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) "
        "VALUES (?, ?, ?, ?, ?, 'New', datetime('now'))",
        (device_id, alert_type, risk_score, severity, description),
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return alert_id