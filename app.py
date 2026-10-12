from flask import Flask, render_template, request, redirect
from database.db import get_connection

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static",
)


@app.route("/")
def dashboard():
    conn = get_connection()
    device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    max_risk = conn.execute("SELECT COALESCE(MAX(risk_score), 0) FROM alerts").fetchone()[0]
    latest = conn.execute(
        "SELECT alert_type, risk_score, severity, status, time FROM alerts ORDER BY id DESC LIMIT 5"
    ).fetchall()
    severity_counts = []
    for s in ["Low", "Medium", "High", "Critical"]:
        severity_counts.append(
            conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = ?", (s,)).fetchone()[0]
        )
    conn.close()

    if max_risk >= 80:
        risk_level = "Critical"
    elif max_risk >= 60:
        risk_level = "High"
    elif max_risk >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return render_template(
        "dashboard.html",
        device_count=device_count,
        alert_count=alert_count,
        risk_level=risk_level,
        latest=latest,
        severity_counts=severity_counts,
    )


@app.route("/devices")
def devices():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
    conn.close()
    return render_template("devices.html", devices=rows)


@app.route("/alerts")
def alerts():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT alerts.*, devices.ip_address
        FROM alerts JOIN devices ON alerts.device_id = devices.id
        ORDER BY alerts.id DESC
        """
    ).fetchall()
    conn.close()
    return render_template("alerts.html", alerts=rows)


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    status = request.form["status"]
    if status in ["New", "Investigating", "Resolved", "False Positive"]:
        conn = get_connection()
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        conn.commit()
        conn.close()
    return redirect("/alerts")

@app.route("/analytics")
def analytics():
    conn = get_connection()

    traffic_rows = conn.execute(
        "SELECT substr(timestamp, 1, 10) AS day, SUM(packet_size) AS total "
        "FROM traffic GROUP BY day ORDER BY day"
    ).fetchall()
    traffic_labels = [r["day"] for r in traffic_rows]
    traffic_values = [r["total"] for r in traffic_rows]

    proto_rows = conn.execute(
        "SELECT protocol, COUNT(*) AS c FROM traffic GROUP BY protocol ORDER BY c DESC"
    ).fetchall()
    proto_labels = [r["protocol"] for r in proto_rows]
    proto_values = [r["c"] for r in proto_rows]

    risk_values = []
    for s in ["Low", "Medium", "High", "Critical"]:
        risk_values.append(
            conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = ?", (s,)).fetchone()[0]
        )
    conn.close()

    return render_template(
        "analytics.html",
        traffic_labels=traffic_labels,
        traffic_values=traffic_values,
        proto_labels=proto_labels,
        proto_values=proto_values,
        risk_values=risk_values,
    )


if __name__ == "__main__":
    app.run(debug=True)