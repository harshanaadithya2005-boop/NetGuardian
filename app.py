from flask import Flask, render_template, request, redirect, Response
import csv
import io
import random
from database.db import get_connection
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from ai.ai_engine import explain_alert
from flask import Flask, render_template, request, redirect, Response, jsonify

app = Flask(
    __name__,
    template_folder="dashboard/templates",
    static_folder="dashboard/static",
)


@app.route("/")
def dashboard():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'").fetchone()[0]
    quarantined = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'quarantined'").fetchone()[0]
    open_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE status IN ('New', 'Investigating')"
    ).fetchone()[0]
    high_risk = conn.execute("SELECT COUNT(*) FROM devices WHERE risk_score >= 70").fetchone()[0]

    devices = conn.execute(
        "SELECT * FROM devices ORDER BY risk_score DESC, id LIMIT 50"
    ).fetchall()
    feed = conn.execute(
        "SELECT alerts.*, devices.ip_address, devices.hostname FROM alerts "
        "JOIN devices ON alerts.device_id = devices.id ORDER BY alerts.id DESC LIMIT 25"
    ).fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        total=total, online=online, quarantined=quarantined,
        open_alerts=open_alerts, high_risk=high_risk,
        devices=devices, feed=feed,
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

@app.route("/reports")
def reports():
    conn = get_connection()
    total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unknown_devices = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE hostname = 'Unknown' OR device_type = 'Unknown'"
    ).fetchone()[0]
    highest_risk = conn.execute("SELECT COALESCE(MAX(risk_score), 0) FROM alerts").fetchone()[0]
    top = conn.execute(
        "SELECT devices.hostname, COUNT(*) AS c FROM traffic "
        "JOIN devices ON traffic.device_id = devices.id "
        "GROUP BY devices.id ORDER BY c DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return render_template(
        "reports.html",
        total_devices=total_devices,
        total_alerts=total_alerts,
        unknown_devices=unknown_devices,
        highest_risk=highest_risk,
        top_device=top["hostname"] if top else "N/A",
    )


@app.route("/reports/alerts.csv")
def alerts_csv():
    conn = get_connection()
    rows = conn.execute(
        "SELECT alerts.id, devices.ip_address, alerts.alert_type, alerts.risk_score, "
        "alerts.severity, alerts.status, alerts.time "
        "FROM alerts JOIN devices ON alerts.device_id = devices.id ORDER BY alerts.id"
    ).fetchall()
    conn.close()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Device IP", "Type", "Risk", "Severity", "Status", "Time"])
    for r in rows:
        writer.writerow(list(r))

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_report.csv"},
    )
@app.route("/reports/report.pdf")
def report_pdf():
    conn = get_connection()
    total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    highest_risk = conn.execute("SELECT COALESCE(MAX(risk_score), 0) FROM alerts").fetchone()[0]
    rows = conn.execute(
        "SELECT devices.ip_address, alerts.alert_type, alerts.risk_score, "
        "alerts.severity, alerts.status, alerts.time "
        "FROM alerts JOIN devices ON alerts.device_id = devices.id ORDER BY alerts.id DESC"
    ).fetchall()
    conn.close()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("NetGuardian Report", styles["Title"]),
        Paragraph(f"Devices: {total_devices} &nbsp;&nbsp; Alerts: {total_alerts} &nbsp;&nbsp; Highest Risk: {highest_risk}", styles["Normal"]),
        Spacer(1, 16),
    ]
    data = [["Device IP", "Type", "Risk", "Severity", "Status", "Time"]]
    for r in rows:
        data.append([r["ip_address"], r["alert_type"], str(r["risk_score"]), r["severity"], r["status"], r["time"]])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(table)
    doc.build(story)

    return Response(
        buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netguardian_report.pdf"},
    )

@app.route("/alerts/<int:alert_id>/explain")
def explain(alert_id):
    conn = get_connection()
    alert = conn.execute(
        "SELECT alerts.*, devices.ip_address FROM alerts "
        "JOIN devices ON alerts.device_id = devices.id WHERE alerts.id = ?",
        (alert_id,),
    ).fetchone()
    if alert is None:
        conn.close()
        return "Alert not found", 404

    existing = conn.execute(
        "SELECT summary, recommendation FROM ai_reports WHERE alert_id = ? ORDER BY id DESC LIMIT 1",
        (alert_id,),
    ).fetchone()

    if existing:
        summary, recommendation, source = existing["summary"], existing["recommendation"], "Saved"
    else:
        summary, recommendation, source = explain_alert(
            alert["alert_type"], alert["severity"], alert["risk_score"],
            alert["description"], alert["ip_address"],
        )
        conn.execute(
            "INSERT INTO ai_reports (alert_id, summary, recommendation, created_at) VALUES (?, ?, ?, ?)",
            (alert_id, summary, recommendation, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
    conn.close()
    return render_template(
        "explain.html", alert=alert, summary=summary, recommendation=recommendation, source=source
    )
@app.route("/api/alerts/latest")
def api_latest_alert():
    conn = get_connection()
    row = conn.execute(
        "SELECT alerts.id, alerts.alert_type, alerts.severity, devices.ip_address "
        "FROM alerts JOIN devices ON alerts.device_id = devices.id "
        "ORDER BY alerts.id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"id": 0})
    return jsonify(dict(row))

def _alert(conn, device_id, alert_type, score, description):
    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    else:
        severity = "Medium"
    conn.execute(
        "INSERT INTO alerts (device_id, alert_type, risk_score, severity, description, status, time) "
        "VALUES (?, ?, ?, ?, ?, 'New', datetime('now', 'localtime'))",
        (device_id, alert_type, score, severity, description),
    )


def _bump(conn, device_id, amount):
    conn.execute(
        "UPDATE devices SET risk_score = MIN(100, risk_score + ?) WHERE id = ?",
        (amount, device_id),
    )
    row = conn.execute("SELECT risk_score FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row["risk_score"] >= 70:
        conn.execute("UPDATE devices SET status = 'quarantined' WHERE id = ?", (device_id,))


@app.route("/simulate/<kind>", methods=["POST"])
def simulate(kind):
    conn = get_connection()
    dev = conn.execute(
        "SELECT * FROM devices WHERE status != 'quarantined' ORDER BY RANDOM() LIMIT 1"
    ).fetchone()
    if dev is None:
        conn.close()
        return redirect("/")

    ip = dev["ip_address"]
    if kind == "portscan":
        _alert(conn, dev["id"], "Port Scan", 65, f"{ip} probed many ports.")
        _bump(conn, dev["id"], 30)
    elif kind == "dns":
        _alert(conn, dev["id"], "DNS Anomaly", 40, f"{ip} made unusual DNS requests.")
        _bump(conn, dev["id"], 20)
    elif kind == "spike":
        _alert(conn, dev["id"], "Traffic Spike", 60, f"{ip} traffic far above normal.")
        _bump(conn, dev["id"], 30)
    elif kind == "rogue":
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        n = random.randint(200, 250)
        mac = ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))
        conn.execute(
            "INSERT OR IGNORE INTO devices (ip_address, mac_address, hostname, device_name, "
            "device_type, first_seen, last_seen, status, trusted, risk_score) "
            "VALUES (?, ?, ?, ?, 'Unknown', ?, ?, 'online', 0, 20)",
            (f"172.16.0.{n}", mac, f"Rogue-{n}", f"Rogue-{n}", now, now),
        )
        rogue = conn.execute(
            "SELECT id FROM devices WHERE ip_address = ?", (f"172.16.0.{n}",)
        ).fetchone()
        _alert(conn, rogue["id"], "Rogue Device", 85, f"Unknown device 172.16.0.{n} joined the network.")
    elif kind == "full":
        _alert(conn, dev["id"], "Port Scan", 65, f"{ip} probed many ports.")
        _alert(conn, dev["id"], "Traffic Spike", 60, f"{ip} traffic far above normal.")
        _bump(conn, dev["id"], 80)
    conn.commit()
    conn.close()
    return redirect("/")


@app.route("/simulate/reset", methods=["POST"])
def simulate_reset():
    conn = get_connection()
    conn.execute("UPDATE devices SET risk_score = 0, status = 'online' WHERE status = 'quarantined' OR risk_score > 0")
    conn.execute("DELETE FROM ai_reports")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return redirect("/")


@app.route("/devices/<int:device_id>/quarantine", methods=["POST"])
def quarantine(device_id):
    conn = get_connection()
    conn.execute("UPDATE devices SET status = 'quarantined' WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return redirect("/")


@app.route("/devices/<int:device_id>/release", methods=["POST"])
def release(device_id):
    conn = get_connection()
    conn.execute("UPDATE devices SET status = 'online', risk_score = 0 WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)