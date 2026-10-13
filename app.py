from flask import Flask, render_template, request, redirect, Response
import csv
import io
from database.db import get_connection
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

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


if __name__ == "__main__":
    app.run(debug=True)