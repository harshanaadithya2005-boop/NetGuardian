import os
import sys
import threading
import csv
import io
import time
import ipaddress
from pathlib import Path
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Auto-detect virtual environment if launched via global python
venv_python = BASE_DIR / ".venv" / "Scripts" / "python.exe"
if not venv_python.exists():
    venv_python = BASE_DIR / ".venv" / "bin" / "python"

if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
    try:
        import flask
    except ImportError:
        import subprocess
        proc = subprocess.run([str(venv_python), str(BASE_DIR / "app.py")] + sys.argv[1:])
        sys.exit(proc.returncode)

from flask import Flask, render_template, request, jsonify, redirect, Response
from datetime import datetime
from database.db import get_connection
from ai.ai_engine import explain_alert

import config
from database.db import initialize_database
from database.models import (
    get_all_devices,
    get_device_by_id,
    get_recent_alerts,
    get_recent_traffic,
    get_network_stats,
    set_device_trusted,
    resolve_alert
)
from discovery.device_discovery import discover_devices, seed_demo_devices
from risk.risk_engine import evaluate_device_risk, evaluate_all_devices, get_risk_level
from detection.behaviour_drift import check_behaviour_drift_for_device
from response.quarantine import quarantine_device, release_device
from capture.packet_capture import start_capture
import simulation.simulate_traffic as sim

# Initialize Flask application with proper templates and static directories
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "dashboard" / "templates"),
    static_folder=str(BASE_DIR / "dashboard" / "static")
)
app.secret_key = config.SECRET_KEY

def is_local_ip(ip_address):
    """Check whether an IP address belongs to the configured local network."""
    try:
        network = ipaddress.ip_network(config.TARGET_NETWORK, strict=False)
        return ipaddress.ip_address(ip_address) in network
    except (ValueError, TypeError):
        return False


@app.route("/alerts/<int:alert_id>/explain")
def explain(alert_id):
    """Generate or retrieve an AI explanation for a security alert."""

    conn = get_connection()

    try:
        alert = conn.execute(
            """
            SELECT alerts.*, devices.ip_address
            FROM alerts
            JOIN devices ON alerts.device_id = devices.id
            WHERE alerts.id = ?
            """,
            (alert_id,)
        ).fetchone()

        if alert is None:
            return "Alert not found", 404

        existing = conn.execute(
            """
            SELECT summary, recommendation
            FROM ai_reports
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (alert_id,)
        ).fetchone()

        if existing:
            summary = existing["summary"]
            recommendation = existing["recommendation"]
            source = "Saved"
        else:
            summary, recommendation, source = explain_alert(
                alert["alert_type"],
                alert["severity"],
                alert["risk_score"],
                alert["description"],
                alert["ip_address"]
            )

            conn.execute(
                """
                INSERT INTO ai_reports
                (alert_id, summary, recommendation, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    alert_id,
                    summary,
                    recommendation,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )

            conn.commit()

        return render_template(
            "explain.html",
            alert=alert,
            summary=summary,
            recommendation=recommendation,
            source=source
        )

    finally:
        conn.close()


# ---------------------------------------------------------
# Web Dashboard HTML Routes
# ---------------------------------------------------------

@app.route("/devices")
def devices_page():
    devices = get_all_devices()
    return render_template("devices.html", devices=devices)


@app.route("/alerts")
def alerts_page():
    conn = get_connection()
    try:
        alerts = conn.execute("""
            SELECT
                alerts.*,
                devices.ip_address
            FROM alerts
            LEFT JOIN devices
                ON alerts.device_id = devices.id
            ORDER BY alerts.timestamp DESC, alerts.id DESC
        """).fetchall()
    finally:
        conn.close()

    return render_template("alerts.html", alerts=alerts)



@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):

    allowed_statuses = {"open", "resolved", "ignored"}
    new_status = request.form.get("status", "").strip().lower()

    if new_status not in allowed_statuses:
        return "Invalid alert status", 400

    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

        if existing is None:
            return "Alert not found", 404

        conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (new_status, alert_id)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect("/alerts")


@app.route("/analytics")
def analytics_page():
    conn = get_connection()

    try:
        # 1. Daily network traffic usage
        traffic_rows = conn.execute("""
            SELECT
                DATE(timestamp) AS day,
                SUM(packet_size) AS total_bytes
            FROM traffic
            GROUP BY DATE(timestamp)
            ORDER BY day ASC
        """).fetchall()

        traffic_labels = [row["day"] for row in traffic_rows]
        traffic_values = [row["total_bytes"] for row in traffic_rows]

        # 2. Network protocol distribution
        protocol_rows = conn.execute("""
            SELECT
                protocol,
                COUNT(*) AS total
            FROM traffic
            GROUP BY protocol
            ORDER BY total DESC
        """).fetchall()

        proto_labels = [row["protocol"] for row in protocol_rows]
        proto_values = [row["total"] for row in protocol_rows]

        # 3. Alert severity distribution
        risk_rows = conn.execute("""
            SELECT
                UPPER(severity) AS severity,
                COUNT(*) AS total
            FROM alerts
            GROUP BY UPPER(severity)
        """).fetchall()

        risk_counts = {
            row["severity"]: row["total"]
            for row in risk_rows
        }

        risk_values = [
            risk_counts.get("LOW", 0),
            risk_counts.get("MEDIUM", 0),
            risk_counts.get("HIGH", 0),
            risk_counts.get("CRITICAL", 0)
        ]

    finally:
        conn.close()

    return render_template(
        "analytics.html",
        traffic_labels=traffic_labels,
        traffic_values=traffic_values,
        proto_labels=proto_labels,
        proto_values=proto_values,
        risk_values=risk_values
    )


@app.route("/reports")
def reports_page():
    conn = get_connection()

    try:
        # Total registered devices
        total_devices = conn.execute(
            "SELECT COUNT(*) FROM devices"
        ).fetchone()[0]

        # Total security alerts
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        # Devices not marked as trusted
        unknown_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE trusted = 0"
        ).fetchone()[0]

        # Highest recorded device risk score
        highest_risk = conn.execute(
            "SELECT COALESCE(MAX(risk_score), 0) FROM devices"
        ).fetchone()[0]

        # Device with the most recorded traffic
        top_device_row = conn.execute("""
            SELECT
                devices.ip_address,
                COALESCE(SUM(traffic.packet_size), 0) AS total_bytes
            FROM devices
            JOIN traffic
                ON devices.id = traffic.device_id
            GROUP BY devices.id, devices.ip_address
            ORDER BY total_bytes DESC
            LIMIT 1
        """).fetchone()

        if top_device_row:
            top_device = (
                f"{top_device_row['ip_address']} "
                f"({top_device_row['total_bytes']:,} bytes)"
            )
        else:
            top_device = "No traffic recorded"

    finally:
        conn.close()

    return render_template(
        "reports.html",
        total_devices=total_devices,
        total_alerts=total_alerts,
        unknown_devices=unknown_devices,
        highest_risk=highest_risk,
        top_device=top_device
    )


@app.route("/reports/alerts.csv")
def export_alerts_csv():
    conn = get_connection()

    try:
        alerts = conn.execute("""
            SELECT
                alerts.id,
                devices.ip_address,
                alerts.alert_type,
                alerts.risk_score,
                alerts.severity,
                alerts.description,
                alerts.status,
                alerts.timestamp
            FROM alerts
            LEFT JOIN devices
                ON alerts.device_id = devices.id
            ORDER BY alerts.timestamp DESC, alerts.id DESC
        """).fetchall()
    finally:
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Alert ID",
        "Device IP",
        "Alert Type",
        "Risk Score",
        "Severity",
        "Description",
        "Status",
        "Timestamp"
    ])

    for alert in alerts:
        writer.writerow([
            alert["id"],
            alert["ip_address"],
            alert["alert_type"],
            alert["risk_score"],
            alert["severity"],
            alert["description"],
            alert["status"],
            alert["timestamp"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=netguardian_alerts.csv"
        }
    )


@app.route("/reports/report.pdf")
def export_security_pdf():
    # Create the PDF in memory without modifying the database
    buffer = io.BytesIO()

    conn = get_connection()
    try:
        total_devices = conn.execute(
            "SELECT COUNT(*) FROM devices"
        ).fetchone()[0]

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
        ).fetchone()[0]

        highest_risk = conn.execute(
            "SELECT COALESCE(MAX(risk_score), 0) FROM devices"
        ).fetchone()[0]

        alerts = conn.execute("""
            SELECT
                alerts.id,
                devices.ip_address,
                alerts.alert_type,
                alerts.severity,
                alerts.risk_score,
                alerts.status,
                alerts.timestamp
            FROM alerts
            LEFT JOIN devices
                ON alerts.device_id = devices.id
            ORDER BY alerts.timestamp DESC, alerts.id DESC
            LIMIT 20
        """).fetchall()

        # Convert database rows into plain values before closing
        alert_rows = [
            [
                str(a["id"]),
                str(a["ip_address"] or "Unknown"),
                str(a["alert_type"]),
                str(a["severity"]),
                str(a["risk_score"]),
                str(a["status"])
            ]
            for a in alerts
        ]
    finally:
        conn.close()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph("NetGuardian - Security Report", styles["Title"])
    )

    elements.append(Spacer(1, 12))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(
        Paragraph(f"Generated: {generated_at}", styles["Normal"])
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph("Network Security Overview", styles["Heading2"])
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Devices", str(total_devices)],
        ["Total Alerts", str(total_alerts)],
        ["Open Alerts", str(open_alerts)],
        ["Highest Device Risk", f"{highest_risk}/100"]
    ]

    summary_table = Table(summary_data, colWidths=[240, 160])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 24))

    elements.append(
        Paragraph("Recent Security Alerts", styles["Heading2"])
    )

    alert_data = [
        ["ID", "Device IP", "Alert Type", "Severity", "Risk", "Status"]
    ]

    alert_data.extend(alert_rows)

    if not alert_rows:
        alert_data.append(["-", "No alerts", "-", "-", "-", "-"])

    alerts_table = Table(
        alert_data,
        colWidths=[35, 95, 125, 75, 45, 75],
        repeatRows=1
    )

    alerts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f1f5f9")])
    ]))

    elements.append(alerts_table)

    doc.build(elements)
    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                "attachment; filename=NetGuardian_Security_Report.pdf"
        }
    )



@app.route("/")
def index():
    """Main NetGuardian Security Dashboard."""
    stats = get_network_stats()


    devices = [
        device for device in get_all_devices()
        if is_local_ip(device.get("ip_address"))
    ]
    alerts = [
        alert for alert in get_recent_alerts(limit=1000)
        if is_local_ip(alert.get("ip_address"))
    ][:25]
    traffic = get_recent_traffic(limit=25)

    return render_template(
        "index.html",
        stats=stats,
        devices=devices,
        alerts=alerts,
        traffic=traffic,
        protection_mode=config.PROTECTION_MODE
    )


@app.route("/device/<int:device_id>")
def device_detail(device_id):
    """Detailed host view: profile, behavioral drift, traffic history, and quarantine."""
    device = get_device_by_id(device_id)
    if not device:
        return "Device not found", 404

    drift = check_behaviour_drift_for_device(device_id)
    traffic = get_recent_traffic(limit=50, device_id=device_id)
    risk_lvl = get_risk_level(device.get("risk_score", 0))

    return render_template(
        "device.html",
        device=device,
        drift=drift,
        traffic=traffic,
        risk_level=risk_lvl
    )


# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return live network stats for real-time dashboard updating."""
    return jsonify(get_network_stats())


@app.route("/api/devices", methods=["GET"])
def api_devices():
    """Return all discovered devices."""
    return jsonify(get_all_devices())


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Return recent security alerts."""
    return jsonify(get_recent_alerts(limit=50))


@app.route("/api/traffic", methods=["GET"])
def api_traffic():
    """Return recent network flows."""
    return jsonify(get_recent_traffic(limit=50))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Trigger on-demand network device discovery."""
    discovered = discover_devices()
    evaluate_all_devices()
    return jsonify({
        "status": "success",
        "count": len(discovered),
        "devices": discovered
    })


@app.route("/api/device/<int:device_id>/trust", methods=["POST"])
def api_toggle_trust(device_id):
    """Update trusted state for a device."""
    data = request.get_json() or {}
    new_trusted = bool(data.get("trusted", 1))
    set_device_trusted(device_id, new_trusted)
    evaluate_device_risk(device_id)
    state_str = "trusted" if new_trusted else "untrusted"
    return jsonify({
        "status": "success",
        "message": f"Device marked as {state_str}."
    })


@app.route("/api/device/<int:device_id>/quarantine", methods=["POST"])
def api_toggle_quarantine(device_id):
    """Manually quarantine or release a device."""
    data = request.get_json() or {}
    action = data.get("action", "quarantine")

    if action == "quarantine":
        success, msg = quarantine_device(
            device_id=device_id,
            reason="Manual Administrator Action",
            performed_by="Dashboard Administrator"
        )
    else:
        success, msg = release_device(
            device_id=device_id,
            performed_by="Dashboard Administrator"
        )

    return jsonify({"status": "success" if success else "error", "message": msg})


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def api_resolve_alert(alert_id):
    """Mark an alert as resolved."""
    resolve_alert(alert_id)
    return jsonify({"status": "success", "message": f"Alert {alert_id} resolved."})


@app.route("/api/simulate/<attack_type>", methods=["POST"])
def api_simulate(attack_type):
    """Execute controlled attack simulations to demonstrate NetGuardian response."""
    msg = ""
    if attack_type == "port_scan":
        msg = sim.simulate_port_scan()
    elif attack_type == "dns_anomaly":
        msg = sim.simulate_dns_anomaly()
    elif attack_type == "traffic_spike":
        msg = sim.simulate_traffic_spike()
    elif attack_type == "rogue_device":
        msg = sim.simulate_unknown_rogue_device()
    elif attack_type == "critical_attack":
        msg = sim.simulate_critical_incident()
    elif attack_type == "reset":
        msg = sim.reset_simulation()
    else:
        return jsonify({"status": "error", "message": f"Unknown attack type: {attack_type}"}), 400

    return jsonify({"status": "success", "message": msg})


# ---------------------------------------------------------
# Background Engine Tasks
# ---------------------------------------------------------

def background_threat_monitor():
    """Periodically evaluate network device risk scores and maintain detection state."""
    while True:
        try:
            evaluate_all_devices(auto_quarantine=True)
        except Exception:
            pass
        time.sleep(15)


def startup_initialization():
    """Initialize system, populate seed devices, run discovery and start threads."""
    print("=" * 60)
    print("Initializing NetGuardian Security System...")
    print("=" * 60)

    # 1. Initialize SQLite Database Tables
    initialize_database()

    # 2. Seed standard lab devices if database has < 3 devices
    current_devs = get_all_devices()
    if len(current_devs) < 3:
        seed_demo_devices()

    # 3. Perform initial network discovery
    try:
        discover_devices()
    except Exception as e:
        print(f"[Init] Initial network discovery notice: {e}")

    # 4. Evaluate initial risk states
    evaluate_all_devices()

    # 5. Start passive traffic sniffer in background
    try:
        start_capture()
    except Exception as e:
        print(f"[Init] Passive sniffer notice: {e}")

    # 6. Start background risk monitor
    monitor_thread = threading.Thread(target=background_threat_monitor, daemon=True)
    monitor_thread.start()

    print("\nNetGuardian Security Engine is fully initialized and operational!")
    print(f"Dashboard URL: http://{config.SERVER_HOST}:{config.SERVER_PORT}\n")


if __name__ == "__main__":
    startup_initialization()
    app.run(
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=False
    )
