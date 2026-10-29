
import os
import sys
import threading
import csv
import io
import time
import ipaddress
import logging

from pathlib import Path
from datetime import datetime

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Auto-detect virtual environment if launched via global python
venv_python = BASE_DIR / ".venv" / "Scripts" / "python.exe"
if not venv_python.exists():
    venv_python = BASE_DIR / ".venv" / "bin" / "python"

if (
    venv_python.exists()
    and Path(sys.executable).resolve() != venv_python.resolve()
):
    try:
        import flask, scapy, requests, dotenv, reportlab
    except ImportError:
        import subprocess
        proc = subprocess.run(
            [str(venv_python), str(BASE_DIR / "app.py")] + sys.argv[1:]
        )
        sys.exit(proc.returncode)

from dotenv import load_dotenv

load_dotenv()

from router.huawei_client import HuaweiRouterClient
from router.router_sync import sync_connected_wifi_devices
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


from flask import url_for
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    Response
)
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
from risk.risk_engine import (
    evaluate_device_risk,
    evaluate_all_devices,
    get_risk_level
)
from detection.behaviour_drift import check_behaviour_drift_for_device
from response.quarantine import quarantine_device, release_device
from response.router_quarantine import get_state as get_router_enforcement
from router import manual_mode
from capture.packet_capture import start_capture
import simulation.simulate_traffic as sim


# ---------------------------------------------------------
# Flask Application
# ---------------------------------------------------------

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "dashboard" / "templates"),
    static_folder=str(BASE_DIR / "dashboard" / "static")
)

app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=16384)
from router.control_api import controls
app.register_blueprint(controls)
from detection.security_api import security
app.register_blueprint(security)


@app.after_request
def local_dashboard_headers(response):
    response.headers['X-Frame-Options']='DENY'
    response.headers['Referrer-Policy']='same-origin'
    return response


@app.before_request
def protect_local_actions():
    """Reject cross-origin browser writes to the local control dashboard."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        from urllib.parse import urlsplit
        origin = request.headers.get("Origin")
        if request.headers.get("Sec-Fetch-Site") == "cross-site" or (
            origin and urlsplit(origin).netloc != request.host
        ):
            return jsonify(status="error", message="Cross-origin actions are not allowed."), 403


@app.context_processor
def safety_context():
    return {"protection_mode": manual_mode.get_mode(), "auto_quarantine": False}


@app.route("/api/health")
def api_health():
    from capture.packet_capture import get_capture_health, SCAPY_AVAILABLE
    from monitoring.engine import state
    return jsonify(protection_mode=manual_mode.get_mode(), auto_quarantine=False,
                   capture=get_capture_health(), scapy_available=SCAPY_AVAILABLE,
                   analytics=dict(state), target_network=config.TARGET_NETWORK)


@app.get('/threat-detection')
def threat_detection_page():
    return render_template('threat_detection.html')


@app.get('/viva-lab')
def viva_lab_page():
    return render_template('viva_lab.html')


@app.route("/api/analytics")
def api_analytics():
    conn = get_connection()
    try:
        # Real traffic only; no row limits or duplicate statistics-table counts.
        days = [dict(r) for r in conn.execute("""
            SELECT DATE(timestamp) AS day, SUM(packet_size) AS total_bytes
            FROM traffic WHERE COALESCE(is_simulated,0)=0
            GROUP BY DATE(timestamp) ORDER BY day DESC LIMIT 30
        """)][::-1]
        protocols = [dict(r) for r in conn.execute("""
            SELECT protocol, COUNT(*) AS total FROM traffic
            WHERE COALESCE(is_simulated,0)=0 GROUP BY protocol ORDER BY total DESC
        """)]
        severity = {r[0]: r[1] for r in conn.execute(
            "SELECT UPPER(severity), COUNT(*) FROM alerts GROUP BY UPPER(severity)")}
        risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for dev in get_verified_local_devices():
            risk[get_risk_level(dev["risk_score"] or 0)] += 1
        return jsonify(traffic_labels=[r["day"] for r in days], traffic_values=[r["total_bytes"] for r in days],
                       proto_labels=[r["protocol"] for r in protocols], proto_values=[r["total"] for r in protocols],
                       risk_values=[severity.get(s,0) for s in ("LOW","MEDIUM","HIGH","CRITICAL")],
                       device_risk_values=list(risk.values()))
    finally:
        conn.close()


# ---------------------------------------------------------
# Flask HTTP Access Log Filtering
# ---------------------------------------------------------

class DashboardPollingFilter(logging.Filter):
    """
    Hide successful routine dashboard API polling logs.

    Preserve:
    - HTTP errors
    - Non-dashboard requests
    - NetGuardian monitoring messages
    """

    QUIET_ENDPOINTS = (
        "/api/stats",
        "/api/devices",
        "/api/alerts",
        "/api/traffic"
    )

    def filter(self, record):
        message = record.getMessage()

        if (
            '"GET /api/' in message
            and '" 200 ' in message
            and any(
                f"GET {endpoint} " in message
                for endpoint in self.QUIET_ENDPOINTS
            )
        ):
            return False

        return True


werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.addFilter(DashboardPollingFilter())



# ---------------------------------------------------------
# Local Network Filtering
# ---------------------------------------------------------

def is_local_ip(ip_address):
    """Check whether an IP address belongs to the configured local network."""
    try:
        network = ipaddress.ip_network(
            config.TARGET_NETWORK,
            strict=False
        )
        return ipaddress.ip_address(ip_address) in network
    except (ValueError, TypeError):
        return False


# Historical/placeholder records remain untouched in SQLite.
INVALID_DEVICE_MACS = frozenset({
    "",
    "AUTO-CAPTURED",
    "UNKNOWN",
    "00:00:00:00:00:00"
})


def get_verified_local_devices():
    """Return local devices with a real recorded MAC identity."""
    devices = [
        device
        for device in get_all_devices()
        if is_local_ip(device.get("ip_address"))
        and str(
            device.get("mac_address") or ""
        ).strip().upper() not in INVALID_DEVICE_MACS
    ]

    for device in devices:
        device["router_enforcement"] = get_router_enforcement(device["id"])
    return devices


# ---------------------------------------------------------
# AI Alert Explanation
# ---------------------------------------------------------

@app.route("/alerts/<int:alert_id>/explain")
@app.route("/api/alerts/<int:alert_id>/explain")
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
            SELECT summary, recommendation, evidence_signature
            FROM ai_reports
            WHERE alert_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (alert_id,)
        ).fetchone()

        import hashlib
        evidence_signature=hashlib.sha256(str((alert['alert_type'],alert['severity'],alert['risk_score'],alert['description'],alert['ip_address'])).encode()).hexdigest()
        if existing and existing['evidence_signature']==evidence_signature:
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
                (alert_id, summary, recommendation, created_at, evidence_signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    summary,
                    recommendation,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),evidence_signature
                )
            )

            conn.commit()

        if request.path.startswith("/api/") or request.headers.get("Accept") == "application/json":
            return jsonify({
                "status": "success",
                "summary": summary,
                "recommendation": recommendation,
                "source": source,
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "ip_address": alert["ip_address"],
                "risk_score": alert["risk_score"]
            })

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
    """Current local device inventory, including genuinely offline hosts."""
    return render_template(
        "devices.html",
        devices=get_verified_local_devices()
    )


@app.route("/alerts")
def alerts_page():
    reset_id = get_alert_reset_id()
    conn = get_connection()

    try:
        alerts = conn.execute(
            """
            SELECT alerts.*, devices.ip_address
            FROM alerts
            LEFT JOIN devices ON alerts.device_id = devices.id
            WHERE alerts.id > ?
            ORDER BY alerts.timestamp DESC, alerts.id DESC
            """,
            (reset_id,)
        ).fetchall()
    finally:
        conn.close()

    return render_template("alerts.html", alerts=alerts)


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):

    allowed_statuses = {"open", "resolved", "ignored"}
    json_data = request.get_json(silent=True) or {}
    new_status = (request.form.get("status") or json_data.get("status") or "").strip().lower()
    new_status = request.form.get(
        "status", ""
    ).strip().lower()

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

    if request.is_json or request.headers.get("Accept") == "application/json" or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(status="success", message=f"Alert {alert_id} status updated to {new_status}.")
    return redirect("/alerts")


@app.route("/alerts/reset", methods=["POST"])
def reset_alerts():
    """Archive current alerts and hide them from active views."""

    conn = get_connection()

    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_reset_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_cleared_id INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        latest_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM alerts"
        ).fetchone()[0]

        conn.execute(
            """
            UPDATE alerts
            SET status = 'ignored'
            WHERE id <= ? AND status = 'open'
            """,
            (latest_id,)
        )

        conn.execute(
            """
            INSERT INTO alert_reset_state (id, last_cleared_id)
            VALUES (1, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_cleared_id = excluded.last_cleared_id
            """,
            (latest_id,)
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if request.is_json or request.headers.get("Accept") == "application/json" or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(status="success", message=f"Alert {alert_id} status updated to {new_status}.")
    return redirect("/alerts")


def get_alert_reset_id():
    """Return the ID of the last alert cleared."""

    conn = get_connection()

    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_reset_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_cleared_id INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        row = conn.execute(
            """
            SELECT last_cleared_id
            FROM alert_reset_state
            WHERE id = 1
            """
        ).fetchone()

        return row[0] if row else 0

    finally:
        conn.close()


# ---------------------------------------------------------
# Analytics
# ---------------------------------------------------------

@app.route("/analytics")
def analytics_page():
    return render_template("analytics.html", **api_analytics().get_json())


# ---------------------------------------------------------
# Reports
# ---------------------------------------------------------

@app.route("/reports")
def reports_page():
    """Display NetGuardian security report summary."""

    local_devices = get_verified_local_devices()

    total_devices = len(local_devices)

    unknown_devices = sum(
        1 for device in local_devices
        if not bool(device.get("trusted", 0))
    )

    highest_risk = max(
        (
            int(device.get("risk_score") or 0)
            for device in local_devices
        ),
        default=0
    )

    reset_id = get_alert_reset_id()

    conn = get_connection()

    try:
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        new_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE id > ?
            """,
            (reset_id,)
        ).fetchone()[0]

        active_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE id > ? AND status = ?
            """,
            (reset_id, "open")
        ).fetchone()[0]

        historical_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE id <= ?
            """,
            (reset_id,)
        ).fetchone()[0]

        traffic_rows = conn.execute(
            """
            SELECT
                devices.ip_address,
                COALESCE(SUM(traffic.packet_size), 0) AS total_bytes
            FROM devices
            JOIN traffic ON devices.id = traffic.device_id
            GROUP BY devices.id, devices.ip_address
            ORDER BY total_bytes DESC
            """
        ).fetchall()

        top_device = "No traffic recorded"

        for row in traffic_rows:
            if is_local_ip(row["ip_address"]):
                top_device = (
                    f"{row['ip_address']} "
                    f"({row['total_bytes']:,} bytes)"
                )
                break

    finally:
        conn.close()

    return render_template(
        "reports.html",
        total_devices=total_devices,
        total_alerts=total_alerts,
        new_alerts=new_alerts,
        active_alerts=active_alerts,
        historical_alerts=historical_alerts,
        unknown_devices=unknown_devices,
        highest_risk=highest_risk,
        top_device=top_device
    )


@app.route("/reports/alerts.csv")
def export_alerts_csv():

    conn = get_connection()

    try:
        alerts = conn.execute(
            """
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
            """
        ).fetchall()

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
            "Content-Disposition":
                "attachment; filename=netguardian_alerts.csv"
        }
    )


@app.route("/reports/report.pdf")
def export_security_pdf():
    """Create a PDF security report in memory."""

    buffer = io.BytesIO()

    conn = get_connection()

    try:
        local_devices = get_verified_local_devices()

        total_devices = len(local_devices)

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        open_alerts = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'open'
            """
        ).fetchone()[0]

        highest_risk = max(
            (
                int(device.get("risk_score") or 0)
                for device in local_devices
            ),
            default=0
        )

        alerts = conn.execute(
            """
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
            """
        ).fetchall()

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
        Paragraph(
            "NetGuardian - Security Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 12))

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    elements.append(
        Paragraph(
            f"Generated: {generated_at}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Network Security Overview",
            styles["Heading2"]
        )
    )

    summary_data = [
        ["Metric", "Value"],
        ["Total Devices", str(total_devices)],
        ["Total Alerts", str(total_alerts)],
        ["Open Alerts", str(open_alerts)],
        ["Highest Device Risk", f"{highest_risk}/100"]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[240, 160]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e293b")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
        ])
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 24))

    elements.append(
        Paragraph(
            "Recent Historical Security Alerts",
            styles["Heading2"]
        )
    )

    alert_data = [
        [
            "ID",
            "Device IP",
            "Alert Type",
            "Severity",
            "Risk",
            "Status"
        ]
    ]

    alert_data.extend(alert_rows)

    if not alert_rows:
        alert_data.append([
            "-", "No alerts", "-", "-", "-", "-"
        ])

    alerts_table = Table(
        alert_data,
        colWidths=[35, 95, 125, 75, 45, 75],
        repeatRows=1
    )

    alerts_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e293b")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [
                    colors.white,
                    colors.HexColor("#f1f5f9")
                ]
            )
        ])
    )

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


# ---------------------------------------------------------
# Main Dashboard
# ---------------------------------------------------------

@app.route("/")
def index():
    """Main NetGuardian Security Dashboard."""

    stats = get_network_stats()

    devices = get_verified_local_devices()

    reset_id = get_alert_reset_id()

    alerts = [
        alert
        for alert in get_recent_alerts(limit=1000)
        if alert["id"] > reset_id
        and is_local_ip(alert.get("ip_address"))
    ][:25]

    traffic = get_recent_traffic(limit=25)

    return render_template(
        "index.html",
        stats=stats,
        devices=devices,
        alerts=alerts,
        traffic=traffic,
        protection_mode=manual_mode.get_mode()
    )


# ---------------------------------------------------------
# Device Pages
# ---------------------------------------------------------

@app.route("/device/<int:device_id>/trust", methods=["POST"])
def update_device_trust(device_id):
    """Manually trust or untrust a known device."""

    trusted_value = request.form.get("trusted")

    if trusted_value not in ("0", "1"):
        return "Invalid trust value", 400

    conn = get_connection()

    try:
        existing = conn.execute(
            "SELECT id FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()

        if existing is None:
            return "Device not found", 404

        conn.execute(
            """
            UPDATE devices
            SET trusted = ?
            WHERE id = ?
            """,
            (int(trusted_value), device_id)
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    evaluate_device_risk(device_id, auto_quarantine=False)

    return redirect(
        url_for(
            "device_detail",
            device_id=device_id
        )
    )


@app.route("/device/<int:device_id>")
def device_detail(device_id):
    """Display device profile, traffic, risk and behavioral drift."""

    device = get_device_by_id(device_id)

    if not device:
        return "Device not found", 404

    drift = check_behaviour_drift_for_device(device_id)

    traffic = get_recent_traffic(
        limit=50,
        device_id=device_id
    )

    risk_lvl = get_risk_level(
        device.get("risk_score", 0)
    )

    return render_template(
        "device.html",
        device=device,
        drift=drift,
        traffic=traffic,
        risk_level=risk_lvl,
        quarantine_logs=get_device_quarantine_logs(device_id),
        router_enforcement=get_router_enforcement(device_id)
    )


def get_device_quarantine_logs(device_id):
    conn = get_connection()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM quarantine_logs WHERE device_id=? ORDER BY id DESC LIMIT 30", (device_id,))]
    finally:
        conn.close()


@app.route("/api/device/<int:device_id>/name", methods=["POST"])
def api_device_name(device_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("device_name"), str) or not 1 <= len(data["device_name"].strip()) <= 100:
        return jsonify(status="error", message="A device name of 1–100 characters is required."), 400
    conn = get_connection()
    try:
        result = conn.execute("UPDATE devices SET device_name=? WHERE id=?", (data["device_name"].strip(), device_id))
        if not result.rowcount:
            return jsonify(status="error", message="Device not found"), 404
        conn.commit()
        return jsonify(status="success", message="Device name updated.")
    finally:
        conn.close()


# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return live network statistics."""
    return jsonify(get_network_stats())


@app.route("/api/devices", methods=["GET"])
def api_devices():
    """Return verified local network devices."""
    return jsonify(get_verified_local_devices())


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Return local alerts created after the last reset."""

    reset_id = get_alert_reset_id()

    alerts = [
        alert
        for alert in get_recent_alerts(limit=1000)
        if alert["id"] > reset_id
        and is_local_ip(alert.get("ip_address"))
    ]

    return jsonify(alerts[:50])


@app.route("/api/traffic", methods=["GET"])
def api_traffic():
    """Return recent network traffic records."""
    return jsonify(get_recent_traffic(limit=50))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Trigger discovery without overlapping background scans."""

    try:
        discovered = run_discovery_safely()

        if discovered is None:
            return jsonify({
                "status": "busy",
                "message": "A discovery scan is already running."
            }), 409

        evaluate_all_devices(
            auto_quarantine=False
        )

        return jsonify({
            "status": "success",
            "count": len(discovered),
            "devices": discovered
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


@app.route(
    "/api/device/<int:device_id>/trust",
    methods=["POST"]
)
def api_toggle_trust(device_id):
    """Update trusted state for a device."""

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or type(data.get("trusted")) not in (bool, int) or data["trusted"] not in (0, 1):
        return jsonify(status="error", message="trusted must be a boolean or 0/1."), 400
    if get_device_by_id(device_id) is None:
        return jsonify(status="error", message="Device not found"), 404
    new_trusted = bool(data["trusted"])

    set_device_trusted(
        device_id,
        new_trusted
    )

    evaluate_device_risk(device_id)

    state_str = (
        "trusted"
        if new_trusted
        else "untrusted"
    )

    return jsonify({
        "status": "success",
        "message": f"Device marked as {state_str}."
    })


@app.route(
    "/api/device/<int:device_id>/quarantine",
    methods=["POST"]
)
def api_toggle_quarantine(device_id):
    """Manually quarantine or release a device."""

    if manual_mode.get_mode() == "LIVE":
        return jsonify(status="error", code="ADMIN_PLAN_REQUIRED", message="LIVE operations require an administrator session and a confirmed router quarantine plan."), 409

    managed=get_router_enforcement(device_id)
    if managed.get('has_ownership') and managed['state']!='RELEASED':
        return jsonify(status="error",code="LIVE_RELEASE_REQUIRED",message="This device has a managed LIVE quarantine. Use its administrator-confirmed router Release, available even in DEMO mode."),409

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("action") not in ("quarantine", "release"):
        return jsonify(status="error", message="action must be quarantine or release."), 400
    if get_device_by_id(device_id) is None:
        return jsonify(status="error", message="Device not found"), 404
    action = data["action"]

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

    return jsonify({
        "status": "success" if success else "error",
        "message": msg,
        "protection_mode": "DEMO",
        "enforced": False
    }), 200 if success else 409


@app.route(
    "/api/alerts/<int:alert_id>/resolve",
    methods=["POST"]
)
def api_resolve_alert(alert_id):
    """Mark an alert as resolved."""

    conn = get_connection()
    try:
        if conn.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone() is None:
            return jsonify(status="error", message="Alert not found"), 404
    finally:
        conn.close()
    resolve_alert(alert_id)

    return jsonify({
        "status": "success",
        "message": f"Alert {alert_id} resolved."
    })


@app.route(
    "/api/simulate/<attack_type>",
    methods=["POST"]
)
def api_simulate(attack_type):
    """Run isolated attack simulations."""

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
        return jsonify({
            "status": "error",
            "message": (
                f"Unknown attack type: {attack_type}"
            )
        }), 400

    return jsonify({
        "status": "success",
        "message": msg
    })


@app.route(
    "/api/simulate/history",
    methods=["GET"]
)
def api_simulation_history():
    """Return isolated demonstration events."""

    return jsonify({
        "status": "success",
        "simulation": True,
        "events": sim.get_simulation_history()
    })


# ---------------------------------------------------------
# Background Engine Tasks
# ---------------------------------------------------------

discovery_lock = threading.Lock()


def run_discovery_safely(full_sweep=True):
    """
    Run one discovery operation without overlap.

    Returns discovered devices or None if a scan
    is already running.
    """

    if not discovery_lock.acquire(blocking=False):
        print(
            "[LiveDiscovery] Scan skipped: "
            "another discovery operation is running.",
            flush=True
        )
        return None

    try:
        return discover_devices(
            full_sweep=full_sweep
        )

    finally:
        discovery_lock.release()


def background_device_monitor():
    """
    Perform periodic Scapy network discovery.

    Huawei-managed Wi-Fi devices retain authoritative
    online/offline status from the router API.
    """

    SCAN_INTERVAL = 60

    print(
        "[LiveDiscovery] Periodic Scapy monitor started.",
        flush=True
    )

    while not engine_stop.wait(SCAN_INTERVAL):

        started = time.monotonic()

        try:
            discovered = run_discovery_safely(
                full_sweep=True
            )

            if discovered is not None:
                elapsed = time.monotonic() - started

                print(
                    "[LiveDiscovery] Periodic scan completed. "
                    f"Observed: {len(discovered)} | "
                    f"Duration: {elapsed:.1f}s",
                    flush=True
                )

        except Exception as error:
            print(
                "[LiveDiscovery] Periodic scan ERROR: "
                f"{type(error).__name__}: {error}",
                flush=True
            )


def background_threat_monitor():
    """Evaluate device risk without automatic quarantine."""

    while not engine_stop.is_set():
        try:
            print(
                "[ThreatMonitor] Starting risk evaluation...",
                flush=True
            )

            result = evaluate_all_devices(
                auto_quarantine=False
            )

            print(
                "[ThreatMonitor] Risk evaluation completed: "
                f"{len(result)} devices",
                flush=True
            )

        except Exception as error:
            import traceback

            print(
                "[ThreatMonitor] ERROR: "
                f"{type(error).__name__}: {error}",
                flush=True
            )

            traceback.print_exc()

        engine_stop.wait(15)


# ---------------------------------------------------------
# Huawei Router Live Monitoring
# ---------------------------------------------------------

def background_huawei_monitor():
    """
    Monitor Huawei WLAN clients every two seconds.

    Two consecutive successful missing observations
    are required before setting a known Wi-Fi device
    Offline.

    Router and wired devices are not marked Offline
    by this monitor.
    """

    from router.router_sync import (
        sync_connected_wifi_devices,
        mark_disconnected_wifi_devices_offline,
        register_huawei_wifi_devices
    )

    username = os.getenv(
        "HUAWEI_ROUTER_USERNAME",
        "user"
    )

    password = os.getenv(
        "HUAWEI_ROUTER_PASSWORD"
    )

    if not password:
        print(
            "[HuaweiMonitor] Router password not configured.",
            flush=True
        )
        return

    client = None
    previous_macs = None

    observed_wifi_macs = set()
    missed_polls = {}

    print(
        "[HuaweiMonitor] Background monitoring started.",
        flush=True
    )

    while not engine_stop.is_set():
        try:
            if client is None:
                client = HuaweiRouterClient(
                    username=username,
                    password=password,
                    base_url=os.getenv("HUAWEI_ROUTER_URL", "http://192.168.8.1")
                )

                client.login()

                print(
                    "[HuaweiMonitor] Authentication successful.",
                    flush=True
                )

            started = time.perf_counter()

            # Only successful API responses change device
            # presence status.
            wifi_devices = client.get_connected_wifi_devices()

            # Record known Huawei Wi-Fi MAC identities.
            register_huawei_wifi_devices(wifi_devices)

            current_macs = {
                str(device["mac"]).upper()
                for device in wifi_devices
            }

            # Connected Wi-Fi devices become Online.
            sync_connected_wifi_devices(wifi_devices)

            observed_wifi_macs.update(current_macs)

            # Reset missed-poll counters for connected clients.
            for mac in current_macs:
                missed_polls[mac] = 0

            confirmed_disconnected = set()

            for mac in observed_wifi_macs - current_macs:
                missed_polls[mac] = (
                    missed_polls.get(mac, 0) + 1
                )

                if missed_polls[mac] == 2:
                    confirmed_disconnected.add(mac)

            if confirmed_disconnected:
                updated = mark_disconnected_wifi_devices_offline(
                    confirmed_disconnected
                )

                print(
                    "[HuaweiMonitor] Confirmed Offline: "
                    f"{len(confirmed_disconnected)} | "
                    f"Database rows updated: {updated}",
                    flush=True
                )

            elapsed = time.perf_counter() - started

            if current_macs != previous_macs:

                print(
                    "[HuaweiMonitor] Wi-Fi clients: "
                    f"{len(wifi_devices)} | "
                    f"API + sync: {elapsed:.3f}s",
                    flush=True
                )

                if previous_macs is not None:
                    joined = current_macs - previous_macs
                    left = previous_macs - current_macs

                    for mac in sorted(joined):
                        print(
                            f"[HuaweiMonitor] CONNECTED: {mac}",
                            flush=True
                        )

                    for mac in sorted(left):
                        print(
                            f"[HuaweiMonitor] DISCONNECTED: {mac}",
                            flush=True
                        )

                previous_macs = current_macs

        except Exception as error:

            print(
                "[HuaweiMonitor] ERROR: "
                f"{type(error).__name__}: {error}",
                flush=True
            )

            if client is not None:
                client.close()

            client = None

            # Failed API calls must not count as
            # missing-device observations.
            engine_stop.wait(10)
            continue

        engine_stop.wait(2)
    if client is not None:
        client.close()


# ---------------------------------------------------------
# Startup Initialization
# ---------------------------------------------------------

def _startup_initialization():
    """Initialize and start the NetGuardian monitoring engine."""

    print("=" * 60)
    print("Initializing NetGuardian Security System...")
    print("=" * 60)

    # 1. Initialize SQLite database.
    initialize_database()

    # A process that died without shutdown leaves an open capture session.
    # The process lock below ensures no active NetGuardian owns these rows.
    conn = get_connection()
    try:
        conn.execute("UPDATE capture_sessions_v2 SET ended_at=MAX(started_at, ?), end_reason='ERROR' WHERE ended_at IS NULL",
                     (datetime.now().isoformat(timespec="seconds"),))
        conn.commit()
    finally:
        conn.close()

    # 2. Seed demo data only for a fresh lab database.
    current_devs = get_all_devices()

    if config.SEED_DEMO_DEVICES and not current_devs:
        seed_demo_devices()

    # 3. Fast initial Scapy scan.
    # Huawei handles live Wi-Fi presence separately.
    try:
        discover_devices(
            full_sweep=False
        )

    except Exception as error:
        print(
            "[Init] Initial network discovery notice: "
            f"{error}",
            flush=True
        )

    # 4. Initial risk evaluation.
    # Never automatically quarantine devices.
    evaluate_all_devices(
        auto_quarantine=False
    )

    # 5. Start passive packet capture.
    try:
        start_capture()

    except Exception as error:
        print(
            f"[Init] Passive sniffer notice: {error}",
            flush=True
        )

    # 6. Start background threat monitoring.
    monitor_thread = threading.Thread(
        target=background_threat_monitor,
        name="NetGuardianThreatMonitor",
        daemon=True
    )

    monitor_thread.start()
    _engine_threads.append(monitor_thread)

    # 7. Start periodic Scapy monitoring.
    discovery_thread = threading.Thread(
        target=background_device_monitor,
        name="NetGuardianPeriodicDiscovery",
        daemon=True
    )

    discovery_thread.start()
    _engine_threads.append(discovery_thread)

    print(
        "[Init] Periodic Scapy discovery enabled.",
        flush=True
    )

    # 8. Start authenticated Huawei Wi-Fi monitoring.
    huawei_thread = threading.Thread(
        target=background_huawei_monitor,
        name="NetGuardianHuaweiMonitor",
        daemon=True
    )

    huawei_thread.start()
    _engine_threads.append(huawei_thread)

    from monitoring.engine import start_analytics_monitor
    start_analytics_monitor()

    print(
        "[Init] Huawei router monitoring " + ("enabled." if os.getenv("HUAWEI_ROUTER_PASSWORD") else "not configured."),
        flush=True
    )

    print(
        "\nNetGuardian startup complete. Check the dashboard capture status for live monitoring health."
    )

    print(
        f"Dashboard URL: "
        f"http://{config.SERVER_HOST}:{config.SERVER_PORT}\n"
    )


engine_stop = threading.Event()
_startup_lock = threading.Lock()
_started = False
_instance_handle = None
_engine_threads = []


def startup_initialization():
    """Start one engine instance, even if called twice by a launcher."""
    global _started, _instance_handle
    from database import db
    with _startup_lock:
        if _started:
            return
        if any(thread.is_alive() for thread in _engine_threads):
            raise RuntimeError("Previous monitoring workers are still shutting down")
        _engine_threads.clear()
        lock_path = Path(db.DB_PATH).with_suffix(".lock")
        handle = open(lock_path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                if not handle.read(1):
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise RuntimeError("Another NetGuardian monitoring engine is already running")
        _instance_handle = handle
        engine_stop.clear()
        try:
            _startup_initialization()
            _started = True
        except Exception:
            shutdown_engine()
            raise


def shutdown_engine():
    global _instance_handle, _started
    engine_stop.set()
    from capture.packet_capture import stop_capture
    from monitoring.engine import stop_analytics_monitor
    stop_analytics_monitor()
    stop_capture()
    for thread in _engine_threads:
        if thread is not threading.current_thread():
            thread.join(timeout=6)
    if _instance_handle:
        _instance_handle.close()
        _instance_handle = None
    _started = False


import atexit
atexit.register(shutdown_engine)


# ---------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------

if __name__ == "__main__":

    startup_initialization()

    app.run(
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=False,
        use_reloader=False
    )
