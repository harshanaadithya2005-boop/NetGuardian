import os
import sys
import threading
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

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


# ---------------------------------------------------------
# Web Dashboard HTML Routes
# ---------------------------------------------------------

@app.route("/")
def index():
    """Main NetGuardian Security Dashboard."""
    stats = get_network_stats()
    devices = get_all_devices()
    alerts = get_recent_alerts(limit=25)
    traffic = get_recent_traffic(limit=25)
    return render_template(
        "index.html",
        stats=stats,
        devices=devices,
        alerts=alerts,
        traffic=traffic
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
