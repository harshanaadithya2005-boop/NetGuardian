import sys
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import config
from database.models import (
    get_all_devices,
    get_device_by_id,
    get_recent_traffic,
    update_device_risk,
    create_alert
)
from detection.unknown_device import check_unknown_device
from detection.port_scan import check_port_scan
from detection.dns_anomaly import check_dns_anomaly
from detection.behaviour_drift import check_behaviour_drift_for_device
from response.quarantine import quarantine_device

# Risk Scoring Weights (Proposal Section 8.3)
RISK_SCORES = config.RISK_WEIGHTS


def calculate_risk(detections):
    """
    Original function from Member 2:
    Sum the fixed weights of all detected indicators, capped at 100.
    """
    score = 0
    for detection in detections:
        score += RISK_SCORES.get(detection, 0)
    return min(score, 100)


def get_risk_level(score):
    """
    Original function from Member 2 updated to match Proposal Section 8.3:
    - 0-39: LOW (Green - Normal)
    - 40-69: MEDIUM (Amber - Suspicious)
    - 70-100: HIGH (Red - Critical)
    """
    if score < config.RISK_THRESHOLD_MEDIUM:
        return "LOW"
    elif score < config.RISK_THRESHOLD_HIGH:
        return "MEDIUM"
    else:
        return "HIGH"


def evaluate_device_risk(device_or_id, auto_quarantine=True):
    """
    Complete detection-to-response pipeline for a device:
    1. Fetch device info and recent network traffic.
    2. Run all detection modules (Unknown Device, Port Scan, DNS Anomaly, Behaviour Drift, Traffic Spike).
    3. Calculate total risk score (0-100) and risk level.
    4. Persist updated score in database.
    5. Generate alerts for newly triggered detections.
    6. If risk score >= 70, automatically trigger quarantine response.
    """
    if isinstance(device_or_id, dict):
        device = device_or_id
    else:
        device = get_device_by_id(device_or_id)

    if not device:
        return None

    device_id = device["id"]
    ip_address = device["ip_address"]
    trusted = bool(device.get("trusted", 0))
    current_status = device.get("status", "online")

    # Fetch recent traffic associated with this device
    traffic = get_recent_traffic(limit=100, device_id=device_id)

    active_indicators = []
    detection_results = []

    # 1. Unknown Device Detection (if device is untrusted)
    if not trusted:
        res_unknown = check_unknown_device(ip_address)
        if res_unknown.get("detected"):
            active_indicators.append("unknown_device")
            detection_results.append(res_unknown)
            create_alert(
                device_id=device_id,
                alert_type="unknown_device",
                risk_score=config.RISK_WEIGHTS.get("unknown_device", 20),
                severity="MEDIUM",
                description=f"Device {ip_address} is untrusted/unknown on the network."
            )

    # 2. Port Scan Detection
    res_port = check_port_scan(traffic, source_ip=ip_address)
    if res_port.get("detected"):
        active_indicators.append("port_scan")
        detection_results.append(res_port)
        create_alert(
            device_id=device_id,
            alert_type="port_scan",
            risk_score=config.RISK_WEIGHTS.get("port_scan", 30),
            severity="HIGH",
            description=f"Port scan from {ip_address}: {res_port.get('unique_ports_count')} distinct destination ports."
        )

    # 3. DNS Anomaly Detection
    res_dns = check_dns_anomaly(traffic, source_ip=ip_address)
    if res_dns.get("detected"):
        active_indicators.append("dns_anomaly")
        detection_results.append(res_dns)
        create_alert(
            device_id=device_id,
            alert_type="dns_anomaly",
            risk_score=config.RISK_WEIGHTS.get("dns_anomaly", 20),
            severity="MEDIUM",
            description=f"DNS Anomaly on {ip_address}: {res_dns.get('message')}."
        )

    # 4. Behaviour Drift & Traffic Spike Detection
    res_drift = check_behaviour_drift_for_device(device_id, recent_traffic=traffic)
    if res_drift.get("detected"):
        if res_drift.get("traffic_spike"):
            active_indicators.append("traffic_spike")
            create_alert(
                device_id=device_id,
                alert_type="traffic_spike",
                risk_score=config.RISK_WEIGHTS.get("traffic_spike", 15),
                severity="MEDIUM",
                description=f"Traffic volume spike detected from {ip_address}."
            )
        if res_drift.get("drift_score", 0) >= 50.0:
            active_indicators.append("behaviour_drift")
            create_alert(
                device_id=device_id,
                alert_type="behaviour_drift",
                risk_score=config.RISK_WEIGHTS.get("behaviour_drift", 15),
                severity="HIGH" if res_drift.get("drift_score", 0) >= 75 else "MEDIUM",
                description=f"High behavioural drift score ({res_drift.get('drift_score')}%) on {ip_address}."
            )
        detection_results.append(res_drift)

    # Calculate overall risk score
    total_risk = calculate_risk(active_indicators)
    risk_level = get_risk_level(total_risk)

    # Update device score in database
    update_device_risk(device_id, total_risk)

    # Check automatic quarantine threshold
    quarantined = (current_status == "quarantined")
    if auto_quarantine and total_risk >= config.RISK_THRESHOLD_HIGH and current_status != "quarantined":
        reasons_text = ", ".join(active_indicators) if active_indicators else "Severe Risk"
        success, msg = quarantine_device(
            device_id=device_id,
            ip_address=ip_address,
            reason=f"Risk Score {total_risk}/100 reached HIGH threshold ({reasons_text})"
        )
        quarantined = success

    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "risk_score": total_risk,
        "risk_level": risk_level,
        "indicators": active_indicators,
        "detections": detection_results,
        "quarantined": quarantined
    }


def evaluate_all_devices(auto_quarantine=True):
    """Run full risk evaluation for all devices currently stored in the database."""
    devices = get_all_devices()
    evaluations = []
    for dev in devices:
        evaluations.append(evaluate_device_risk(dev, auto_quarantine=auto_quarantine))
    return evaluations


if __name__ == "__main__":
    print("Testing Risk Engine:")
    sample_detections = ["unknown_device", "port_scan", "dns_anomaly"]
    sample_score = calculate_risk(sample_detections)
    print(f"Detections: {sample_detections}")
    print(f"Calculated Score: {sample_score}/100")
    print(f"Risk Level: {get_risk_level(sample_score)}")