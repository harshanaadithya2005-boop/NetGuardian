import json
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"

# Built-in explanations used when Ollama is not running
FALLBACKS = {
    "Unknown Device": (
        "A new device that is not in the trusted list joined the network.",
        "Verify whether the device belongs to an authorized user before allowing access.",
    ),
    "Traffic Spike": (
        "Network traffic volume is far higher than this device's normal level.",
        "Check which application is generating the traffic and look for malware or data transfer.",
    ),
    "Port Scan": (
        "A device is probing many ports, which is often a sign of reconnaissance.",
        "Isolate the device and review its recent activity.",
    ),
}



def _fallback(alert_type):
    """Return a built-in explanation for NetGuardian alert types."""

    normalized = str(alert_type).strip().lower().replace(" ", "_")

    explanations = {
        "unknown_device": (
            "An untrusted or unrecognized device was detected on the network.",
            "Verify the device owner and mark it trusted only if authorized."
        ),
        "traffic_spike": (
            "Network traffic is significantly higher than the expected baseline.",
            "Review recent traffic and investigate unusual applications or transfers."
        ),
        "port_scan": (
            "A device may be attempting to connect to multiple network ports.",
            "Review the device's recent connections and investigate suspicious activity."
        ),
        "dns_anomaly": (
            "Unusual DNS activity was detected, such as suspicious domains or excessive queries.",
            "Review the DNS queries and check for potentially malicious domains."
        ),
        "behaviour_drift": (
            "The device's network behavior differs significantly from its normal baseline.",
            "Compare recent traffic patterns with the device's usual activity."
        )
    }

    return explanations.get(
        normalized,
        (
            f"A '{alert_type}' security alert was generated.",
            "Review the device activity and investigate the alert."
        )
    )



def _ask_ollama(prompt):
    body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())["response"].strip()


def explain_alert(alert_type, severity, risk_score, description, device_ip):
    """Deterministic evidence-grounded explanation; optional model is not required.

    Unverified model prose never replaces recorded facts or authorizes response.
    """
    _,recommendation=_fallback(alert_type)
    evidence=str(description or 'No packet-level details were recorded for this alert.')
    summary=f"Recorded {alert_type} alert for {device_ip}: {evidence} Risk at alert creation: {risk_score}/100 ({severity}). This is an indicator requiring review, not proof of compromise."
    return summary,recommendation,'Built-in'


def explain_detection(detection):
    evidence=detection['evidence']
    if detection['type']=='unknown_device':
        return f"Device {detection['device_id']} ({detection['ip_address']}): {detection['message']} Inventory trust indicator (+{detection['risk_contribution']}); this does not imply observed attack traffic or authorize quarantine."
    return (f"Device {detection['device_id']} ({detection['ip_address']}): "
            f"{detection['message']} Recorded {evidence['packet_count']} packet records "
            f"between {evidence['window_start']} and {evidence['window_end']}. "
            f"Risk contribution +{detection['risk_contribution']}; confidence {detection['confidence']:.0%}. "
            f"Source: {detection['source']}.")
