import os
import json
import requests
import config
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


def _ask_gemini(alert_type, severity, risk_score, description, device_ip):
    api_key = getattr(config, "GEMINI_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return None
    prompt = (
        f"You are a Senior Network Security Analyst analyzing an intrusion detection alert.\n"
        f"Alert Type: {alert_type}\n"
        f"Severity: {severity}\n"
        f"Risk Score: {risk_score}/100\n"
        f"Device IP: {device_ip}\n"
        f"Observed Evidence: {description}\n\n"
        f"Provide your analysis in exactly two sections:\n"
        f"SUMMARY: <Concise technical explanation of the behavior, mechanism, and immediate risk>\n"
        f"RECOMMENDATION: <Concrete 2-3 step remediation or verification instructions for the network administrator>"
    )
    for model in ["gemini-3.8-flash", "gemini-flash-latest", "gemini-2.0-flash"]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            res = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                headers={"Content-Type": "application/json"},
                timeout=6
            )
            if res.status_code == 200:
                data = res.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                summary = ""
                recommendation = ""
                if "SUMMARY:" in text and "RECOMMENDATION:" in text:
                    parts = text.split("RECOMMENDATION:")
                    summary = parts[0].replace("SUMMARY:", "").strip()
                    recommendation = parts[1].strip()
                else:
                    lines = [l.strip() for l in text.split("\n") if l.strip()]
                    summary = lines[0] if lines else text
                    recommendation = "\n".join(lines[1:]) if len(lines) > 1 else "Investigate source IP and inspect related network logs."
                return summary, recommendation, "Gemini AI"
        except Exception:
            continue
    return None


def explain_alert(alert_type, severity, risk_score, description, device_ip):
    """Deterministic evidence-grounded explanation; optional model is not required.

    Unverified model prose never replaces recorded facts or authorizes response.
    """
    gemini_res = _ask_gemini(alert_type, severity, risk_score, description, device_ip)
    if gemini_res:
        return gemini_res
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
