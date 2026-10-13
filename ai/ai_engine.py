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
    return FALLBACKS.get(
        alert_type,
        (
            f"A '{alert_type}' alert was raised for this device.",
            "Review the device activity and confirm whether it is expected.",
        ),
    )


def _ask_ollama(prompt):
    body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())["response"].strip()


def explain_alert(alert_type, severity, risk_score, description, device_ip):
    """Return (summary, recommendation, source)."""
    prompt = (
        "You are a network security assistant. Explain this alert to a non-expert.\n"
        f"Alert: {alert_type}\nDevice IP: {device_ip}\nSeverity: {severity}\n"
        f"Risk score: {risk_score}/100\nDetails: {description}\n\n"
        "Reply in exactly this format:\n"
        "SUMMARY: <one or two sentences>\n"
        "RECOMMENDATION: <one or two sentences>"
    )
    try:
        text = _ask_ollama(prompt)
        summary, recommendation = text, ""
        if "RECOMMENDATION:" in text:
            summary, recommendation = text.split("RECOMMENDATION:", 1)
        summary = summary.replace("SUMMARY:", "").strip()
        return summary, recommendation.strip(), "Ollama"
    except Exception:
        summary, recommendation = _fallback(alert_type)
        return summary, recommendation, "Built-in"