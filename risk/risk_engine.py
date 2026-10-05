RISK_SCORES = {
    "unknown_device": 20,
    "port_scan": 30,
    "dns_anomaly": 15,
    "traffic_spike": 15,
    "behaviour_drift": 20
}


def calculate_risk(detections):
    score = 0

    for detection in detections:
        score += RISK_SCORES.get(detection, 0)

    return min(score, 100)

detections = [
    "unknown_device",
    "dns_anomaly"
]

score = calculate_risk(detections)

print(score)

def get_risk_level(score):
    if score <= 29:
        return "LOW"
    elif score <= 59:
        return "MEDIUM"
    elif score <= 79:
        return "HIGH"
    else:
        return "CRITICAL"

    score = 35

print(get_risk_level(score))