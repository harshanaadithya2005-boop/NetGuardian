from database.models import create_alert as persist_alert


def create_alert(device_id, alert_type, risk_score, description=""):
    """Insert an alert. Severity is worked out from the risk score."""
    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 60:
        severity = "High"
    elif risk_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    return persist_alert(device_id, alert_type, risk_score, severity.upper(), description)
