"""Read-only risk scoring for NetGuardian demonstrations."""

from risk.risk_engine import calculate_risk, get_risk_level


def evaluate_simulation(indicators):
    """
    Calculate a demonstration risk score without changing
    device records, alerts, or quarantine states.
    """
    if not isinstance(indicators, (list, tuple, set)):
        raise TypeError("indicators must be a list, tuple, or set")

    indicators = list(dict.fromkeys(indicators))

    risk_score = calculate_risk(indicators)
    risk_level = get_risk_level(risk_score)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "would_quarantine": risk_level == "HIGH",
        "simulation": True
    }