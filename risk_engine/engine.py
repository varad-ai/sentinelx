def calculate_risk(detections):
    score = 0

    for detection in detections:
        severity = detection.get("severity", "").lower()

        if severity == "low":
            score += 10

        elif severity == "medium":
            score += 30

        elif severity == "high":
            score += 50

        elif severity == "critical":
            score += 80

    # Maximum risk score is 100
    score = min(score, 100)

    # Determine risk level
    if score >= 80:
        risk_level = "critical"

    elif score >= 60:
        risk_level = "high"

    elif score >= 30:
        risk_level = "medium"

    else:
        risk_level = "low"

    return {
        "score": score,
        "risk_level": risk_level
    }