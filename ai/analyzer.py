from ai.ai_data import save_analysis


def analyze(sonar, trivy, falco):

    critical = 0
    high = 0

    recommendations = []

    # --------------------
    # Sonar
    # --------------------
    if sonar:

        critical += sonar.get("critical", 0)
        high += sonar.get("high", 0)

        if sonar.get("critical", 0):

            recommendations.append(
                "Critical code vulnerabilities found. Fix immediately."
            )

    # --------------------
    # Trivy
    # --------------------
    if trivy:

        critical += trivy.get("critical", 0)
        high += trivy.get("high", 0)

        if trivy.get("critical", 0):

            recommendations.append(
                "Critical container vulnerabilities detected."
            )

    # --------------------
    # Falco
    # --------------------
    if falco:

        recommendations.append(
            f"{len(falco)} runtime security events detected."
        )

    # --------------------

    if critical > 0:

        risk = "CRITICAL"

    elif high > 0:

        risk = "HIGH"

    else:

        risk = "LOW"

    result = {

        "risk": risk,

        "summary": {

            "critical": critical,
            "high": high,
            "falco_events": len(falco),

        },

        "recommendations": recommendations

    }

    save_analysis(result)

    return result