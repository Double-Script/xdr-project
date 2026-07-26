import joblib
import numpy as np
from pathlib import Path

BASE = Path(__file__).parent

clf = joblib.load(BASE / "models" / "threat_classifier.pkl")
iso = joblib.load(BASE / "models" / "anomaly_detector.pkl")
scaler = joblib.load(BASE / "models" / "scaler.pkl")
label_map = joblib.load(BASE / "models" / "label_map.pkl")

SEVERITY_MAP = {
    "normal": {
        "score": 0,
        "level": "INFO",
        "action": "No action required"
    },
    "port_scan": {
        "score": 40,
        "level": "MEDIUM",
        "action": "Investigate source IP"
    },
    "brute_force": {
        "score": 75,
        "level": "HIGH",
        "action": "Block IP"
    },
    "sql_injection": {
        "score": 80,
        "level": "HIGH",
        "action": "Check vulnerable endpoint"
    },
    "ddos": {
        "score": 90,
        "level": "CRITICAL",
        "action": "Enable mitigation"
    },
    "malware": {
        "score": 95,
        "level": "CRITICAL",
        "action": "Isolate workload"
    },
    "reverse_shell": {
        "score": 99,
        "level": "CRITICAL",
        "action": "Kill container immediately"
    }
}


def analyze_event(event):

    features = [
        float(event.get("bytes_in",100)),
        float(event.get("bytes_out",100)),
        float(event.get("packet_count",1)),
        float(event.get("unique_ports",1)),
        float(event.get("failed_auth",0)),
        float(event.get("request_rate",1)),
        float(event.get("severity",1)),
        float(event.get("alert_count",1))
    ]

    X = scaler.transform(np.array([features]))

    prediction = int(clf.predict(X)[0])

    confidence = float(max(clf.predict_proba(X)[0]))

    anomaly = bool(iso.predict(X)[0] == -1)

    attack = label_map[prediction]

    info = SEVERITY_MAP.get(
        attack,
        SEVERITY_MAP["normal"]
    )

    return {
        "attack_type": attack,
        "confidence": round(confidence * 100,2),
        "severity_level": info["level"],
        "severity_score": info["score"],
        "recommended_action": info["action"],
        "is_anomaly": anomaly
    }