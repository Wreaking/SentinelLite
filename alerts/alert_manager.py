"""
Alert Manager Module
====================
What it does:
    Converts threat detections into structured alert records and stores them.

Why it exists:
    Keeps alert creation in one place so every rule generates consistent output.

How it communicates:
    - The detection engine sends detection objects here.
    - This module writes alert records to data/alerts.jsonl.
    - The terminal UI reads alerts from storage for display.
"""

import json
from datetime import datetime

from storage.file_storage import get_all_alerts, store_alert


def generate_alert_id() -> str:
    """Generate a simple unique ID like ALT-001."""
    existing = get_all_alerts()
    next_number = len(existing) + 1
    return f"ALT-{next_number:03d}"


def create_alert(detection: dict) -> dict:
    """
    Transform a threat detection dictionary into a structured alert.

    Args:
        detection: Detection result from the detection engine.

    Returns:
        Alert dictionary ready to append to storage.
    """
    alert = {
        "alert_id": generate_alert_id(),
        "timestamp": detection.get("timestamp") or datetime.now().isoformat(timespec="seconds"),
        "alert_type": detection.get("alert_type", "UNKNOWN"),
        "severity": detection.get("severity", "MEDIUM"),
        "source_ip": detection.get("source_ip", "unknown"),
        "description": detection.get("description", "Security alert detected"),
        "status": "ACTIVE",
        "details": {
            "time_window_seconds": detection.get("time_window_seconds"),
            "failed_attempts": detection.get("failed_attempts"),
            "accounts_targeted": detection.get("accounts_targeted"),
            "unique_ports": detection.get("unique_ports"),
            "requests": detection.get("requests")
        }
    }
    store_alert(alert)
    return alert


def create_alerts_from_detections(detections: list) -> list:
    """Create alert records for a list of detection objects."""
    alerts = []
    for detection in detections:
        alert = create_alert(detection)
        alerts.append(alert)
    return alerts


def calculate_threat_score(alerts: list) -> int:
    """
    Compute a simple threat score from the active alerts.
    The scoring is intentionally simple and educational.
    """
    score = 0
    score_map = {
        "FAILED_LOGIN": 5,
        "REPEATED_FAILED_LOGIN": 10,
        "BRUTE_FORCE": 40,
        "CREDENTIAL_STUFFING": 50,
        "PORT_SCAN": 30,
        "TRAFFIC_SPIKE": 50
    }

    for alert in alerts:
        score += score_map.get(alert.get("alert_type"), 10)

    return min(score, 100)


def get_threat_level(score: int) -> str:
    """Map a numeric score to LOW / MEDIUM / HIGH / CRITICAL."""
    if 0 <= score <= 20:
        return "LOW"
    if 21 <= score <= 40:
        return "MEDIUM"
    if 41 <= score <= 70:
        return "HIGH"
    return "CRITICAL"
