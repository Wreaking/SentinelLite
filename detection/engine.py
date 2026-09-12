"""
Detection Engine Module
======================
What it does:
    Runs all detection rules against recent events and gathers any matches.

Why it exists:
    Centralizes the threat logic so new rules can be added easily.

How it communicates:
    - It reads events from storage.
    - It calls individual detection modules like brute_force.py and port_scan.py.
    - It hands all matches to the alert manager to be saved and displayed.
"""

import json
from pathlib import Path

from detection.brute_force import detect_brute_force
from detection.credential_stuffing import detect_credential_stuffing
from detection.port_scan import detect_port_scan
from detection.traffic_spike import detect_traffic_spike
from storage.file_storage import get_recent_events

BASE_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = BASE_DIR / "config" / "rules.json"


def load_rules():
    """Load detection rules from the config file."""
    with open(RULES_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def detect_threats(events=None):
    """
    Run all detections against recent events.

    Args:
        events: Optional list of events to analyze. If None, use recent events.

    Returns:
        List of detection payloads.
    """
    rules = load_rules()
    if events is None:
        events = get_recent_events(seconds=300)

    detections = []

    detections.extend(
        detect_brute_force(
            events,
            rules["brute_force"]["failed_attempts"],
            rules["brute_force"]["time_window_seconds"]
        )
    )

    detections.extend(
        detect_credential_stuffing(
            events,
            rules["credential_stuffing"]["unique_usernames"],
            rules["credential_stuffing"]["time_window_seconds"]
        )
    )

    detections.extend(
        detect_port_scan(
            events,
            rules["port_scan"]["unique_ports"],
            rules["port_scan"]["time_window_seconds"]
        )
    )

    detections.extend(
        detect_traffic_spike(
            events,
            rules["traffic_spike"]["max_requests"],
            rules["traffic_spike"]["time_window_seconds"]
        )
    )

    return detections


def get_rule_summary():
    """Return a concise view of the configured rules."""
    rules = load_rules()
    return {
        "brute_force": rules["brute_force"],
        "credential_stuffing": rules["credential_stuffing"],
        "port_scan": rules["port_scan"],
        "traffic_spike": rules["traffic_spike"],
        "suspicious_login": rules.get("suspicious_login", {})
    }
