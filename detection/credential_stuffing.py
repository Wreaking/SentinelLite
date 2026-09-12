"""Credential stuffing detection module."""

from collections import defaultdict
from datetime import datetime


def detect_credential_stuffing(events, unique_usernames_threshold, time_window_seconds):
    """
    Detect one IP targeting many different usernames in a short time.

    Args:
        events: List of event dictionaries.
        unique_usernames_threshold: Minimum unique account names to flag.
        time_window_seconds: Look-back window in seconds.

    Returns:
        A list of detection dictionaries.
    """
    attempts_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "failed_login":
            timestamp = event.get("timestamp")
            try:
                dt = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue
            source_ip = event.get("source_ip")
            attempts_by_ip[source_ip].append({
                "username": event.get("username"),
                "timestamp": dt,
            })

    detections = []
    for source_ip, attempts in attempts_by_ip.items():
        attempts.sort(key=lambda item: item["timestamp"])
        for index, item in enumerate(attempts):
            window = [attempt for attempt in attempts if 0 <= (attempt["timestamp"] - item["timestamp"]).total_seconds() <= time_window_seconds]
            usernames = {attempt["username"] for attempt in window if attempt.get("username")}
            if len(usernames) >= unique_usernames_threshold:
                detections.append({
                    "alert_type": "CREDENTIAL_STUFFING",
                    "source_ip": source_ip,
                    "accounts_targeted": len(usernames),
                    "time_window_seconds": time_window_seconds,
                    "severity": "HIGH",
                    "description": "One IP attempted multiple usernames in a short period",
                    "timestamp": item["timestamp"].isoformat(timespec="seconds")
                })
                break
    return detections
