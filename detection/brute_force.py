"""Brute force detection module."""

from collections import defaultdict
from datetime import datetime


def detect_brute_force(events, failed_attempts_threshold, time_window_seconds):
    """
    Detect repeated failed logins from the same IP within a time window.

    Args:
        events: List of event dictionaries.
        failed_attempts_threshold: Number of failed login attempts required.
        time_window_seconds: Maximum time window in seconds.

    Returns:
        A list of detection dictionaries.
    """
    failed_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "failed_login":
            timestamp = event.get("timestamp")
            try:
                dt = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue
            source_ip = event.get("source_ip")
            failed_by_ip[source_ip].append(dt)

    detections = []
    for source_ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for index, current in enumerate(timestamps):
            window = [ts for ts in timestamps if 0 <= (current - ts).total_seconds() <= time_window_seconds]
            if len(window) >= failed_attempts_threshold:
                detections.append({
                    "alert_type": "BRUTE_FORCE",
                    "source_ip": source_ip,
                    "failed_attempts": len(window),
                    "time_window_seconds": time_window_seconds,
                    "severity": "HIGH",
                    "description": "Multiple failed login attempts detected from one IP",
                    "timestamp": current.isoformat(timespec="seconds")
                })
                break
    return detections
