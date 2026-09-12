"""Traffic spike detection module."""

from collections import defaultdict
from datetime import datetime


def detect_traffic_spike(events, request_threshold, time_window_seconds):
    """
    Detect a high volume of network requests from one IP within a short time.

    Args:
        events: List of event dictionaries.
        request_threshold: Number of requests required to trigger.
        time_window_seconds: Look-back window in seconds.

    Returns:
        A list of detection dictionaries.
    """
    requests_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "network_request":
            timestamp = event.get("timestamp")
            try:
                dt = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue
            source_ip = event.get("source_ip")
            requests_by_ip[source_ip].append(dt)

    detections = []
    for source_ip, timestamps in requests_by_ip.items():
        timestamps.sort()
        for index, current in enumerate(timestamps):
            window = [ts for ts in timestamps if 0 <= (current - ts).total_seconds() <= time_window_seconds]
            if len(window) >= request_threshold:
                detections.append({
                    "alert_type": "TRAFFIC_SPIKE",
                    "source_ip": source_ip,
                    "requests": len(window),
                    "time_window_seconds": time_window_seconds,
                    "severity": "HIGH",
                    "description": "Unusual traffic volume detected from a single source",
                    "timestamp": current.isoformat(timespec="seconds")
                })
                break
    return detections
