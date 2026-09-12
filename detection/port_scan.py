"""Port scan detection module."""

from collections import defaultdict
from datetime import datetime


def detect_port_scan(events, unique_ports_threshold, time_window_seconds):
    """
    Detect when one IP quickly probes several different ports.

    Args:
        events: List of event dictionaries.
        unique_ports_threshold: Minimum number of unique ports required.
        time_window_seconds: Look-back window in seconds.

    Returns:
        A list of detection dictionaries.
    """
    probes_by_ip = defaultdict(list)
    for event in events:
        if event.get("event_type") == "port_scan":
            timestamp = event.get("timestamp")
            try:
                dt = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue
            source_ip = event.get("source_ip")
            probes_by_ip[source_ip].append({
                "port": event.get("target_port"),
                "timestamp": dt,
            })

    detections = []
    for source_ip, probes in probes_by_ip.items():
        probes.sort(key=lambda item: item["timestamp"])
        for index, probe in enumerate(probes):
            window = [entry for entry in probes if 0 <= (entry["timestamp"] - probe["timestamp"]).total_seconds() <= time_window_seconds]
            unique_ports = {entry["port"] for entry in window if entry.get("port") is not None}
            if len(unique_ports) >= unique_ports_threshold:
                detections.append({
                    "alert_type": "PORT_SCAN",
                    "source_ip": source_ip,
                    "unique_ports": len(unique_ports),
                    "time_window_seconds": time_window_seconds,
                    "severity": "MEDIUM",
                    "description": "Multiple ports were probed from one IP in a short window",
                    "timestamp": probe["timestamp"].isoformat(timespec="seconds")
                })
                break
    return detections
