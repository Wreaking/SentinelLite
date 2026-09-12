"""
File Storage Module
===================
What it does:
    Handles all file read/write operations for events and alerts.
    Uses JSON Lines (.jsonl) format — one JSON object per line — which
    makes it easy to append new records without loading the whole file.

Why it exists:
    Centralizes file I/O so other modules never touch the filesystem directly.
    This keeps the code organized and prevents data corruption.

How it communicates:
    - The Event Collector calls store_event() to save new events.
    - The Alert Manager calls store_alert() to save new alerts.
    - The Detection Engine calls get_recent_events() to read events for analysis.
    - The Terminal UI calls get_all_alerts() to display alert summaries.
"""

import json
import os
import threading
from datetime import datetime


# A lock to prevent two threads from writing to the same file at the same time
_file_lock = threading.Lock()

# Default paths for data files (relative to the project root)
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
ALERTS_FILE = os.path.join(DATA_DIR, "alerts.jsonl")


def _ensure_data_dir():
    """Create the data directory if it does not exist."""
    os.makedirs(DATA_DIR, exist_ok=True)


def store_event(event: dict) -> None:
    """
    Append a single event to the events.jsonl file.

    Args:
        event: A dictionary containing event data (timestamp, event_type, etc.)
    """
    _ensure_data_dir()
    with _file_lock:
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


def store_alert(alert: dict) -> None:
    """
    Append a single alert to the alerts.jsonl file.

    Args:
        alert: A dictionary containing alert data (alert_id, severity, etc.)
    """
    _ensure_data_dir()
    with _file_lock:
        with open(ALERTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")


def get_all_events() -> list:
    """
    Read and return every event from the events file.

    Returns:
        A list of event dictionaries, ordered from oldest to newest.
    """
    events = []
    if not os.path.exists(EVENTS_FILE):
        return events

    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # Skip any corrupted lines
                    continue
    return events


def get_recent_events(seconds: int = 120) -> list:
    """
    Return events that occurred within the last `seconds` seconds.
    This is used by the detection engine to check for patterns.

    Args:
        seconds: How far back in time to look (default 120 seconds).

    Returns:
        A list of recent event dictionaries.
    """
    all_events = get_all_events()
    now = datetime.now()
    recent = []

    for event in all_events:
        try:
            event_time = datetime.fromisoformat(event.get("timestamp", ""))
            diff = (now - event_time).total_seconds()
            if diff <= seconds:
                recent.append(event)
        except (ValueError, TypeError):
            # Skip events with invalid timestamps
            continue

    return recent


def get_all_alerts() -> list:
    """
    Read and return every alert from the alerts file.

    Returns:
        A list of alert dictionaries, ordered from oldest to newest.
    """
    alerts = []
    if not os.path.exists(ALERTS_FILE):
        return alerts

    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def get_alert_count() -> int:
    """Return the total number of alerts stored."""
    return len(get_all_alerts())


def clear_data():
    """
    Clear all events and alerts. Useful for resetting before a demo.
    Creates fresh empty files.
    """
    _ensure_data_dir()
    with _file_lock:
        with open(EVENTS_FILE, "w", encoding="utf-8") as f:
            f.write("")
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            f.write("")
