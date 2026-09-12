"""
Event Collector Module
======================
What it does:
    Creates structured security events and stores them using the storage module.
    Every event gets a consistent format with a timestamp, event type, source IP,
    and other relevant details.

Why it exists:
    Acts as the single entry point for creating events.  Whether the Flask web
    simulator or any other source generates an event, it goes through here so
    the format is always consistent.

How it communicates:
    - The Flask web simulator calls functions here to create events.
    - This module calls storage.file_storage.store_event() to persist them.
    - The detection engine later reads these events from storage.
"""

import random
from datetime import datetime

from storage.file_storage import store_event


def _now() -> str:
    """Return the current timestamp in ISO format."""
    return datetime.now().isoformat(timespec="seconds")


def _random_ip() -> str:
    """Generate a random private IP address for simulation."""
    return f"192.168.1.{random.randint(100, 250)}"


# ──────────────────────────────── Single Event Generators ────────────────────

def create_login_event(username: str = "sample_user", source_ip: str = None,
                       success: bool = True, source_id: str = "security_lab_browser",
                       source_type: str = "local_simulator", target: str = "security_lab_login") -> dict:
    """
    Create and store a login event (successful or failed).

    Args:
        username:  The account name used in the login attempt.
        source_ip: The IP address of the client.  Auto-generated if None.
        success:   True for a successful login, False for a failed one.
        source_id: Identifier for the source application or test environment.
        source_type: Type of source, such as a browser or simulator.
        target:    The login target resource.

    Returns:
        The event dictionary that was stored.
    """
    source_ip = source_ip or _random_ip()
    event = {
        "timestamp": _now(),
        "event_type": "login_success" if success else "failed_login",
        "username": username,
        "source_ip": source_ip,
        "source_id": source_id,
        "source_type": source_type,
        "target": target,
        "status": "success" if success else "failed",
        "description": f"{'Successful' if success else 'Failed'} login attempt for user '{username}'"
    }
    store_event(event)
    return event


def create_port_scan_event(source_ip: str = None, target_port: int = 80,
                          source_id: str = "security_lab_browser",
                          source_type: str = "local_simulator") -> dict:
    """
    Create and store a port-scan simulation event.

    Args:
        source_ip:   The scanner's IP address.  Auto-generated if None.
        target_port: The port that was probed.
        source_id:   Identifier for the source application or test environment.
        source_type: Type of source, such as a browser or simulator.

    Returns:
        The event dictionary that was stored.
    """
    source_ip = source_ip or _random_ip()
    event = {
        "timestamp": _now(),
        "event_type": "port_scan",
        "source_ip": source_ip,
        "source_id": source_id,
        "source_type": source_type,
        "target_port": target_port,
        "status": "detected",
        "description": f"Port scan detected: {source_ip} → Port {target_port}"
    }
    store_event(event)
    return event


def create_traffic_event(source_ip: str = None, source_id: str = "security_lab_browser",
                        source_type: str = "local_simulator", endpoint: str = "/login") -> dict:
    """
    Create and store a single network-traffic event.
    Multiple rapid calls simulate a traffic spike.

    Args:
        source_ip: The client IP.  Auto-generated if None.
        source_id: Identifier for the source application or test environment.
        source_type: Type of source, such as a browser or simulator.
        endpoint: The local endpoint that was requested.

    Returns:
        The event dictionary that was stored.
    """
    source_ip = source_ip or _random_ip()
    event = {
        "timestamp": _now(),
        "event_type": "network_request",
        "source_ip": source_ip,
        "source_id": source_id,
        "source_type": source_type,
        "endpoint": endpoint,
        "status": "completed",
        "description": f"Network request from {source_ip} to {endpoint}"
    }
    store_event(event)
    return event


# ──────────────────────────── Scenario Simulators ────────────────────────────

def simulate_brute_force(target_username: str = "sample_user",
                         source_ip: str = None,
                         attempts: int = 7) -> list:
    """
    Simulate a brute-force attack: many failed logins from the same IP
    targeting the same account.

    Args:
        target_username: The account being attacked.
        source_ip:       Attacker IP (auto-generated if None).
        attempts:        Number of failed login attempts to generate.

    Returns:
        List of generated event dictionaries.
    """
    source_ip = source_ip or _random_ip()
    events = []
    for _ in range(attempts):
        event = create_login_event(
            username=target_username,
            source_ip=source_ip,
            success=False
        )
        events.append(event)
    return events


def simulate_credential_stuffing(source_ip: str = None,
                                 usernames: list = None) -> list:
    """
    Simulate a credential-stuffing attack: one IP tries many different
    usernames in quick succession.

    Args:
        source_ip: Attacker IP (auto-generated if None).
        usernames: List of usernames to try.  Defaults to a pre-set list.

    Returns:
        List of generated event dictionaries.
    """
    source_ip = source_ip or _random_ip()
    if usernames is None:
        usernames = ["sample_user_1", "sample_user_2", "sample_user_3", "sample_user_4",
                     "sample_user_5", "sample_user_6", "sample_user_7", "sample_user_8"]
    events = []
    for username in usernames:
        event = create_login_event(
            username=username,
            source_ip=source_ip,
            success=False
        )
        events.append(event)
    return events


def simulate_port_scan(source_ip: str = None,
                       ports: list = None) -> list:
    """
    Simulate a port scan: one IP probes many different ports.

    Args:
        source_ip: Scanner IP (auto-generated if None).
        ports:     List of port numbers to probe.  Defaults to common ports.

    Returns:
        List of generated event dictionaries.
    """
    source_ip = source_ip or _random_ip()
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 3306, 3389, 5432, 8080, 8443]
    events = []
    for port in ports:
        event = create_port_scan_event(source_ip=source_ip, target_port=port)
        events.append(event)
    return events


def simulate_traffic_spike(source_ip: str = None,
                           request_count: int = 150) -> list:
    """
    Simulate a traffic spike / possible flooding: one IP sends a huge
    number of requests in a short time.

    Args:
        source_ip:     Sender IP (auto-generated if None).
        request_count: Number of requests to generate.

    Returns:
        List of generated event dictionaries.
    """
    source_ip = source_ip or _random_ip()
    events = []
    for _ in range(request_count):
        event = create_traffic_event(source_ip=source_ip)
        events.append(event)
    return events
