# SentinelLite

SentinelLite is a lightweight, terminal-based SIEM project designed for cybersecurity learning and demonstration. It simulates real-time security monitoring by collecting security events, detecting suspicious behavior, creating alerts, and displaying activity in a clean terminal interface.

## Problem Statement

Small organizations often need basic security monitoring but cannot afford or deploy complex enterprise SIEM platforms. SentinelLite solves this problem by providing a simple, educational, and realistic SIEM that can run locally without extra infrastructure.

## Objectives

- Collect security-related events generated locally
- Detect common attack patterns in real time
- Produce structured alerts
- Display current threat levels in a terminal UI
- Provide a safe testing environment with a local Flask simulator
- Keep the project simple enough for an internship presentation

## Features

- Real-time event monitoring
- Event storage in JSON Lines format
- Threat detection for:
  - Brute-force attempts
  - Credential stuffing
  - Port scanning
  - Traffic spikes
- Alert generation and storage
- Threat scoring system
- Terminal-based SIEM interface
- Local Flask-based security event simulator

## Architecture

```text
                    ┌─────────────────────┐
                    │  Testing Web App    │
                    │  Generates Events   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Event Collector   │
                    │  Validates & Stores  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     Log Storage     │
                    │  events.jsonl      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Detection Engine   │
                    │ Rule-based checks   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Alert Manager     │
                    │ Generates Alerts    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Terminal SIEM UI   │
                    │  Real-Time Display  │
                    └─────────────────────┘
```

## Technologies Used

- Python
- Flask
- JSONL file storage
- Rich terminal UI library
- Vanilla HTML, CSS, and JavaScript

## Installation

1. Create and activate a virtual environment (optional but recommended)
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## How to Run

### 1. Start the SIEM monitor

```bash
python main.py
```

### 2. Start the simulator web app

Open another terminal and run:

```bash
python web_simulator/app.py
```

Then open:

```text
http://127.0.0.1:5001/
```

## Detection Rules

### 1. Brute Force

Detects repeated failed login attempts from the same IP address. The default rule is 5 failed attempts within 60 seconds.

### 2. Credential Stuffing

Detects one IP attempting to access several different usernames in a short period.

### 3. Port Scan

Detects one IP probing multiple different ports within a short time window.

### 4. Traffic Spike

Detects abnormal request volume from a single source IP.

## Sample Output

```text
╔══════════════════════════════════════════════════╗
║              🛡️ SENTINELLITE SIEM               ║
║        REAL-TIME SECURITY MONITORING          ║
╚══════════════════════════════════════════════════╝

[17:40:01] INFO     System started
[17:40:02] INFO     Normal login detected
[17:40:08] WARNING  Failed login detected
[17:40:10] WARNING  Failed login detected
[17:40:12] WARNING  Failed login detected
[17:40:15] WARNING  Failed login detected
[17:40:17] WARNING  Failed login detected
[17:40:18] ALERT     BRUTE-FORCE ATTACK DETECTED

Source IP: 192.168.1.100
Attempts: 7
Severity: HIGH
```

## Testing

The Flask web simulator is used to trigger events:

- Normal Login
- Failed Login
- Brute Force Attack
- Credential Stuffing
- Port Scan
- Traffic Spike

Each test generates structured events in the local `data/events.jsonl` file, which the SIEM monitors automatically.

## Limitations

This project is intentionally lightweight and educational. It does not replace enterprise SIEM solutions such as Splunk, ELK, or Microsoft Sentinel. It is designed for learning, demonstration, and basic security monitoring in a safe local environment.

## Future Improvements

- Windows and Linux log ingestion
- Email or SMS alerting
- WebSocket live dashboard updates
- More detection rules
- Threat intelligence correlation
- User-friendly analytics dashboard

## Internship Presentation Support

### Problem

Small teams need a low-cost way to understand how SIEM systems detect suspicious behavior and generate alerts.

### Solution

SentinelLite demonstrates the core SIEM workflow: collect events, analyze them, detect patterns, raise alerts, and display results in real time.

### Workflow

```text
Test Event
↓
Event Collection
↓
Analysis
↓
Threat Detection
↓
Alert Generation
↓
Terminal Display
```

### Demo Scenario

1. Start the SIEM monitor with `python main.py`
2. Start the simulator with `python web_simulator/app.py`
3. Trigger a normal login event
4. Trigger failed login events
5. Trigger a brute-force attack simulation
6. Show the alert created by the system
7. Explain the attack timeline and threat score

## Project Notes

This project intentionally keeps the implementation simple and approachable. It is designed to be beginner-friendly while still demonstrating the most important ideas behind a SIEM system.
