# SentinelLite Testing Guide

This document explains how to validate the main detection features of SentinelLite.

## Test 1: Normal Login

### Steps

1. Start the SIEM monitor.
2. Open the Flask simulator.
3. Click "Normal Login".

### Expected Result

- One normal login event is created.
- No alert is raised.
- The terminal shows normal activity only.

## Test 2: Failed Login

### Steps

1. Click "Failed Login" from the simulator.

### Expected Result

- One failed_login event is generated.
- The SIEM logs the event.
- No alert should trigger unless repeated patterns occur.

## Test 3: Brute Force Attack

### Steps

1. Click "Simulate Brute Force".

### Expected Result

- Multiple failed login events are created from the same IP.
- A BRUTE_FORCE alert is generated.
- Threat score should rise to HIGH.

## Test 4: Credential Stuffing

### Steps

1. Click "Simulate Credential Stuffing".

### Expected Result

- One source IP attempts many usernames.
- A CREDENTIAL_STUFFING alert is raised.
- Description should mention multiple accounts targeted.

## Test 5: Port Scan

### Steps

1. Click "Simulate Port Scan".

### Expected Result

- Multiple port scan events are generated.
- A PORT_SCAN detection appears.
- The alert should show several unique ports.

## Test 6: Traffic Spike

### Steps

1. Click "Simulate Traffic Spike".

### Expected Result

- A large number of network requests are generated.
- A TRAFFIC_SPIKE alert is raised.
- The terminal displays abnormal traffic behavior.

## Actual Result Section

Use this section to record what actually happened during your test run:

- Date:
- Environment:
- Observer:
- Result:
- Notes:

Example:

```text
Date: 2026-09-12
Environment: Local Windows machine
Observer: Student Name
Result: Brute-force alert successfully generated after 7 failed logins.
Notes: Terminal UI updated in real time and alert was stored to data/alerts.jsonl.
```
