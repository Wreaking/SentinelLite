import os
import sys

from flask import Flask, jsonify, render_template, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from collector.event_collector import (
    create_login_event,
    create_port_scan_event,
    create_traffic_event,
)
from storage.file_storage import clear_data

VALID_USERNAME = "sample_user"
VALID_PASSWORD = "ChangeMe123!"

app = Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/lab/login", methods=["POST"])
def lab_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    source_ip = data.get("source_ip") or "127.0.0.1"
    source_id = data.get("source_id") or "security_lab_browser"
    source_type = data.get("source_type") or "local_simulator"
    target = data.get("target") or "security_lab_login"

    success = username == VALID_USERNAME and password == VALID_PASSWORD
    if success:
        event = create_login_event(
            username=username,
            source_ip=source_ip,
            success=True,
            source_id=source_id,
            source_type=source_type,
            target=target,
        )
        message = "Login successful"
    else:
        event = create_login_event(
            username=username,
            source_ip=source_ip,
            success=False,
            source_id=source_id,
            source_type=source_type,
            target=target,
        )
        message = "Invalid username or password"

    return jsonify({
        "status": "ok",
        "authenticated": success,
        "message": message,
        "event": event,
    })


@app.route("/api/lab/port-scan", methods=["POST"])
def lab_port_scan():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    source_id = data.get("source_id") or "security_lab_browser"
    source_type = data.get("source_type") or "local_simulator"
    ports = data.get("ports") or [22, 80, 443, 3306, 8080]

    events = []
    for port in ports:
        event = create_port_scan_event(
            source_ip=source_ip,
            target_port=int(port),
            source_id=source_id,
            source_type=source_type,
        )
        events.append(event)

    return jsonify({"status": "ok", "count": len(events), "events": events})


@app.route("/api/lab/traffic-spike", methods=["POST"])
def lab_traffic_spike():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    source_id = data.get("source_id") or "security_lab_browser"
    source_type = data.get("source_type") or "local_simulator"
    request_count = max(1, int(data.get("request_count") or 25))
    endpoint = data.get("endpoint") or "/lab/login"

    events = []
    for _ in range(request_count):
        event = create_traffic_event(
            source_ip=source_ip,
            source_id=source_id,
            source_type=source_type,
            endpoint=endpoint,
        )
        events.append(event)

    return jsonify({"status": "ok", "count": len(events), "events": events})


@app.route("/api/lab/reset", methods=["POST"])
def lab_reset():
    clear_data()
    return jsonify({"status": "ok", "message": "Demo state reset"})


@app.route("/api/event/login", methods=["POST"])
def api_login_legacy():
    return lab_login()


@app.route("/api/event/bruteforce", methods=["POST"])
def api_bruteforce_legacy():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    attempts = int(data.get("attempts") or 5)
    username = data.get("username") or "sample_user"
    events = []
    for _ in range(attempts):
        events.append(
            create_login_event(
                username=username,
                source_ip=source_ip,
                success=False,
                source_id="legacy_simulator",
                source_type="legacy_test",
            )
        )
    return jsonify({"status": "ok", "count": len(events), "events": events})


@app.route("/api/event/credential-stuffing", methods=["POST"])
def api_credential_stuffing_legacy():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    usernames = data.get("usernames") or ["sample_user_1", "sample_user_2", "sample_user_3", "sample_user_4", "sample_user_5"]
    events = []
    for username in usernames:
        events.append(
            create_login_event(
                username=username,
                source_ip=source_ip,
                success=False,
                source_id="legacy_simulator",
                source_type="legacy_test",
            )
        )
    return jsonify({"status": "ok", "count": len(events), "events": events})


@app.route("/api/event/port-scan", methods=["POST"])
def api_port_scan_legacy():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    ports = data.get("ports") or [22, 80, 443, 3306, 8080]
    events = []
    for port in ports:
        events.append(
            create_port_scan_event(
                source_ip=source_ip,
                target_port=port,
                source_id="legacy_simulator",
                source_type="legacy_test",
            )
        )
    return jsonify({"status": "ok", "count": len(events), "events": events})


@app.route("/api/event/traffic-spike", methods=["POST"])
def api_traffic_spike_legacy():
    data = request.get_json(silent=True) or {}
    source_ip = data.get("source_ip") or "127.0.0.1"
    count = int(data.get("request_count") or 25)
    events = []
    for _ in range(count):
        events.append(
            create_traffic_event(
                source_ip=source_ip,
                source_id="legacy_simulator",
                source_type="legacy_test",
                endpoint="/legacy_test",
            )
        )
    return jsonify({"status": "ok", "count": len(events), "events": events})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
