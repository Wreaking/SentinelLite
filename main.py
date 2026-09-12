import threading
import time
from pathlib import Path

from alerts.alert_manager import create_alerts_from_detections, calculate_threat_score, get_threat_level
from detection.engine import detect_threats
from storage.file_storage import clear_data, get_all_alerts, get_all_events
from terminal_ui.siem_console import SentinelLiteConsole

BASE_DIR = Path(__file__).resolve().parent


def monitor_loop(console, polling_interval=1.0, max_iterations=None):
    """Continuously monitor event data and process new detections."""
    iteration = 0
    last_event_count = 0

    while True:
        if max_iterations is not None and iteration >= max_iterations:
            break

        events = get_all_events()
        if len(events) != last_event_count:
            console.print_event_summary(events)
            detections = detect_threats(events)
            if detections:
                alerts = create_alerts_from_detections(detections)
                score = calculate_threat_score(alerts)
                level = get_threat_level(score)
                console.print_alerts(alerts, score, level)
                console.print_timeline(events, alerts)
            else:
                console.print_status("No active threats detected", "INFO")
            last_event_count = len(events)

        time.sleep(polling_interval)
        iteration += 1


def main():
    """Entry point for the SIEM terminal interface."""
    clear_data()
    console = SentinelLiteConsole()
    console.render_header()
    console.print_status("Monitoring started", "INFO")

    monitor_thread = threading.Thread(target=monitor_loop, args=(console,), daemon=True)
    monitor_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print_status("Monitoring stopped by user", "INFO")
        print("\n[+] SentinelLite shutdown complete")


if __name__ == "__main__":
    main()
