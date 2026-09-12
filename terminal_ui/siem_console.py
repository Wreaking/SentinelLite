"""Terminal user interface for SentinelLite."""

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class SentinelLiteConsole:
    """Simple console-based SIEM display."""

    def __init__(self):
        self.console = Console()

    def render_header(self):
        self.console.print(Panel.fit(
            "[bold cyan]🛡️ SentinelLite[/bold cyan]\n[white]Real-Time Security Monitoring System[/white]",
            border_style="cyan"
        ))

    def print_status(self, message, level="INFO"):
        color_map = {
            "INFO": "green",
            "LOW": "cyan",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold red"
        }
        time_str = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"[{color_map.get(level, 'green')}][{time_str}] {level}: {message}[/]")

    def print_event_summary(self, events):
        if not events:
            return
        latest = events[-1]
        self.console.print(
            f"[bold green][{datetime.now().strftime('%H:%M:%S')}] INFO[/bold green] New event: {latest.get('event_type')} | IP: {latest.get('source_ip')}"
        )

    def print_alerts(self, alerts, score, level):
        self.console.print(Panel.fit(
            f"[bold red]🚨 ALERT GENERATED[/bold red]\n"
            f"Score: {score}/100\n"
            f"Threat Level: {level}",
            border_style="red"
        ))
        for alert in alerts:
            self.console.print(
                f"[bold red][{alert.get('timestamp')}] {alert.get('alert_type')}[/bold red] | "
                f"Severity: {alert.get('severity')} | IP: {alert.get('source_ip')} | "
                f"Description: {alert.get('description')}"
            )

    def print_timeline(self, events, alerts):
        if not alerts:
            return
        table = Table(title="Attack Timeline")
        table.add_column("Time", style="cyan")
        table.add_column("Event", style="magenta")
        table.add_column("Details", style="white")

        for event in events[-10:]:
            table.add_row(
                event.get("timestamp", "unknown").split("T")[-1],
                event.get("event_type", "unknown"),
                event.get("description", event.get("source_ip", ""))
            )

        self.console.print(table)
