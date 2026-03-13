"""
TUI/dashboard.py — Real-time Trust Dashboard
Polls JSON files only. No DB, No HTTP.
"""

import os
import json
import time
from pathlib import Path
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich import box
from rich.text import Text

LIVE_LOG_DIR = Path("logs/live")
ALL_LATEST = LIVE_LOG_DIR / "_all_latest.json"

console = Console()

class Dashboard:
    def __init__(self):
        self.selected_device = None
        self.devices_config = self._load_devices_config()

    def _load_devices_config(self):
        path = Path("config/devices.json")
        if not path.exists():
            return {}
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}

    def _get_data(self):
        live_data = {}
        if ALL_LATEST.exists():
            try:
                with open(ALL_LATEST) as f:
                    live_data = json.load(f)
            except:
                pass
        
        # Merge with config devices so they show up even without traffic
        merged = {}
        for mac, info in self.devices_config.items():
            dev_id = info["id"]
            if dev_id in live_data:
                merged[dev_id] = live_data[dev_id]
            else:
                # Placeholder for device with no live data yet
                merged[dev_id] = {
                    "device_id": dev_id,
                    "device_type": info["type"],
                    "trust_score": 100,
                    "tier": "TRUSTED",
                    "violations": [],
                    "timestamp": "No Data",
                    "signals": []
                }
        return merged

    def _get_alerts(self, device_id):
        path = LIVE_LOG_DIR / f"{device_id}.jsonl"
        if not path.exists():
            return []
        try:
            alerts = []
            with open(path) as f:
                for line in f:
                    entry = json.loads(line)
                    if entry["violations"] or entry["tier"] == "HIGH RISK":
                        alerts.append(entry)
            return alerts[-5:] # last 5
        except:
            return []

    def make_table(self, data):
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("DEVICE_ID", style="bold cyan")
        table.add_column("TYPE", style="dim")
        table.add_column("SCORE", justify="right")
        table.add_column("TIER")
        table.add_column("TOP VIOLATION", style="italic")
        table.add_column("LAST UPDATED", justify="center")

        for dev_id, entry in data.items():
            score = entry["trust_score"]
            tier = entry["tier"]
            
            # Color coding
            color = "green"
            if tier == "HIGH RISK": color = "bold red"
            elif tier == "SUSPICIOUS": color = "orange3"
            elif tier == "MONITOR": color = "yellow"
            
            # Top violation
            top_v = "None"
            if entry["violations"]:
                top_v = entry["violations"][0]["detail"]
                
            style = ""
            if tier == "HIGH RISK" and (int(time.time() * 2) % 2 == 0):
                style = "blink"

            table.add_row(
                dev_id,
                entry["device_type"],
                str(score),
                Text(tier, style=color),
                Text(top_v, style="dim" if top_v == "None" else "bold white"),
                entry["timestamp"].split("T")[-1][:8], # Time only
                style=style
            )
            
            if not self.selected_device:
                self.selected_device = dev_id

        return table

    def make_alerts_panel(self):
        if not self.selected_device:
            return Panel("No alerts.")
            
        alerts = self._get_alerts(self.selected_device)
        content = []
        for a in alerts:
            ts = a["timestamp"].split("T")[-1][:8]
            v = a["violations"][0]["detail"] if a["violations"] else "State Change"
            content.append(f"[{ts}] [bold red]ALERT[/] {v} (Score: {a['trust_score']})")
            
        return Panel("\n".join(content) if content else "No recent alerts.", title=f"Alerts: {self.selected_device}")

    def generate_layout(self):
        data = self._get_data()
        
        layout = Layout()
        layout.split_column(
            Layout(Panel("[bold cyan]THRUSTGUARD[/] Network Trust Monitoring (JSON Mode)", border_style="cyan"), size=3),
            Layout(self.make_table(data), name="table"),
            Layout(self.make_alerts_panel(), size=10)
        )
        return layout

def run_dashboard():
    dash = Dashboard()
    with Live(dash.generate_layout(), refresh_per_second=5, screen=True) as live:
        try:
            while True:
                time.sleep(0.2)
                live.update(dash.generate_layout())
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    run_dashboard()