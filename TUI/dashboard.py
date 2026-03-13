import sys
import os
import time

# Allow running from project root or from TUI/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.console import Console
from rich import box

# Direct Engine Imports as per CONTEXT.md
from engine.trust import get_latest_scores, get_score_history

console = Console()

# ── Terminal-Style Icons & Braille ───────────────────────────────────────────

# Replacing emojis with terminal-native status indicators
STATUS_DATA = {
    "TRUSTED":    {"color": "bold green",  "icon": "[√]", "label": "TRUSTED"},
    "MONITOR":    {"color": "bold yellow", "icon": "[!]", "label": "MONITOR"},
    "SUSPICIOUS": {"color": "bold orange3","icon": "[?]", "label": "SUSPECT"},
    "HIGH RISK":  {"color": "bold red",    "icon": "[X]", "label": "RISKY  "},
    "CALIBRATING":{"color": "dim",         "icon": "[∞]", "label": "CALIB  "},
}

DEVICE_TYPE_ICONS = {
    "camera": "[CAM]",
    "bulb":   "[LIT]",
    "sensor": "[SNR]",
}

# Braille dot patterns for behavioral drift
BRAILLE_SPARK = ["⠀", "⠂", "⠒", "⠖", "⠶", "⠷", "⠿"]
BRAILLE_SNAKE = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# ── Render Helpers ──────────────────────────────────────────────────────────

def _score_color(score: float) -> str:
    if score >= 80: return "green"
    if score >= 60: return "yellow"
    if score >= 40: return "orange3"
    return "red"

def _braille_sparkline(mac_addr: str, width: int = 14) -> Text:
    """Renders high-res behavioral history using braille dots."""
    history = get_score_history(mac_addr)
    if not history:
        return Text(" ".join(["."] * width), style="dim")
    
    # Get last N scores from history list of tuples (timestamp, score)
    recent = [h[1] for h in history[-width:]]
    
    chars = []
    for val in recent:
        # Map 0-100 to index 0-6
        level = min(6, int(val / 100 * 6))
        chars.append(BRAILLE_SPARK[level])
    
    # Left-pad with empty Braille cells for clean look
    padding = ["⠀"] * (width - len(chars))
    return Text("".join(padding + chars), style="cyan")

def _terminal_bar(score: float, width: int = 15) -> Text:
    """Btop-style dotted progress bar."""
    filled_len = int((score / 100) * width)
    bar = "█" * filled_len + "░" * (width - filled_len)
    return Text(bar, style=_score_color(score))

# ── Main Layout Components ───────────────────────────────────────────────────

def render_header(devices: list[dict]) -> Text:
    """Top bar with spinner and counts."""
    counts = {"TRUSTED": 0, "MONITOR": 0, "RISK": 0}
    for d in devices:
        s = d.get("status", "TRUSTED")
        if s in ["HIGH RISK", "SUSPICIOUS"]: counts["RISK"] += 1
        elif s == "MONITOR": counts["MONITOR"] += 1
        else: counts["TRUSTED"] += 1

    spinner = BRAILLE_SNAKE[int(time.time() * 10) % len(BRAILLE_SNAKE)]
    
    header = Text()
    header.append(f" {spinner} THRUSHGUARD LOCAL_ENGINE ", style="bold cyan")
    header.append("│ ", style="dim")
    header.append(f" TRUSTED: {counts['TRUSTED']} ", style="green")
    header.append(f" MONITOR: {counts['MONITOR']} ", style="yellow")
    header.append(f" RISK: {counts['RISK']} ", style="bold red")
    header.append(" │ ", style="dim")
    header.append(f" {time.strftime('%H:%M:%S')} ", style="dim")
    return header

def render_table(devices: list[dict]) -> Table:
    """The main inventory grid."""
    table = Table(box=box.SIMPLE_HEAVY, expand=True, border_style="bright_black")
    table.add_column("STATUS", width=12)
    table.add_column("DEVICE_ID", style="bold white")
    table.add_column("TYPE", width=8)
    table.add_column("SCORE", justify="right", width=6)
    table.add_column("TRUST_BAR", width=18)
    table.add_column("DRIFT_S1", width=16) # Braille Sparkline

    for d in devices:
        status = d.get("status", "TRUSTED")
        s_info = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])
        t_icon = DEVICE_TYPE_ICONS.get(d.get("device_type"), "[DEV]")
        
        # Simulated blink for High Risk
        blink_style = "blink" if status == "HIGH RISK" and (int(time.time() * 2) % 2) else ""
        row_style = "on dark_red" if status == "HIGH RISK" else ""

        table.add_row(
            Text(f"{s_info['icon']} {s_info['label']}", style=f"{s_info['color']} {blink_style}"),
            d["device_id"],
            Text(t_icon, style="dim cyan"),
            Text(str(d["score"]), style=_score_color(d["score"])),
            _terminal_bar(d["score"]),
            _braille_sparkline(d["device_id"]),
            style=row_style
        )
    return table

# ── Dashboard Entry Point ────────────────────────────────────────────────────

def run_dashboard():
    """Main loop for the TUI."""
    try:
        with Live(refresh_per_second=4, screen=True) as live:
            while True:
                devices = get_latest_scores() # Direct engine call
                
                # Assemble Layout
                layout = Layout()
                layout.split_column(
                    Layout(Panel(render_header(devices), border_style="cyan"), size=3),
                    Layout(Panel(render_table(devices), title="[bold]Behavioral Drift Analytics", border_style="bright_black")),
                    Layout(Panel(Text("Commands: attack <id> <type> | inspect <id> | sys_exit: ^C", justify="center", style="dim"), border_style="bright_black"), size=3)
                )
                
                live.update(layout)
                time.sleep(0.2)
    except KeyboardInterrupt:
        console.clear()
        console.print("[bold cyan]ThrushGuard[/] - System Disconnected.\n")

if __name__ == "__main__":
    run_dashboard()
