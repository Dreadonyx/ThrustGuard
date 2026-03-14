"""
TUI/dashboard.py — ThrushGuard Interactive Dashboard
btop-inspired layout, live updates, device selection, Ollama incident reports.
"""

import os
import sys
import time
import json
import queue
import threading
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from engine.trust import get_latest_scores, get_score_history

try:
    from engine.features import get_device_states
except ImportError:
    def get_device_states(): return {}

try:
    from intent.narrator import generate_report, generate_report_fallback
    NARRATOR_AVAILABLE = True
except ImportError:
    NARRATOR_AVAILABLE = False
    def generate_report(*a, **k): return None
    def generate_report_fallback(device_id, violations, score_history, device_type):
        return f"## {device_id}\nOllama unavailable. Violations:\n" + "\n".join(f"- {v}" for v in violations)


SPARK = "▁▂▃▄▅▆▇█"
SPIN  = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

DEVICE_ICONS = {
    "camera": "[CAM]", "bulb": "[LIT]", "sensor": "[SNR]",
    "thermostat": "[THM]", "router": "[RTR]", "lock": "[LCK]",
}

STATUS_DATA = {
    "TRUSTED":     {"color": "green",       "icon": "✓", "label": "TRUSTED "},
    "MONITOR":     {"color": "yellow",      "icon": "!", "label": "MONITOR "},
    "SUSPICIOUS":  {"color": "dark_orange", "icon": "?", "label": "SUSPECT "},
    "HIGH RISK":   {"color": "red",         "icon": "✕", "label": "HI-RISK "},
    "CALIBRATING": {"color": "dim",         "icon": "∞", "label": "CALIB..."},
}


_selected_idx:      int  = 0
_violations_feed:   list = []        # [(ts_str, device_id, reason, score), ...]
_last_seen_ts:      dict = {}        # device_id → timestamp, for dedup
_report_panel:      list = []        # lines shown in report panel
_report_device:     str  = ""
_report_generating: bool = False
_input_queue:       queue.Queue = queue.Queue()
_stop_event:        threading.Event = threading.Event()
_tick:              int  = 0

console = Console()


def score_color(score: int) -> str:
    if score >= 80: return "green"
    if score >= 60: return "yellow"
    if score >= 40: return "dark_orange"
    return "red"

def score_bar(score: int, width: int = 16) -> Text:
    filled = int((score / 100) * width)
    return Text("█" * filled + "░" * (width - filled), style=score_color(score))

def sparkline(device_id: str, width: int = 8) -> Text:
    rows   = get_score_history(device_id, limit=width)
    scores = [r["score"] for r in reversed(rows)]
    if not scores:
        return Text("░" * width, style="dim")
    chars = "".join(SPARK[min(7, int(s / 100 * 8))] for s in scores)
    return Text(chars.rjust(width, "░"), style=score_color(scores[-1]))

def time_ago(ts: int) -> str:
    diff = int(time.time()) - ts
    if diff < 5:    return "now"
    if diff < 60:   return f"{diff}s"
    if diff < 3600: return f"{diff//60}m"
    return f"{diff//3600}h"

def infer_type(device_id: str) -> str:
    for t in DEVICE_ICONS:
        if device_id.startswith(t[:3]):
            return t
    return "unknown"

def parse_reasons(raw) -> list:
    if isinstance(raw, list): return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw or "[]")
        except json.JSONDecodeError:
            return [raw] if raw else []
    return []


def build_header(devices: list) -> Panel:
    trusted = sum(1 for d in devices if d.get("tier", d.get("status", "")) == "TRUSTED")
    monitor = sum(1 for d in devices if d.get("tier", d.get("status", "")) == "MONITOR")
    risky   = sum(1 for d in devices if d.get("tier", d.get("status", "")) in ("HIGH RISK", "SUSPICIOUS"))
    spin    = SPIN[_tick % len(SPIN)]
    clock   = datetime.now().strftime("%H:%M:%S")

    t = Text()
    t.append(f" {spin} ", style="cyan")
    t.append("THRUSHGUARD  LOCAL_ENGINE", style="bold cyan")
    t.append("  │  ", style="dim")
    t.append(f"✓ {trusted}", style="bold green")
    t.append("  ")
    t.append(f"! {monitor}", style="bold yellow")
    t.append("  ")
    t.append(f"✕ {risky}", style="bold red")
    t.append("  │  ", style="dim")
    if NARRATOR_AVAILABLE:
        t.append("AI:phi3", style="dim green")
        t.append("  │  ", style="dim")
    t.append(clock, style="dim")

    return Panel(t, border_style="cyan", height=3)


def build_table(devices: list) -> Panel:
    cols = console.size.width
    bar_width  = 18 if cols >= 140 else 14 if cols >= 100 else 10
    show_drift = cols >= 100
    show_type  = cols >= 80

    table = Table(
        box=box.SIMPLE_HEAVY, expand=True,
        border_style="bright_black",
        header_style="bold bright_black",
        padding=(0, 1),
    )
    table.add_column("#",      width=3,          justify="right")
    table.add_column("DEVICE", width=13)
    if show_type:
        table.add_column("TYPE",  width=7)
    table.add_column("SCORE",  width=5,          justify="right")
    table.add_column("TRUST",  width=bar_width+2)
    table.add_column("STATUS", width=11)
    if show_drift:
        table.add_column("DRIFT", width=9)

    device_states = get_device_states()
    blink_on = (_tick % 2 == 0)

    if not devices:
        table.add_row("", Text("Waiting for device data...", style="dim"), "", "", "", "")
        return Panel(table, title="[bold]IoT Device Inventory[/]", border_style="bright_black")

    for idx, d in enumerate(devices):
        did    = d["device_id"]
        score  = d.get("score", d.get("trust_score", 0))
        status = d.get("status", d.get("tier", "TRUSTED"))
        ts     = d.get("timestamp", int(time.time()))
        
        # Handle parsed timestamp format
        if isinstance(ts, str):
            try:
                ts = int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
            except:
                ts = int(time.time())

        # Calibrating override
        if device_states.get(did) == "CALIBRATING":
            status = "CALIBRATING"

        reasons  = parse_reasons(d.get("reasons", d.get("violations", [])))
        selected = (idx == _selected_idx)
        is_risk  = (status == "HIGH RISK")
        s_data   = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])
        dtype    = d.get("device_type") or infer_type(did)
        icon     = DEVICE_ICONS.get(dtype, "[DEV]")

        # Row style
        if is_risk and blink_on:
            row_style = "on dark_red"
        elif selected:
            row_style = "on grey19"
        else:
            row_style = ""

        # Number + selection indicator
        num = Text(
            f"▶{idx+1}" if selected else f" {idx+1}",
            style="bold cyan" if selected else "dim"
        )

        # Score + bar
        if status == "CALIBRATING":
            score_t = Text("---", style="dim")
            bar_t   = Text("░" * bar_width, style="dim")
            spark_t = Text("░" * 8, style="dim")
        else:
            score_t = Text(str(score), style=f"bold {score_color(score)}")
            bar_t   = score_bar(score, bar_width)
            spark_t = sparkline(did)

        # Status cell
        status_t = Text()
        status_t.append(f"{s_data['icon']} ", style=s_data["color"])
        status_t.append(s_data["label"], style=f"bold {s_data['color']}")

        row = [num, Text(did, style="bold white" if selected else "white")]
        if show_type:
            row.append(Text(icon, style="dim cyan"))
        row += [score_t, bar_t, status_t]
        if show_drift:
            row.append(spark_t)

        table.add_row(*row, style=row_style)

        # Push violations to feed (dedup by timestamp)
        if reasons and _last_seen_ts.get(did) != ts:
            _last_seen_ts[did] = ts
            ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            for r in reasons:
                # Handle dictionary reasons (detail/reason attributes)
                text = r
                if isinstance(r, dict):
                    text = r.get("detail", r.get("reason", str(r)))
                _violations_feed.insert(0, (ts_str, did, text, score))
            while len(_violations_feed) > 8:
                _violations_feed.pop()

    title = "[bold]IoT Device Inventory[/]"
    if _selected_idx < len(devices):
        sel = devices[_selected_idx]
        title += f"  [dim]selected: {sel['device_id']}[/]"

    return Panel(table, title=title, border_style="bright_black")


def build_violations() -> Panel:
    t = Text()
    if not _violations_feed:
        t.append("No violations detected.", style="dim")
    else:
        for ts_str, did, reason, score in _violations_feed:
            t.append(f" {ts_str} ", style="dim")
            t.append(f"{did:<12}", style=f"bold {score_color(score)}")
            t.append(f"\n   {reason}\n", style="white")

    return Panel(t, title="[bold]Violations[/]", border_style="bright_black")


def build_report() -> Panel:
    t = Text()

    if _report_generating:
        spin = SPIN[_tick % len(SPIN)]
        t.append(f"\n  {spin} ", style="cyan")
        t.append("Generating incident report...\n", style="dim cyan")
        t.append(f"\n  Model: phi3:mini via Ollama\n", style="dim")
        t.append(f"  Device: {_report_device}\n", style="dim")
        t.append(f"\n  This takes 5-10 seconds.\n", style="dim")

    elif _report_panel:
        for line in _report_panel:
            t.append(line + "\n")

    else:
        t.append("\n  Select a device ", style="dim")
        t.append("[1-9]", style="bold cyan")
        t.append(" then press ", style="dim")
        t.append("[r]", style="bold cyan")
        t.append(" for AI report  or  ", style="dim")
        t.append("[i]", style="bold cyan")
        t.append(" for instant inspect.\n", style="dim")
        if not NARRATOR_AVAILABLE:
            t.append("\n  [dim red]narrator.py not found — [r] unavailable[/dim red]\n")

    title = "[bold]Incident Report[/]"
    if _report_device:
        title += f"  [dim]— {_report_device}[/]"

    return Panel(t, title=title, border_style="cyan")


def build_keybindings(devices: list) -> Panel:
    t = Text()
    t.append(" [1-9]", style="bold cyan"); t.append(" select  ", style="dim")
    t.append("[r]",    style="bold cyan"); t.append(" AI report  ", style="dim")
    t.append("[i]",    style="bold cyan"); t.append(" inspect  ", style="dim")
    t.append("[c]",    style="bold cyan"); t.append(" clear  ", style="dim")
    t.append("[q]",    style="bold cyan"); t.append(" quit", style="dim")

    if devices and _selected_idx < len(devices):
        sel    = devices[_selected_idx]
        status = sel.get("status", sel.get("tier", "TRUSTED"))
        score  = sel.get("score", sel.get("trust_score", 100))
        s_data = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])
        t.append("  │  ", style="dim")
        t.append(f"{sel['device_id']}", style="bold white")
        t.append(f"  {s_data['icon']} {status}", style=f"bold {s_data['color']}")
        t.append(f"  score={score}", style=f"bold {score_color(score)}")

    return Panel(t, border_style="bright_black", height=3)


def build_layout(devices: list) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(build_header(devices),    name="header",   size=3),
        Layout(build_table(devices),     name="table",    ratio=1),
        Layout(name="bottom",            size=14),
        Layout(build_keybindings(devices), name="keys",   size=3),
    )
    layout["bottom"].split_row(
        Layout(build_violations(), name="violations"),
        Layout(build_report(),     name="report"),
    )
    return layout


def _input_thread():
    if os.name == 'nt':
        import msvcrt
        while not _stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                try:
                    _input_queue.put(ch.decode('utf-8'))
                except Exception:
                    pass
            time.sleep(0.05)
        return

    try:
        import termios, tty
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not _stop_event.is_set():
                import select
                r, _, _ = select.select([sys.stdin], [], [], 0.1)
                if r:
                    ch = sys.stdin.read(1)
                    if ch: _input_queue.put(ch)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass


def handle_input(ch: str, devices: list):
    global _selected_idx, _violations_feed, _last_seen_ts
    global _report_panel, _report_device, _report_generating

    # Quit
    if ch in ("q", "Q", "\x03"):
        _stop_event.set()
        return

    # Clear
    if ch in ("c", "C"):
        _violations_feed.clear()
        _last_seen_ts.clear()
        _report_panel.clear()
        _report_device = ""
        return

    # Select device
    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(devices):
            _selected_idx = idx
        return

    # [r] AI incident report
    if ch in ("r", "R"):
        if _report_generating or not devices: return
        if not NARRATOR_AVAILABLE:
            _report_panel = ["  [red]narrator.py not built.[/red]"]
            return
        sel = devices[_selected_idx]
        _report_device    = sel["device_id"]
        _report_generating = True
        _report_panel      = []

        def _run():
            global _report_panel, _report_generating
            try:
                history = get_score_history(sel["device_id"], limit=10)
                scores  = [h["score"] for h in reversed(history)]
                reasons = parse_reasons(sel.get("reasons", sel.get("violations", [])))
                dtype   = sel.get("device_type") or infer_type(sel["device_id"])
                
                # Format reasons correctly if dicts
                formatted_reasons = []
                for r in reasons:
                    if isinstance(r, dict):
                        formatted_reasons.append(r.get("detail", r.get("reason", str(r))))
                    else:
                        formatted_reasons.append(str(r))

                report = generate_report(sel["device_id"], formatted_reasons, scores, dtype)
                if not report:
                    report = generate_report_fallback(sel["device_id"], formatted_reasons, scores, dtype)

                os.makedirs("reports", exist_ok=True)
                fname = f"reports/{sel['device_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                with open(fname, "w") as f: f.write(report)

                lines = report.split("\n")
                _report_panel = lines[:12] + [f"[dim]Saved → {fname}[/dim]"]
            except Exception as e:
                _report_panel = [f"[red]Error: {e}[/red]"]
            finally:
                _report_generating = False

        threading.Thread(target=_run, daemon=True, name="narrator").start()
        return

    # [i] Instant inspect — no Ollama
    if ch in ("i", "I"):
        if not devices: return
        sel     = devices[_selected_idx]
        history = get_score_history(sel["device_id"], limit=10)
        scores  = [h["score"] for h in reversed(history)]
        reasons = parse_reasons(sel.get("reasons", sel.get("violations", [])))
        status  = sel.get("status", sel.get("tier", "TRUSTED"))
        score   = sel.get("score", sel.get("trust_score", 100))
        
        # Format reasons correctly if dicts
        formatted_reasons = []
        for r in reasons:
            if isinstance(r, dict):
                formatted_reasons.append(r.get("detail", r.get("reason", str(r))))
            else:
                formatted_reasons.append(str(r))

        _report_device = sel["device_id"]
        _report_panel  = [
            f"## Inspect — {sel['device_id']}",
            f"Score: {score}  Status: {status}",
            f"Trend: {' → '.join(str(s) for s in scores)}",
            "",
            "Violations:" if formatted_reasons else "No active violations.",
        ] + [f"  - {r}" for r in formatted_reasons]
        return


def run_dashboard():
    global _tick, _selected_idx

    threading.Thread(target=_input_thread, daemon=True, name="input").start()

    try:
        with Live(refresh_per_second=4, screen=True, console=console) as live:
            while not _stop_event.is_set():
                # Drain input
                while not _input_queue.empty():
                    ch = _input_queue.get_nowait()
                    devices = get_latest_scores()
                    handle_input(ch, devices)

                _tick += 1
                devices = get_latest_scores()
                if devices:
                    _selected_idx = min(_selected_idx, len(devices) - 1)

                live.update(build_layout(devices))
                time.sleep(0.25)

    except KeyboardInterrupt:
        pass
    finally:
        _stop_event.set()
        console.clear()
        console.print("\n[bold cyan]ThrushGuard[/] — disconnected.\n")


if __name__ == "__main__":
    run_dashboard()
