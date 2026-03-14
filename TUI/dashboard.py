"""
TUI/dashboard.py — ThrustGuard Interactive Dashboard
btop-inspired layout, live updates, device selection, Ollama incident reports.

Controls:
  1-9         select device by number
  r           generate incident report for selected device
  c           clear violations feed
  q / Ctrl+C  quit

Run standalone:  python TUI/dashboard.py
Run via main.py: from TUI.dashboard import run_dashboard; run_dashboard()
"""

import os
import sys
import time
import json
import queue
import threading
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich import box

from engine.trust import get_latest_scores, get_score_history

# ── Try optional imports ───────────────────────────────────────────────────────

try:
    from engine.features import get_device_states
except ImportError:
    def get_device_states():
        return {}

try:
    from intent.narrator import generate_report, generate_report_fallback
    NARRATOR_AVAILABLE = True
except ImportError:
    NARRATOR_AVAILABLE = False
    def generate_report(device_id, violations, score_history, device_type):
        return None
    def generate_report_fallback(device_id, violations, score_history, device_type):
        return f"## {device_id}\nnarrator.py not found."

# ── Constants ──────────────────────────────────────────────────────────────────

SPARK_CHARS  = "▁▂▃▄▅▆▇█"
BRAILLE_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Rich colour tokens
C_CYAN    = "bright_cyan"
C_DIM     = "grey50"
C_BORDER  = "grey30"
C_SEL_BG  = "on grey15"
C_RISK_BG = "on colour52"        # deep blood red background for HIGH RISK blink

STATUS_DATA = {
    "TRUSTED":     {"color": "bright_green",  "bg": "",            "icon": "●", "short": "TRUSTED  "},
    "MONITOR":     {"color": "yellow",         "bg": "",            "icon": "◐", "short": "MONITOR  "},
    "SUSPICIOUS":  {"color": "dark_orange",    "bg": "",            "icon": "◑", "short": "SUSPECT  "},
    "HIGH RISK":   {"color": "bright_red",     "bg": C_RISK_BG,     "icon": "◉", "short": "HI-RISK  "},
    "CALIBRATING": {"color": C_DIM,            "bg": "",            "icon": "∞", "short": "CALIB... "},
}

DEVICE_ICONS = {
    "camera":     "📷 CAM",
    "bulb":       "💡 LIT",
    "sensor":     "📡 SNR",
    "thermostat": "🌡  THM",
    "router":     "🔗 RTR",
    "lock":       "🔒 LCK",
}

# ── State ──────────────────────────────────────────────────────────────────────

_selected_idx: int   = 0
_violations_feed: list = []
_report_panel: list  = []
_report_device: str  = ""
_report_generating: bool = False
_input_queue: queue.Queue = queue.Queue()
_stop_event  = threading.Event()
_blink_state = 0
_spinner_state = 0

console = Console(highlight=False)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _norm(d: dict) -> dict:
    """Normalise a scores-table row to consistent field names.
    trust.py stores 'tier' and 'violations'; dashboard used to expect
    'status' and 'reasons'. This translates so both layouts work."""
    out = dict(d)
    # tier → status
    if "status" not in out:
        out["status"] = out.get("tier", "CALIBRATING")
    # violations → reasons
    if "reasons" not in out:
        raw = out.get("violations", [])
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = [raw] if raw else []
        out["reasons"] = raw
    # timestamp: ISO string → unix int
    ts = out.get("timestamp", "")
    if isinstance(ts, str):
        try:
            from datetime import datetime as _dt
            out["timestamp"] = int(_dt.fromisoformat(ts).timestamp())
        except Exception:
            out["timestamp"] = int(time.time())
    return out

def _score_color(score) -> str:
    score = int(score) if score is not None else 0
    if score >= 80: return "bright_green"
    if score >= 60: return "yellow"
    if score >= 40: return "dark_orange"
    return "bright_red"

def _sparkline(device_id: str) -> Text:
    history = get_score_history(device_id, limit=10)
    scores  = [h["score"] for h in reversed(history)]
    if not scores:
        return Text("░" * 10, style=C_DIM)
    spark = "".join(SPARK_CHARS[min(7, int(s / 100 * 8))] for s in scores)
    spark = spark.rjust(10, "░")
    return Text(spark, style=_score_color(scores[-1]))

def _score_bar(score, width: int = 18) -> Text:
    score  = int(score) if score is not None else 0
    filled = int((score / 100) * width)
    bar    = "█" * filled + "░" * (width - filled)
    return Text(bar, style=_score_color(score))

def _time_ago(ts) -> str:
    try:
        diff = int(time.time()) - int(ts)
    except Exception:
        return "?"
    if diff < 5:    return "just now"
    if diff < 60:   return f"{diff}s ago"
    if diff < 3600: return f"{diff//60}m ago"
    return f"{diff//3600}h ago"

def _push_violation(device_id: str, reasons: list, score: int):
    global _violations_feed
    ts = datetime.now().strftime("%H:%M:%S")
    for r in reasons:
        _violations_feed.insert(0, (ts, device_id, r, score))
    _violations_feed = _violations_feed[:10]

# ── Layout Panels ──────────────────────────────────────────────────────────────

def _build_header(devices: list) -> Panel:
    trusted    = sum(1 for d in devices if d["status"] in ("TRUSTED",))
    monitoring = sum(1 for d in devices if d["status"] == "MONITOR")
    suspicious = sum(1 for d in devices if d["status"] == "SUSPICIOUS")
    risky      = sum(1 for d in devices if d["status"] == "HIGH RISK")
    calib      = sum(1 for d in devices if d["status"] == "CALIBRATING")

    spinner = BRAILLE_SPIN[_spinner_state % len(BRAILLE_SPIN)]
    clock   = datetime.now().strftime("%H:%M:%S")
    date    = datetime.now().strftime("%a %d %b")

    t = Text()
    t.append(f"  {spinner} ", style=C_CYAN)
    t.append("THRUSHGUARD", style=f"bold {C_CYAN}")
    t.append("  ·  IoT Trust Monitor", style=C_DIM)
    t.append("     ", style="")

    # status pills
    t.append(" ● ", style="bold bright_green"); t.append(f"{trusted} TRUSTED", style="bright_green")
    t.append("   ◐ ", style="bold yellow");      t.append(f"{monitoring} MONITOR", style="yellow")
    if suspicious:
        t.append("   ◑ ", style="bold dark_orange"); t.append(f"{suspicious} SUSPECT", style="dark_orange")
    if risky:
        t.append("   ◉ ", style="bold bright_red");  t.append(f"{risky} HI-RISK", style="bold bright_red")
    if calib:
        t.append("   ∞ ", style=C_DIM);              t.append(f"{calib} CALIB", style=C_DIM)

    t.append("     ", style="")
    t.append(f"{date}  {clock}", style=C_DIM)
    if NARRATOR_AVAILABLE:
        t.append("   AI:phi3 ✓", style="dim bright_green")

    return Panel(t, border_style=C_CYAN, height=3, padding=(0, 1))


def _build_device_table(devices: list) -> Panel:
    table = Table(
        box=box.MINIMAL_DOUBLE_HEAD,
        expand=True,
        border_style=C_BORDER,
        show_header=True,
        header_style=f"bold {C_DIM}",
        padding=(0, 1),
        row_styles=["", ""],
    )
    table.add_column("#",        width=3,  justify="right", no_wrap=True)
    table.add_column("DEVICE",   width=14, no_wrap=True)
    table.add_column("TYPE",     width=10, no_wrap=True)
    table.add_column("SCORE",    width=5,  justify="right", no_wrap=True)
    table.add_column("TRUST BAR",width=20, no_wrap=True)
    table.add_column("STATUS",   width=12, no_wrap=True)
    table.add_column("TREND",    width=11, no_wrap=True)
    table.add_column("UPDATED",  width=10, no_wrap=True)

    device_states = get_device_states()
    blink = (_blink_state % 4 < 2)   # blink at ~2Hz (every 2 of 4 quarter-second ticks)

    for idx, d in enumerate(devices):
        device_id = d["device_id"]
        score     = d.get("score", 0)
        status    = d.get("status", "TRUSTED")
        ts        = d.get("timestamp", int(time.time()))
        reasons   = d.get("reasons", [])

        # Infer device type from device_id prefix if not stored
        dtype = d.get("device_type") or next(
            (t for t in ["camera", "bulb", "sensor", "thermostat", "router", "lock"]
             if device_id.lower().startswith(t[:3])), "unknown"
        )

        # Push new violations into feed
        if reasons and status in ("HIGH RISK", "SUSPICIOUS", "MONITOR"):
            _push_violation(device_id, reasons, score)

        # Calibrating override from pipeline state
        state = device_states.get(device_id, "ACTIVE")
        if state == "CALIBRATING":
            status = "CALIBRATING"
            score  = 0

        s_data     = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])
        type_icon  = DEVICE_ICONS.get(dtype, "⚙  DEV")
        selected   = (idx == _selected_idx)

        # Row background
        if status == "HIGH RISK" and blink:
            row_style = C_RISK_BG
        elif selected:
            row_style = C_SEL_BG
        else:
            row_style = ""

        # Score / bar cells
        if status == "CALIBRATING":
            score_text = Text("---", style=C_DIM)
            bar_text   = Text("░" * 18, style=C_DIM)
            spark      = Text("░" * 10, style=C_DIM)
        else:
            score_text = Text(f"{int(score):>3}", style=f"bold {_score_color(score)}")
            bar_text   = _score_bar(score)
            spark      = _sparkline(device_id)

        # Status cell with icon
        status_text = Text()
        status_text.append(f"{s_data['icon']} ", style=f"bold {s_data['color']}")
        status_text.append(s_data["short"].rstrip(), style=f"bold {s_data['color']}")

        # Row number / selector
        num_text = Text()
        if selected:
            num_text.append(f"▶{idx+1}", style=f"bold {C_CYAN}")
        else:
            num_text.append(f" {idx+1}", style=C_DIM)

        table.add_row(
            num_text,
            Text(device_id, style="bold white" if selected else "white"),
            Text(type_icon, style=C_DIM),
            score_text,
            bar_text,
            status_text,
            spark,
            Text(_time_ago(ts), style=C_DIM),
            style=row_style,
        )

    title = f"[bold {C_CYAN}]IoT Device Inventory[/]"
    if devices and _selected_idx < len(devices):
        sel = devices[_selected_idx]
        title += f"  [dim]▶ {sel['device_id']}[/]"

    return Panel(table, title=title, border_style=C_BORDER, padding=(0, 0))


def _build_violations() -> Panel:
    t = Text()
    if not _violations_feed:
        t.append("\n  No violations detected.", style=C_DIM)
        t.append("\n  All devices operating normally.", style=C_DIM)
    else:
        for ts_str, device_id, reason, score in _violations_feed:
            t.append(f"  {ts_str}  ", style=C_DIM)
            t.append(f"{device_id:<14}", style=f"bold {_score_color(score)}")
            t.append(f"{reason}\n", style="white")

    return Panel(
        t,
        title=f"[bold]⚠  Recent Violations[/]",
        border_style=C_BORDER,
        height=10,
        padding=(0, 1),
    )


def _build_report_panel() -> Panel:
    t = Text()
    if _report_generating:
        spin = BRAILLE_SPIN[_spinner_state % len(BRAILLE_SPIN)]
        t.append(f"\n  {spin} Generating incident report with phi3:mini...\n", style=f"dim {C_CYAN}")
        t.append("\n  This takes 5–10 seconds. Hang tight.\n", style=C_DIM)
    elif _report_panel:
        for line in _report_panel:
            t.append(line + "\n")
    else:
        t.append("\n  Select a device ", style=C_DIM)
        t.append("[1-9]", style=f"bold {C_CYAN}")
        t.append(" then press ", style=C_DIM)
        t.append("[r]", style=f"bold {C_CYAN}")
        t.append(" to generate an AI incident report.\n", style=C_DIM)
        if not NARRATOR_AVAILABLE:
            t.append("\n  [dim red]narrator.py not found — report generation unavailable[/dim red]")

    title = f"[bold {C_CYAN}]🧠 Incident Report[/]"
    if _report_device:
        title += f" [dim]— {_report_device}[/]"

    return Panel(t, title=title, border_style=C_CYAN, height=12, padding=(0, 1))


def _build_input_bar(devices: list) -> Panel:
    t = Text()
    keys = [("[1-9]", "select"), ("[r]", "report"), ("[c]", "clear"), ("[q]", "quit")]
    for key, label in keys:
        t.append(f" {key}", style=f"bold {C_CYAN}")
        t.append(f" {label}  ", style=C_DIM)

    if devices and _selected_idx < len(devices):
        sel    = devices[_selected_idx]
        status = sel.get("status", "TRUSTED")
        s_data = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])
        t.append(" │ ", style=C_DIM)
        t.append(f" {sel['device_id']}", style="bold white")
        t.append(f"  {s_data['icon']} {status}", style=f"bold {s_data['color']}")
        t.append(f"  score=", style=C_DIM)
        t.append(f"{int(sel['score'])}", style=f"bold {_score_color(sel['score'])}")

    return Panel(t, border_style=C_BORDER, height=3, padding=(0, 1))


def _build_layout(devices: list) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header",   size=3),
        Layout(name="main",     ratio=1),
        Layout(name="bottom",   size=22),
        Layout(name="inputbar", size=3),
    )
    layout["main"].update(_build_device_table(devices))
    layout["header"].update(_build_header(devices))
    layout["bottom"].split_row(
        Layout(_build_violations(), name="violations", ratio=1),
        Layout(_build_report_panel(), name="report", ratio=1),
    )
    layout["inputbar"].update(_build_input_bar(devices))
    return layout

# ── Input Thread ───────────────────────────────────────────────────────────────

def _input_thread():
    """Read single keypresses from stdin and push to queue."""
    import termios, tty
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while not _stop_event.is_set():
            ch = sys.stdin.read(1)
            if ch:
                _input_queue.put(ch)
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _handle_input(ch: str, devices: list):
    """Process a keypress."""
    global _selected_idx, _violations_feed, _report_panel, _report_device, _report_generating

    if ch in ("q", "Q", "\x03"):
        _stop_event.set()
        return

    if ch in ("c", "C"):
        _violations_feed = []
        _report_panel    = []
        _report_device   = ""
        return

    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(devices):
            _selected_idx = idx
        return

    if ch in ("r", "R"):
        if not NARRATOR_AVAILABLE:
            _report_panel = ["  [dim]narrator.py not built yet.[/dim]"]
            return
        if _report_generating or not devices:
            return

        sel               = devices[_selected_idx]
        _report_device    = sel["device_id"]
        _report_generating = True
        _report_panel     = []

        def _run_report():
            global _report_panel, _report_generating
            try:
                history = get_score_history(sel["device_id"], limit=10)
                reasons = sel.get("reasons", [])
                report  = generate_report(
                    device_id     = sel["device_id"],
                    violations    = reasons,
                    score_history = [h["score"] for h in reversed(history)],
                    device_type   = sel.get("device_type", "unknown"),
                )
                if not report:
                    report = generate_report_fallback(
                        device_id     = sel["device_id"],
                        violations    = reasons,
                        score_history = [h["score"] for h in reversed(history)],
                        device_type   = sel.get("device_type", "unknown"),
                    )
                if report:
                    os.makedirs("reports", exist_ok=True)
                    fname = f"reports/{sel['device_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                    with open(fname, "w") as f:
                        f.write(report)
                    lines = report.split("\n")[:10]
                    _report_panel = lines + [f"\n  [dim]Saved → {fname}[/dim]"]
                else:
                    _report_panel = ["  [red]Report generation failed.[/red]"]
            except Exception as e:
                _report_panel = [f"  [red]Error: {e}[/red]"]
            finally:
                _report_generating = False

        threading.Thread(target=_run_report, daemon=True, name="narrator").start()

# ── Main Loop ──────────────────────────────────────────────────────────────────

def run_dashboard():
    global _blink_state, _spinner_state, _selected_idx

    input_th = threading.Thread(target=_input_thread, daemon=True, name="input")
    input_th.start()

    try:
        with Live(
            console=console,
            refresh_per_second=4,
            screen=True,
            transient=False,
        ) as live:
            while not _stop_event.is_set():
                # Drain input queue
                while not _input_queue.empty():
                    ch      = _input_queue.get_nowait()
                    devices = [_norm(d) for d in get_latest_scores()]
                    _handle_input(ch, devices)

                _blink_state   += 1
                _spinner_state += 1

                devices = [_norm(d) for d in get_latest_scores()]
                if devices:
                    _selected_idx = min(_selected_idx, len(devices) - 1)

                live.update(_build_layout(devices))
                time.sleep(0.25)

    except KeyboardInterrupt:
        pass
    finally:
        _stop_event.set()
        console.clear()
        console.print(f"\n[bold {C_CYAN}]ThrushGuard[/] — disconnected.\n")


if __name__ == "__main__":
    run_dashboard()
