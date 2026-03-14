"""
TUI/dashboard.py — ThrushGuard Dashboard
Clean rewrite — no Rich Live, no tty conflicts.
Uses os.system('clear') + Rich Console.print each frame.

Controls: [1-9] select  [r] AI report  [i] inspect  [c] clear  [q] quit
"""

import os, sys, time, json, queue, threading, select
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
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
    def generate_report_fallback(did, v, h, t):
        return f"## {did}\nViolations:\n" + "\n".join(f"- {x}" for x in v)

# ── Constants ──────────────────────────────────────────────────────────────────

SPARK = "▁▂▃▄▅▆▇█"
SPIN  = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

STATUS_DATA = {
    "TRUSTED":     {"color": "green",       "icon": "✓", "label": "TRUSTED "},
    "MONITOR":     {"color": "yellow",      "icon": "!", "label": "MONITOR "},
    "SUSPICIOUS":  {"color": "dark_orange", "icon": "?", "label": "SUSPECT "},
    "HIGH RISK":   {"color": "red",         "icon": "✕", "label": "HI-RISK "},
    "CALIBRATING": {"color": "dim",         "icon": "∞", "label": "CALIB..."},
}

ICONS = {
    "camera": "[CAM]", "bulb": "[LIT]", "sensor": "[SNR]",
    "thermostat": "[THM]", "router": "[RTR]", "lock": "[LCK]",
}

# ── Global state ───────────────────────────────────────────────────────────────

_sel     = 0
_viols   = []      # [(ts_str, device_id, reason, score)]
_seen_ts = {}      # device_id → ts int, for dedup
_rlines  = []      # report panel lines
_rdevice = ""
_rgen    = False
_tick    = 0
_stop    = threading.Event()

console = Console(highlight=False)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _color(score):
    s = int(float(score or 0))
    if s >= 80: return "green"
    if s >= 60: return "yellow"
    if s >= 40: return "dark_orange"
    return "red"

def _bar(score, w=16):
    s = int(float(score or 0))
    f = int((s / 100) * w)
    return Text("█"*f + "░"*(w-f), style=_color(s))

def _spark(did, w=8):
    rows   = get_score_history(did, limit=w)
    scores = [int(float(r.get("score") or 0)) for r in reversed(rows)]
    if not scores: return Text("░"*w, style="dim")
    chars  = "".join(SPARK[min(7, int(s/100*8))] for s in scores)
    return Text(chars.rjust(w, "░"), style=_color(scores[-1]))

def _status(d):
    return d.get("status") or d.get("tier") or "TRUSTED"

def _ts(d):
    raw = d.get("timestamp") or time.time()
    try:    return int(float(raw))
    except:
        try:    return int(datetime.fromisoformat(str(raw)).timestamp())
        except: return int(time.time())

def _ago(ts):
    d = int(time.time()) - ts
    if d < 5:    return "now"
    if d < 60:   return f"{d}s"
    if d < 3600: return f"{d//60}m"
    return f"{d//3600}h"

def _reasons(d):
    raw = d.get("reasons", [])
    if isinstance(raw, str):
        try:    raw = json.loads(raw)
        except: return []
    out = []
    for r in raw:
        if isinstance(r, dict):
            out.append(r.get("reason") or f"{r.get('type','?')} {r.get('value','')}")
        else:
            out.append(str(r))
    return out

def _infer_type(did):
    for t in ICONS:
        if did.startswith(t[:3]): return t
    return "unknown"

# ── Panels ─────────────────────────────────────────────────────────────────────

def _header(devices):
    trusted = sum(1 for d in devices if _status(d) == "TRUSTED")
    monitor = sum(1 for d in devices if _status(d) == "MONITOR")
    risky   = sum(1 for d in devices if _status(d) in ("HIGH RISK", "SUSPICIOUS"))
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
        t.append("AI:phi3  │  ", style="dim green")
    t.append(clock, style="dim")
    return Panel(t, border_style="cyan", height=3)


def _table(devices):
    tbl = Table(box=box.SIMPLE_HEAVY, expand=True,
                border_style="bright_black",
                header_style="bold bright_black", padding=(0, 1))
    tbl.add_column("#",      width=3,  justify="right")
    tbl.add_column("DEVICE", width=13)
    tbl.add_column("TYPE",   width=7)
    tbl.add_column("SCORE",  width=5,  justify="right")
    tbl.add_column("TRUST",  width=18)
    tbl.add_column("STATUS", width=10)
    tbl.add_column("DRIFT",  width=9)
    tbl.add_column("AGO",    width=5)

    states   = get_device_states()
    blink_on = (_tick % 2 == 0)

    if not devices:
        tbl.add_row("", Text("─── waiting for device data ───", style="dim"),
                    "", "", "", "", "", "")
        return Panel(tbl, title="[bold]IoT Device Inventory[/]", border_style="bright_black")

    for i, d in enumerate(devices):
        did    = d["device_id"]
        score  = int(float(d.get("score") or 0))
        status = _status(d)
        ts     = _ts(d)
        dtype  = d.get("device_type") or _infer_type(did)
        icon   = ICONS.get(dtype, "[DEV]")
        rs     = _reasons(d)

        if states.get(did) == "CALIBRATING":
            status = "CALIBRATING"

        # push to violations feed (dedup)
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        if rs and status in ("HIGH RISK", "SUSPICIOUS", "MONITOR"):
            if _seen_ts.get(did) != ts:
                _seen_ts[did] = ts
                for r in rs:
                    _viols.insert(0, (ts_str, did, r, score))
                while len(_viols) > 8:
                    _viols.pop()

        sel  = (i == _sel)
        risk = (status == "HIGH RISK")
        sd   = STATUS_DATA.get(status, STATUS_DATA["TRUSTED"])

        if risk and blink_on: row_style = "on dark_red"
        elif sel:             row_style = "on grey19"
        else:                 row_style = ""

        num = Text(f"▶{i+1}" if sel else f" {i+1}",
                   style="bold cyan" if sel else "dim")

        if status == "CALIBRATING":
            sc_t = Text("---", style="dim")
            br_t = Text("░"*16, style="dim")
            sp_t = Text("░"*8,  style="dim")
        else:
            sc_t = Text(str(score), style=f"bold {_color(score)}")
            br_t = _bar(score)
            sp_t = _spark(did)

        st_t = Text()
        st_t.append(f"{sd['icon']} ", style=sd["color"])
        st_t.append(sd["label"], style=f"bold {sd['color']}")

        tbl.add_row(
            num,
            Text(did, style="bold white" if sel else "white"),
            Text(icon, style="dim cyan"),
            sc_t, br_t, st_t, sp_t,
            Text(_ago(ts), style="dim"),
            style=row_style,
        )

    title = "[bold]IoT Device Inventory[/]"
    if _sel < len(devices):
        title += f"  [dim]selected: {devices[_sel]['device_id']}[/]"
    return Panel(tbl, title=title, border_style="bright_black")


def _violations():
    t = Text()
    if not _viols:
        t.append("No violations detected.", style="dim")
    else:
        for ts_str, did, reason, score in _viols:
            t.append(f" {ts_str} ", style="dim")
            t.append(f"{did:<12}", style=f"bold {_color(score)}")
            t.append(f" {reason}\n", style="white")
    return Panel(t, title="[bold]Violations[/]", border_style="bright_black", height=12)


def _report():
    t = Text()
    if _rgen:
        spin = SPIN[_tick % len(SPIN)]
        t.append(f"\n  {spin} Generating report via phi3:mini...\n", style="dim cyan")
        t.append(f"  Device: {_rdevice}   (~8 seconds)\n", style="dim")
    elif _rlines:
        for line in _rlines:
            t.append(line + "\n")
    else:
        t.append("\n  Select device ", style="dim")
        t.append("[1-9]", style="bold cyan")
        t.append("  then press ", style="dim")
        t.append("[r]", style="bold cyan")
        t.append(" AI report  or  ", style="dim")
        t.append("[i]", style="bold cyan")
        t.append(" instant inspect\n", style="dim")
        if not NARRATOR_AVAILABLE:
            t.append("\n  [dim]narrator.py not found[/dim]\n")
    title = "[bold]Incident Report[/]"
    if _rdevice:
        title += f"  [dim]— {_rdevice}[/]"
    return Panel(t, title=title, border_style="cyan", height=12)


def _keybindings(devices):
    t = Text()
    t.append(" [1-9]", style="bold cyan"); t.append(" select  ", style="dim")
    t.append("[r]",    style="bold cyan"); t.append(" report  ", style="dim")
    t.append("[i]",    style="bold cyan"); t.append(" inspect  ", style="dim")
    t.append("[c]",    style="bold cyan"); t.append(" clear  ", style="dim")
    t.append("[q]",    style="bold cyan"); t.append(" quit", style="dim")
    if devices and _sel < len(devices):
        d  = devices[_sel]
        st = _status(d)
        sd = STATUS_DATA.get(st, STATUS_DATA["TRUSTED"])
        sc = int(float(d.get("score") or 0))
        t.append("  │  ", style="dim")
        t.append(d["device_id"], style="bold white")
        t.append(f"  {sd['icon']} {st}", style=f"bold {sd['color']}")
        t.append(f"  score={sc}", style=f"bold {_color(sc)}")
    return Panel(t, border_style="bright_black", height=3)

# ── Input (non-blocking via select) ───────────────────────────────────────────

def _setup_term():
    import termios, tty
    fd  = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    return fd, old

def _restore_term(fd, old):
    import termios
    termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _poll_key(fd):
    r, _, _ = select.select([sys.stdin], [], [], 0)
    if r:
        return sys.stdin.read(1)
    return None

# ── Input handler ──────────────────────────────────────────────────────────────

def _handle(ch, devices):
    global _sel, _viols, _seen_ts, _rlines, _rdevice, _rgen

    if ch in ("q", "Q", "\x03"):
        _stop.set(); return

    if ch in ("c", "C"):
        _viols.clear(); _seen_ts.clear()
        _rlines.clear(); _rdevice = ""
        return

    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(devices): _sel = idx
        return

    if ch in ("i", "I") and devices:
        sel     = devices[_sel]
        history = get_score_history(sel["device_id"], limit=10)
        scores  = [int(float(r.get("score") or 0)) for r in reversed(history)]
        rs      = _reasons(sel)
        _rdevice = sel["device_id"]
        _rlines  = [
            f"## Inspect — {sel['device_id']}",
            f"Score: {int(float(sel.get('score') or 0))}  Status: {_status(sel)}",
            f"Trend: {' → '.join(str(s) for s in scores)}",
            "",
            "Violations:" if rs else "No active violations.",
        ] + [f"  - {r}" for r in rs]
        return

    if ch in ("r", "R") and devices and not _rgen:
        if not NARRATOR_AVAILABLE:
            _rlines = ["  narrator.py not found."]; return
        sel      = devices[_sel]
        _rdevice = sel["device_id"]
        _rgen    = True
        _rlines  = []

        def _run():
            global _rlines, _rgen
            try:
                history = get_score_history(sel["device_id"], limit=10)
                scores  = [int(float(r.get("score") or 0)) for r in reversed(history)]
                rs      = _reasons(sel)
                dtype   = sel.get("device_type") or _infer_type(sel["device_id"])
                report  = generate_report(sel["device_id"], rs, scores, dtype)
                if not report:
                    report = generate_report_fallback(sel["device_id"], rs, scores, dtype)
                os.makedirs("reports", exist_ok=True)
                fname = f"reports/{sel['device_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                with open(fname, "w") as f:
                    f.write(report)
                lines   = report.split("\n")
                _rlines = lines[:12] + [f"[dim]→ {fname}[/dim]"]
            except Exception as e:
                _rlines = [f"[red]Error: {e}[/red]"]
            finally:
                _rgen = False

        threading.Thread(target=_run, daemon=True).start()

# ── Main loop ──────────────────────────────────────────────────────────────────

def run_dashboard():
    global _tick, _sel

    fd, old_term = _setup_term()
    sys.stdout.write("\033[?25l"); sys.stdout.flush()  # hide cursor

    _last_render = 0
    _last_devices = None

    try:
        while not _stop.is_set():
            ch = _poll_key(fd)
            if ch:
                devices = get_latest_scores()
                _handle(ch, devices)
                _last_devices = None  # force redraw on keypress

            now = time.time()
            # Redraw at most once per second, or immediately on keypress
            if now - _last_render < 1.0 and _last_devices is not None:
                time.sleep(0.05)
                continue

            _tick += 1
            _last_render = now
            devices = get_latest_scores()
            _last_devices = devices
            if devices:
                _sel = min(_sel, len(devices) - 1)

            sys.stdout.write("\033[H"); sys.stdout.flush()  # cursor to top, no flicker
            console.print(_header(devices))
            console.print(_table(devices))
            console.print(Columns([_violations(), _report()], equal=True, expand=True))
            console.print(_keybindings(devices))
            sys.stdout.write("\033[J"); sys.stdout.flush()  # clear below

            time.sleep(0.05)

    except KeyboardInterrupt:
        pass
    finally:
        _restore_term(fd, old_term)
        sys.stdout.write("\033[?25h"); sys.stdout.flush()  # show cursor
        sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()
        console.print("\n[bold cyan]ThrushGuard[/] — disconnected.\n")


if __name__ == "__main__":
    run_dashboard()
