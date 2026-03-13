# ThrushGuard — TUI Build Prompt
> Feed this alongside CONTEXT.md to any AI model to build TUI/dashboard.py

---

## What You Are Building

`TUI/dashboard.py` — the primary interface for ThrushGuard.
A Rich terminal dashboard inspired by btop. Dark, dense, live-updating.
No browser. No HTML. One terminal window.

---

## Visual Reference

Think btop — panels with box borders, dotted progress bars, color-coded rows,
everything updating in real time. Here is the exact target layout:

```
┌ ThrushGuard ──────────────────── TRUSTED: 3  MONITOR: 1  RISK: 1 ── 15:42:07 ┐
├──────────────────────────────────────────────────────────────────────────────────┤
│ Device      Type    Score                     Status        History   Updated    │
│ cam-01      📷      ████████████████░░░░  84  TRUSTED  ✅  ▁▂▃▄▅▆▇  12s ago   │
│ cam-02      📷      ████░░░░░░░░░░░░░░░░  28  HIGH RISK🔴  █▇▅▃▁░░  5s ago ●  │
│ bulb-01     💡      ████████████░░░░░░░░  67  MONITOR  🟡  ▄▄▅▄▄▅▄  31s ago   │
│ bulb-02     💡      ████████████████████ 100  TRUSTED  ✅  ▅▆▇████  18s ago   │
│ sensor-01   🌡      ██████████████████░░  91  TRUSTED  ✅  ▇▇▇▇███  44s ago   │
├──────────────────────────────────────────────────────────────────────────────────┤
│ RECENT VIOLATIONS                                                                │
│  [15:41:03] cam-02  — Port 22 unauthorized          → -40pts  🔴               │
│  [15:41:03] cam-02  — DNS entropy 4.9 > 3.5         → -15pts  🔴               │
│  [15:41:03] cam-02  — Traffic spike Z=8.4           → -20pts  🔴               │
│  [15:41:03] cam-02  — ML anomaly -0.225 < -0.1      →  -8pts  🟠               │
│  [15:40:45] bulb-02 — EWMA drift delta=0.31         →  -5pts  🟡               │
├──────────────────────────────────────────────────────────────────────────────────┤
│ > _                                                                              │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## Engine Imports (direct — no HTTP)

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.trust import get_latest_scores, get_score_history
```

Audit import is optional — wrap in try/except:
```python
try:
    from compliance.audit import AuditLog
    def get_violations():
        events = AuditLog.get_recent(limit=10)
        return [e for e in events if e["event_type"] in ("trust_violation", "anomaly_detected")]
except ImportError:
    def get_violations():
        return []
```

---

## Score Bar Style

Use dotted btop-style bars. `░` for empty, `█` for filled:
```python
def score_bar(score: int, width: int = 18) -> Text:
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    t = Text()
    t.append(bar, style=score_color(score))
    t.append(f"  {score:3d}", style=f"bold {score_color(score)}")
    return t
```

Color mapping:
```python
def score_color(score: int) -> str:
    if score >= 80: return "green"
    if score >= 60: return "yellow"
    if score >= 40: return "dark_orange"
    return "red"
```

---

## Sparkline History

Pull last 8 score values from get_score_history() per device.
Map to braille block chars:
```python
SPARK_CHARS = "▁▂▃▄▅▆▇█"

def sparkline(scores: list[int]) -> str:
    if not scores:
        return "░░░░░░░░"
    scores = scores[-8:]
    return "".join(SPARK_CHARS[min(7, int(s / 100 * 8))] for s in reversed(scores))
```

Color the sparkline the same as the current score color.

---

## HIGH RISK Flash

When a device status is "HIGH RISK":
- Apply `style="on dark_red"` to the entire row
- Append a blinking dot `"●"` after the Updated column
- The blink is simulated by toggling the dot every other refresh cycle
  using a module-level counter: `_blink_state = int(time.time()) % 2`

---

## Stats Bar (header)

```python
scores = get_latest_scores()
trusted    = sum(1 for s in scores if s["score"] >= 80)
monitoring = sum(1 for s in scores if 60 <= s["score"] < 80)
risky      = sum(1 for s in scores if s["score"] < 60)
clock      = datetime.now().strftime("%H:%M:%S")
```

Header panel title string:
```
ThrushGuard        TRUSTED: 3   MONITOR: 1   RISK: 1        15:42:07
```

Use Rich Panel with `title` set to this string, `border_style="cyan"`.

---

## Input Panel

Bottom panel. A simple `> ` prompt line showing the current typed input.
Input is read in a background thread using `input()` or `sys.stdin.readline()`.
The main Live loop reads from a shared queue.

Supported commands:
```
attack <device_id> <attack_type>
  → calls simulate_attack inline for one window
  → example: attack cam-02 dns_tunnel

inspect <device_id>
  → shows last 10 score history + reasons in the violations panel
  → example: inspect cam-02

clear
  → clears the violations feed
```

Show feedback in the violations panel after a command runs.
Unknown commands: show `[red]Unknown command. Try: attack <device> <type> | inspect <device>[/red]`

---

## Refresh Loop

```python
from rich.live import Live

with Live(build_layout(), refresh_per_second=1, screen=True) as live:
    while not _stop_event.is_set():
        live.update(build_layout())
        time.sleep(1)
```

`build_layout()` assembles the full layout fresh every second.
Keep it fast — all it does is read from SQLite (get_latest_scores is a simple SELECT).

---

## Layout Assembly

Use Rich Layout or just stack Panels vertically:

```python
from rich.console import Group

def build_layout() -> Group:
    return Group(
        build_header(),       # Panel — stats bar + clock
        build_device_table(), # Panel — device rows
        build_violations(),   # Panel — recent violation feed
        build_input_panel(),  # Panel — command input
    )
```

Each panel has a colored border. Use `box=box.SIMPLE` or `box.ROUNDED`.
Header border: `"cyan"`. Device table: `"bright_black"`. Violations: `"bright_black"`. Input: `"cyan"`.

---

## Entry Point

```python
def run_dashboard():
    """Called by main.py to launch the TUI."""
    ...

if __name__ == "__main__":
    run_dashboard()
```

---

## Device Icons

```python
DEVICE_ICONS = {
    "camera": "📷",
    "bulb":   "💡",
    "sensor": "🌡",
}
```

---

## Status Icons

```python
STATUS_STYLE = {
    "TRUSTED":     ("green",       "✅"),
    "MONITOR":     ("yellow",      "🟡"),
    "SUSPICIOUS":  ("dark_orange", "🟠"),
    "HIGH RISK":   ("red",         "🔴"),
    "CALIBRATING": ("dim",         "⏳"),
}
```

---

## Terminal Size Handling

Test and handle these widths:
- 80 cols  — minimum, truncate score bar to width=10
- 120 cols — standard, score bar width=18
- 180 cols — wide, add extra padding

Use `console.size.columns` to detect and branch.

---

## Key Constraints

- No asyncio in dashboard.py — use threads only
- No HTTP calls — direct engine imports only
- Must work with `screen=True` in Rich Live (full terminal takeover)
- Ctrl+C must exit cleanly — catch KeyboardInterrupt in run_dashboard()
- If get_latest_scores() returns empty list — show "Waiting for data..." row
- If device is CALIBRATING — show score as "---" and bar as all-░
- All SQLite reads go through engine/trust.py functions — never raw SQL in dashboard.py
