"""
data/scapy_collector.py — Eclipse Real Packet Capture (Production Path)
Uses PyShark (tshark wrapper) to capture live packets per device MAC/IP.
Produces the same device_window shape as synthetic.py.

NOT used in demo — demo uses synthetic.py.
Switch to this in production by swapping the callback in main.py:

    # Demo:
    from data.synthetic import run_feed
    # Production:
    from data.scapy_collector import run_capture

Requirements:
    pip install pyshark
    sudo apt install tshark       # or wireshark-common
    Run with: sudo python -m data.scapy_collector   (needs raw socket access)
    OR: add your user to the 'wireshark' group and grant capabilities to tshark

Device mapping:
    Edit DEVICE_MAP below to associate observed IPs/MACs with device_id/type.
    In production this comes from your network ARP table or DHCP leases.
"""

import math
import time
import threading
import logging
from collections import defaultdict
from typing import Callable

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

logger = logging.getLogger("eclipse.capture")

# ─────────────────────────────────────────────
# Device Map — edit for your network
# Maps source IP → (device_id, device_type)
# In production: pull from DHCP server or ARP table
# ─────────────────────────────────────────────

DEVICE_MAP: dict[str, tuple[str, str]] = {
    "192.168.1.101": ("cam-01",    "camera"),
    "192.168.1.102": ("cam-02",    "camera"),
    "192.168.1.111": ("bulb-01",   "bulb"),
    "192.168.1.112": ("bulb-02",   "bulb"),
    "192.168.1.121": ("sensor-01", "sensor"),
}

# Capture config
CAPTURE_INTERFACE = "eth0"      # change to wlan0, br0, etc.
WINDOW_SECONDS    = 60          # 60s windows match synthetic.py exactly
BPF_FILTER        = "ip"        # capture all IP traffic; tighten per-device if needed

# ─────────────────────────────────────────────
# Per-device EWMA state (mirrors synthetic.py logic)
# ─────────────────────────────────────────────

_state: dict[str, dict] = {}

def _get_state(device_id: str, init_bytes: float) -> dict:
    if device_id not in _state:
        _state[device_id] = {
            "prev_bytes": init_bytes,
            "ewma":       init_bytes,
            "baseline_samples": [],
            "seen_ips": set(),      # baseline IP set for new_ip_flag
        }
    return _state[device_id]


# ─────────────────────────────────────────────
# Feature extraction helpers
# ─────────────────────────────────────────────

def _shannon_entropy(strings: list[str]) -> float:
    """
    Compute Shannon entropy of character frequency across all DNS query strings.
    H = -Σ p_i * log2(p_i)
    High entropy (>3.5) → potential DNS tunneling.
    """
    if not strings:
        return 0.0

    combined = "".join(strings)
    if not combined:
        return 0.0

    freq: dict[str, int] = defaultdict(int)
    for ch in combined:
        freq[ch] += 1

    total = len(combined)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def _compute_derived(device_id: str, bytes_val: float) -> tuple[float, float, float]:
    """Returns (z_score, ewma_delta, spike_delta) — identical logic to synthetic.py"""
    alpha = 0.3
    state = _get_state(device_id, bytes_val)

    prev_bytes = state["prev_bytes"]
    prev_ewma  = state["ewma"]
    samples    = state["baseline_samples"]

    if len(samples) >= 2:
        mu  = sum(samples) / len(samples)
        std = math.sqrt(sum((x - mu) ** 2 for x in samples) / len(samples))
        z   = (bytes_val - mu) / std if std > 0 else 0.0
    else:
        z = 0.0

    new_ewma   = alpha * bytes_val + (1 - alpha) * prev_ewma
    ewma_delta = abs(bytes_val - new_ewma) / new_ewma if new_ewma > 0 else 0.0
    spike_delta = (bytes_val - prev_bytes) / prev_bytes if prev_bytes > 0 else 0.0

    state["prev_bytes"] = bytes_val
    state["ewma"]       = new_ewma
    samples.append(bytes_val)
    if len(samples) > 50:
        samples.pop(0)

    def clamp(v, lo, hi): return max(lo, min(hi, v))
    return (
        round(clamp(z,           -10.0, 10.0), 4),
        round(clamp(ewma_delta,    0.0,  5.0), 4),
        round(clamp(spike_delta,  -1.0, 10.0), 4),
    )


# ─────────────────────────────────────────────
# Packet accumulator
# One accumulator per device, reset every WINDOW_SECONDS
# ─────────────────────────────────────────────

class _WindowAccumulator:
    def __init__(self, device_id: str, device_type: str):
        self.device_id   = device_id
        self.device_type = device_type
        self.reset()

    def reset(self):
        self.bytes_total  = 0
        self.packet_count = 0
        self.dest_ips:    set[str] = set()
        self.ports_used:  set[int] = set()
        self.dns_queries: list[str] = []
        self.window_start = time.time()

    def add_packet(self, pkt_bytes: int, dest_ip: str, dest_port: int, dns_query: str | None):
        self.bytes_total  += pkt_bytes
        self.packet_count += 1
        self.dest_ips.add(dest_ip)
        self.ports_used.add(dest_port)
        if dns_query:
            self.dns_queries.append(dns_query)

    def flush(self) -> dict:
        """Produce a device_window dict and reset accumulator."""
        bytes_val = self.bytes_total
        state     = _get_state(self.device_id, bytes_val)

        # new_ip_flag — True if any dest IP wasn't in the baseline set
        seen = state["seen_ips"]
        new_ip_flag = bool(self.dest_ips - seen)
        seen.update(self.dest_ips)  # fold new IPs into baseline after flagging

        z_score, ewma_delta, spike_delta = _compute_derived(self.device_id, bytes_val)

        window = {
            "device_id":       self.device_id,
            "device_type":     self.device_type,
            "timestamp":       int(time.time()),
            "bytes":           bytes_val,
            "packets":         self.packet_count,
            "unique_dest_ips": len(self.dest_ips),
            "dns_entropy":     _shannon_entropy(self.dns_queries),
            "ports_used":      sorted(self.ports_used) or [0],
            "new_ip_flag":     new_ip_flag,
            "ewma_delta":      ewma_delta,
            "z_score":         z_score,
            "spike_delta":     spike_delta,
        }

        logger.info(
            "[capture] %s | bytes=%d | pkts=%d | z=%.2f | entropy=%.2f | ports=%s | new_ip=%s",
            self.device_id, bytes_val, self.packet_count,
            z_score, window["dns_entropy"], window["ports_used"], new_ip_flag
        )

        self.reset()
        return window


# ─────────────────────────────────────────────
# Packet parser — extracts fields from PyShark pkt
# ─────────────────────────────────────────────

def _parse_packet(pkt) -> tuple[str | None, int, str, int, str | None]:
    """
    Returns (src_ip, pkt_len, dest_ip, dest_port, dns_query_or_None).
    Returns (None, ...) if packet doesn't match expected shape.
    """
    try:
        src_ip   = pkt.ip.src
        dest_ip  = pkt.ip.dst
        pkt_len  = int(pkt.length)
    except AttributeError:
        return None, 0, "", 0, None

    # Destination port — prefer TCP, fallback UDP
    dest_port = 0
    try:
        dest_port = int(pkt.tcp.dstport)
    except AttributeError:
        try:
            dest_port = int(pkt.udp.dstport)
        except AttributeError:
            pass

    # DNS query extraction
    dns_query = None
    try:
        dns_query = pkt.dns.qry_name
    except AttributeError:
        pass

    return src_ip, pkt_len, dest_ip, dest_port, dns_query


# ─────────────────────────────────────────────
# Main capture loop
# ─────────────────────────────────────────────

def run_capture(
    callback: Callable[[dict], None],
    interface: str = CAPTURE_INTERFACE,
    window_seconds: int = WINDOW_SECONDS,
) -> None:
    """
    Production entry point — mirrors run_feed() signature from synthetic.py.
    Runs in a background thread. Calls callback(device_window) every window_seconds per device.

    Usage in main.py (production swap):
        from data.scapy_collector import run_capture
        from engine.features import enrich_window
        t = threading.Thread(target=run_capture, args=(enrich_window,), daemon=True)
        t.start()
    """
    if not PYSHARK_AVAILABLE:
        logger.error("[capture] PyShark not installed. Run: pip install pyshark")
        raise ImportError("pyshark is required for live packet capture")

    logger.info("[capture] Starting live capture on %s | window=%ds", interface, window_seconds)
    logger.info("[capture] Watching %d devices: %s", len(DEVICE_MAP), list(DEVICE_MAP.values()))

    # Initialize one accumulator per device
    accumulators: dict[str, _WindowAccumulator] = {
        device_id: _WindowAccumulator(device_id, device_type)
        for src_ip, (device_id, device_type) in DEVICE_MAP.items()
        # Use device_id as key (multiple IPs could map to same device — rare for IoT)
        for device_id, device_type in [(device_id, device_type)]
    }

    # Deduplicated IP → device mapping for fast lookup
    ip_to_device: dict[str, str] = {
        src_ip: device_id
        for src_ip, (device_id, _) in DEVICE_MAP.items()
    }

    # Window flush timer — runs in its own thread
    flush_stop = threading.Event()

    def flush_loop():
        while not flush_stop.is_set():
            time.sleep(window_seconds)
            for device_id, acc in accumulators.items():
                if acc.packet_count == 0:
                    # No traffic this window — emit a zero window so engine still updates
                    logger.debug("[capture] %s — zero-traffic window", device_id)
                try:
                    window = acc.flush()
                    callback(window)
                except Exception as exc:
                    logger.error("[capture] flush error for %s: %s", device_id, exc)

    flush_thread = threading.Thread(target=flush_loop, daemon=True)
    flush_thread.start()

    # Packet capture loop (blocking — run this in a dedicated thread)
    try:
        capture = pyshark.LiveCapture(
            interface=interface,
            bpf_filter=BPF_FILTER,
            output_file=None,
        )

        for pkt in capture.sniff_continuously():
            src_ip, pkt_len, dest_ip, dest_port, dns_query = _parse_packet(pkt)

            if src_ip is None:
                continue

            device_id = ip_to_device.get(src_ip)
            if device_id is None:
                continue  # packet from unknown device — ignore

            accumulators[device_id].add_packet(pkt_len, dest_ip, dest_port, dns_query)

    except KeyboardInterrupt:
        logger.info("[capture] Capture stopped by user")
    except Exception as exc:
        logger.error("[capture] Fatal capture error: %s", exc)
        raise
    finally:
        flush_stop.set()


# ─────────────────────────────────────────────
# PCAP replay — feed a saved .pcap file instead of live interface
# Useful for: testing, demos without root, CI
# ─────────────────────────────────────────────

def replay_pcap(
    pcap_path: str,
    callback: Callable[[dict], None],
    window_seconds: int = WINDOW_SECONDS,
) -> None:
    """
    Replay a .pcap file through the same pipeline as live capture.
    Produces device_window dicts identical to live mode.
    Great for testing without root / without real devices.

    Usage:
        from data.scapy_collector import replay_pcap
        from engine.features import enrich_window
        replay_pcap("captures/test_traffic.pcap", enrich_window)
    """
    if not PYSHARK_AVAILABLE:
        raise ImportError("pyshark is required for pcap replay")

    logger.info("[capture] Replaying pcap: %s", pcap_path)

    accumulators: dict[str, _WindowAccumulator] = {
        device_id: _WindowAccumulator(device_id, device_type)
        for src_ip, (device_id, device_type) in DEVICE_MAP.items()
        for device_id, device_type in [(device_id, device_type)]
    }

    ip_to_device = {
        src_ip: device_id
        for src_ip, (device_id, _) in DEVICE_MAP.items()
    }

    capture = pyshark.FileCapture(pcap_path)
    bucket_start = None

    for pkt in capture:
        src_ip, pkt_len, dest_ip, dest_port, dns_query = _parse_packet(pkt)
        if src_ip is None:
            continue

        device_id = ip_to_device.get(src_ip)
        if device_id is None:
            continue

        try:
            pkt_time = float(pkt.sniff_timestamp)
        except Exception:
            continue

        if bucket_start is None:
            bucket_start = pkt_time

        # Flush window when the time bucket expires
        if pkt_time - bucket_start >= window_seconds:
            for dev_id, acc in accumulators.items():
                try:
                    window = acc.flush()
                    callback(window)
                except Exception as exc:
                    logger.error("[capture] replay flush error for %s: %s", dev_id, exc)
            bucket_start = pkt_time

        accumulators[device_id].add_packet(pkt_len, dest_ip, dest_port, dns_query)

    # Final flush for remaining packets
    for acc in accumulators.values():
        if acc.packet_count > 0:
            callback(acc.flush())

    capture.close()
    logger.info("[capture] Pcap replay complete")


# ─────────────────────────────────────────────
# Standalone smoke test
# sudo python -m data.scapy_collector
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    if not PYSHARK_AVAILABLE:
        print("ERROR: pyshark not installed. Run: pip install pyshark")
        sys.exit(1)

    print("=== scapy_collector.py smoke test ===")
    print(f"Interface : {CAPTURE_INTERFACE}")
    print(f"Watching  : {list(DEVICE_MAP.values())}")
    print(f"Window    : {WINDOW_SECONDS}s")
    print("\nCapturing 1 window then exiting...\n")

    windows_received = []

    def _print_window(w: dict):
        windows_received.append(w)
        print(
            f"  {w['device_id']:12s}  bytes={w['bytes']:>9,}  pkts={w['packets']:>5}  "
            f"z={w['z_score']:+.3f}  entropy={w['dns_entropy']:.3f}  "
            f"ports={w['ports_used']}  new_ip={w['new_ip_flag']}"
        )
        if len(windows_received) >= len(DEVICE_MAP):
            print("\nAll devices flushed. Done.")
            import os; os._exit(0)

    run_capture(_print_window, window_seconds=WINDOW_SECONDS)