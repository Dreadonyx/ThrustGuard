"""
capture/sniffer.py — Live Traffic Capture
Uses Scapy AsyncSniffer to aggregate traffic windows.
"""

import os
import json
import time
import math
from pathlib import Path
from collections import Counter
from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, DNSQR

CONFIG_PATH = Path("config/devices.json")

class LiveSniffer:
    def __init__(self, callback, interface="eth0", fast_mode=False):
        self.callback = callback
        self.interface = interface
        self.window_duration = 5 if fast_mode else 60
        self.devices_config = self._load_config()
        self.active_windows = {} # mac -> data

    def _load_config(self):
        if not CONFIG_PATH.exists():
            return {}
        with open(CONFIG_PATH) as f:
            return json.load(f)

    def _calculate_entropy(self, strings):
        if not strings: return 0.0
        s = "".join(strings)
        if not s: return 0.0
        counts = Counter(s)
        probs = [count/len(s) for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def _process_packet(self, pkt):
        if not IP in pkt: return
        
        mac = pkt.src
        device_info = self.devices_config.get(mac, {
            "id": f"unknown-{mac.replace(':', '')}",
            "type": "unknown"
        })
        device_id = device_info["id"]

        if device_id not in self.active_windows:
            self.active_windows[device_id] = {
                "device_id": device_id,
                "device_type": device_info["type"],
                "bytes": 0,
                "packets": 0,
                "ports": set(),
                "dst_ips": set(),
                "dns_queries": [],
                "timestamp": int(time.time())
            }

        win = self.active_windows[device_id]
        win["bytes"] += len(pkt)
        win["packets"] += 1
        
        if TCP in pkt: win["ports"].add(pkt[TCP].dport)
        if UDP in pkt: win["ports"].add(pkt[UDP].dport)
        
        win["dst_ips"].add(pkt[IP].dst)
        
        if pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            win["dns_queries"].append(query)

    def start(self):
        print(f"[*] Starting Sniffer on {self.interface} (Window: {self.window_duration}s)")
        sniffer = AsyncSniffer(iface=self.interface, prn=self._process_packet, store=False)
        sniffer.start()
        
        try:
            while True:
                time.sleep(self.window_duration)
                
                # Snapshot and clear
                finished_windows = self.active_windows
                self.active_windows = {}
                
                for dev_id, win in finished_windows.items():
                    # Calculate entropy
                    win["dns_entropy"] = round(self._calculate_entropy(win["dns_queries"]), 2)
                    # Convert sets to lists for JSON
                    win["ports"] = sorted(list(win["ports"]))
                    win["dst_ips"] = sorted(list(win["dst_ips"]))
                    
                    # Pass to callback (engine/features.py)
                    self.callback(win)
                    
        except KeyboardInterrupt:
            sniffer.stop()

if __name__ == "__main__":
    # Test stub
    def dummy_callback(win):
        print(f"[DEBUG] Window: {json.dumps(win, indent=2)}")
    
    sniffer = LiveSniffer(dummy_callback, interface="Wi-Fi", fast_mode=True)
    sniffer.start()
