"""
engine/policy.py — Rule-based scoring
"""

import json
from pathlib import Path

POLICY_DIR = Path("policies")

class PolicyEngine:
    def __init__(self):
        self.cache = {}

    def _get_policy(self, device_type: str):
        if device_type in self.cache:
            return self.cache[device_type]
        
        path = POLICY_DIR / f"{device_type}.json"
        if not path.exists():
            path = POLICY_DIR / "default.json"
        
        with open(path) as f:
            policy = json.load(f)
            self.cache[device_type] = policy
            return policy

    def check(self, window: dict) -> list[dict]:
        policy = self._get_policy(window["device_type"])
        violations = []
        
        # Port check
        for port in window.get("ports_used", []):
            if port not in policy["allowed_ports"]:
                violations.append({
                    "type": "port",
                    "detail": f"unauthorized port {port}",
                    "penalty": -40
                })
        
        # New IP check (simplified for now: if IP discovery is needed, we'd need a persistence layer)
        # The prompt says "new_ip_flag" or similar based on baseline. 
        # For this version, we'll assume enrichment handled the 'new' status if we had access to a baseline.
        # However, the prompt implies checking it here.
        if window.get("new_ip_flag") and not policy["allow_new_ips"]:
            violations.append({
                "type": "new_ip",
                "detail": "contacted new destination IP",
                "penalty": -10
            })

        # DNS Entropy check
        if window["dns_entropy"] > policy["max_dns_entropy"]:
            violations.append({
                "type": "dns_entropy",
                "detail": f"entropy {window['dns_entropy']} exceeds policy {policy['max_dns_entropy']}",
                "penalty": -15
            })

        return violations
