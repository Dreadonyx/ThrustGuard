"""
engine/drift.py — Statistical anomaly scoring
"""

class DriftEngine:
    def check(self, window: dict) -> list[dict]:
        signals = []
        
        # Z-Score
        z = window.get("z_score", 0.0)
        if z > 3.0:
            signals.append({
                "type": "z_score",
                "value": z,
                "penalty": -20
            })
            
        # EWMA
        ewma_d = window.get("ewma_delta", 0.0)
        if ewma_d > 0.3:
            signals.append({
                "type": "ewma",
                "value": ewma_d,
                "penalty": -5
            })
            
        # Entropy (Global threshold)
        h = window["dns_entropy"]
        if h > 3.5:
            signals.append({
                "type": "entropy",
                "value": h,
                "penalty": -15
            })
            
        return signals
