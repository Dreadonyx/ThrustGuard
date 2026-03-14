# ThrushGuard — Run book & Workflows

## 1. Full Interactive Demo (Recommended)
This runs the engine, FastAPI server, MCP server, synthetic data threads, and the TUI interface, all in one command. It also automatically fires a `dns_tunnel` attack on `cam-02` after the initial baseline burn-in period.

```bash
# Recommended for judges (fast 5-second windows, auto-attack)
ECLIPSE_FAST_MODE=1 .env/bin/python main.py
```

## 2. Testing the TUI Independently
If you want to run the dashboard by itself (useful for iterating on UI components):

```bash
.env/bin/python TUI/dashboard.py
```

## 3. Simulating an Attack Manually
If you want to trigger attacks yourself, open a second terminal while `main.py` is running (or disable automatic attacks by running `ECLIPSE_NO_ATTACK=1 .env/bin/python main.py`).

```bash
# In Terminal 2:
.env/bin/python simulate_attack.py --device cam-02 --attack dns_tunnel
```
Available attacks in `data/simulate_attack.py`: `dns_tunnel`, `botnet`, `exfil`, `port_scan`.

## 4. MCP Server Validation
To test functionality with Claude Desktop or Claude Inspector:
```bash
npx @modelcontextprotocol/inspector .env/bin/python mcp_server.py
```

## 5. Model Training (Initial Setup)
Run this once to bake the IsolationForest base models for `cam`, `bulb`, and `sensor`.
```bash
.env/bin/python data/synthetic.py
.env/bin/python train_models.py
```

## 6. Real Live Packet Capture
Requires a physical network adapter capable of promiscuous mode monitoring IoT devices. Default is `wlp8s0`.
```bash
# Requires root for scapy
sudo ECLIPSE_IFACE=wlp8s0 .env/bin/python main.py --live
```
