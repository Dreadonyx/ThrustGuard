#!/usr/bin/env bash
# =============================================================================
# demo.sh — Eclipse Live Demo
# =============================================================================
# Layout:
#   LEFT  (70%) → Eclipse TUI (python main.py)
#   RIGHT (30%) → Attack injector output
#
# Usage:
#   ./demo.sh                → dns_tunnel on cam-02 (default)
#   ./demo.sh botnet         → botnet attack
#   ./demo.sh port_scan      → port scan
#   ./demo.sh exfil          → data exfiltration
#   ./demo.sh reset          → kill session, wipe DB, clean slate
# =============================================================================

set -e

ATTACK=${1:-dns_tunnel}
DEVICE="cam-02"
INTERVAL=20
SESSION="eclipse"
DB="eclipse.db"
PYTHON=$(command -v python3 || command -v python)

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; DIM='\033[2m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[ECLIPSE]${RESET} $1"; }
ok()   { echo -e "${GREEN}  ✓${RESET} $1"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $1"; }
err()  { echo -e "${RED}  ✗${RESET} $1"; exit 1; }

# ── Deps check ────────────────────────────────────────────────────────────────
command -v tmux &>/dev/null   || err "tmux not found. Install: sudo pacman -S tmux"
command -v $PYTHON &>/dev/null || err "Python not found"

# ── Reset mode ────────────────────────────────────────────────────────────────
if [[ "$1" == "reset" ]]; then
    log "Resetting Eclipse..."
    tmux kill-session -t "$SESSION" 2>/dev/null && ok "Killed tmux session '$SESSION'" || warn "No session to kill"
    rm -f "$DB" && ok "Wiped $DB"
    rm -f policies/cam-*.json policies/bulb-*.json policies/sensor-*.json 2>/dev/null || true
    ok "Wiped auto-generated device policies"
    log "Clean slate. Run ./demo.sh to start fresh."
    exit 0
fi

# ── Validate attack ───────────────────────────────────────────────────────────
VALID="dns_tunnel botnet port_scan exfil"
[[ " $VALID " =~ " $ATTACK " ]] || err "Unknown attack: $ATTACK. Valid: $VALID"

# ── Train models if missing ───────────────────────────────────────────────────
if [[ ! -f "models/cam_baseline.pkl" ]]; then
    warn "ML models missing — training now..."
    $PYTHON train_models.py && ok "Models trained"
fi

# ── Kill stale session ────────────────────────────────────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true
sleep 0.3

# =============================================================================
# BUILD TMUX LAYOUT
# =============================================================================
# New session, start detached, rename window
tmux new-session  -d -s "$SESSION" -x 220 -y 50 -n "eclipse-demo"

# Split: left 70% = TUI, right 30% = attack panel
tmux split-window -h  -t "$SESSION:0"
tmux select-pane  -t "$SESSION:0.0"
tmux resize-pane  -t "$SESSION:0.0" -x "70%"

# ── LEFT PANE — Eclipse TUI ───────────────────────────────────────────────────
tmux send-keys -t "$SESSION:0.0" \
    "clear && ECLIPSE_FAST_MODE=1 $PYTHON main.py" Enter

# ── RIGHT PANE — Attack sequencer ────────────────────────────────────────────
# Build the attack script inline so right pane runs autonomously
tmux send-keys -t "$SESSION:0.1" "clear" Enter
tmux send-keys -t "$SESSION:0.1" "cat << 'ATTACK_EOF'
╔══════════════════════════════════╗
║   ECLIPSE — ATTACK SEQUENCER     ║
║   Attack : $ATTACK
║   Target : $DEVICE
║   Windows: 3  Interval: ${INTERVAL}s
╚══════════════════════════════════╝
ATTACK_EOF" Enter

# Wait for calibration then run attack
# Calibration = 10 windows × 5s (FAST_MODE) = 50s + buffer = 60s
tmux send-keys -t "$SESSION:0.1" \
"echo '' && \
echo '  Waiting 60s for device calibration...' && \
for i in 60 55 50 45 40 35 30 25 20 15 10 5; do \
    printf \"\r  Injecting attack in \${i}s...   \"; sleep 5; \
done && \
printf \"\r  ✓ Calibration complete. Launching attack...\n\n\" && \
$PYTHON data/simulate_attack.py \
    --device $DEVICE \
    --attack $ATTACK \
    --interval $INTERVAL && \
echo '' && \
echo '  ✓ Attack sequence complete.' && \
echo '  Watch LEFT pane — score recovering +2/window' && \
echo '  Run: ./demo.sh reset   to wipe and restart'" Enter

# ── Attach to session ─────────────────────────────────────────────────────────
log "Launching Eclipse demo (tmux session: $SESSION)"
log "Attack: ${RED}${ATTACK}${RESET} → ${DEVICE} in ~60s"
echo ""
echo -e "  ${DIM}Detach anytime:  Ctrl+B then D${RESET}"
echo -e "  ${DIM}Kill session:    ./demo.sh reset${RESET}"
echo ""

tmux attach-session -t "$SESSION"
