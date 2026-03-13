#!/usr/bin/env bash
# =============================================================================
# reset_data.sh — TrustGuard Demo Reset Script
# =============================================================================
# Clears all runtime-generated device data so the system starts from a
# completely clean state on the next run. Safe to run between demo sessions.
#
# What this resets:
#   • logs/live/       — per-device JSON state + aggregated _all_latest.json
#   • logs/synthetic/  — synthetically generated traffic logs
#   • compliance/      — audit SQLite database & generated reports
#   • __pycache__      — compiled Python bytecode (cosmetic clean)
#
# What this PRESERVES (intentionally):
#   • models/*.pkl     — trained IsolationForest models (takes time to retrain)
#   • config/          — device MAC→ID mapping
#   • data/            — simulation scripts
#   • .venv/           — Python virtual environment
#
# Usage:
#   bash reset_data.sh              # reset all data
#   bash reset_data.sh --dry-run   # preview what would be deleted
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Resolve script location (works regardless of CWD) ─────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  echo -e "${YELLOW}[DRY RUN] No files will actually be deleted.${RESET}\n"
fi

# ── Helper functions ──────────────────────────────────────────────────────────
section() { echo -e "\n${BOLD}${CYAN}══ $1 ══${RESET}"; }
ok()      { echo -e "  ${GREEN}✔${RESET}  $1"; }
skip()    { echo -e "  ${YELLOW}⊘${RESET}  $1 (not found, skipping)"; }
info()    { echo -e "  ${CYAN}→${RESET}  $1"; }

remove_dir() {
  local path="$1"
  local label="${2:-$path}"
  if [ -d "$path" ]; then
    if $DRY_RUN; then
      info "Would remove directory: $label"
    else
      rm -rf "$path"
      ok "Removed: $label"
    fi
  else
    skip "$label"
  fi
}

remove_glob() {
  local dir="$1"
  local pattern="$2"
  local label="$3"
  local found
  found=$(find "$dir" -maxdepth 1 -name "$pattern" 2>/dev/null | head -1)
  if [ -n "$found" ]; then
    if $DRY_RUN; then
      info "Would remove files matching: $dir/$pattern"
    else
      find "$dir" -maxdepth 1 -name "$pattern" -delete
      ok "Cleared: $label"
    fi
  else
    skip "$label"
  fi
}

recreate_dir() {
  local path="$1"
  local label="${2:-$path}"
  if ! $DRY_RUN; then
    mkdir -p "$path"
    ok "Re-created empty dir: $label"
  else
    info "Would re-create empty dir: $label"
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${RED}"
echo "  ████████╗██████╗ ██╗   ██╗███████╗████████╗"
echo "     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝"
echo "     ██║   ██████╔╝██║   ██║███████╗   ██║   "
echo "     ██║   ██╔══██╗██║   ██║╚════██║   ██║   "
echo "     ██║   ██║  ██║╚██████╔╝███████║   ██║   "
echo "     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   "
echo -e "${RESET}${BOLD}          TrustGuard — Demo Data Reset${RESET}"
echo -e "          Project: ${CYAN}${PROJECT_ROOT}${RESET}"
echo ""

# ── Confirmation prompt (skip in dry-run) ────────────────────────────────────
if ! $DRY_RUN; then
  echo -e "${YELLOW}⚠  This will permanently delete all live logs, audit DB, and cached state.${RESET}"
  read -rp "   Proceed? [y/N] " confirm
  case "$confirm" in
    [yY][eE][sS]|[yY]) ;;
    *) echo -e "\n${CYAN}Reset cancelled.${RESET}"; exit 0 ;;
  esac
fi

# ── 1. Live device logs ───────────────────────────────────────────────────────
section "Live Device Logs  (logs/live/)"
remove_dir  "$PROJECT_ROOT/logs/live"       "logs/live/"
recreate_dir "$PROJECT_ROOT/logs/live"      "logs/live/"

# ── 2. Synthetic traffic logs ─────────────────────────────────────────────────
section "Synthetic Traffic Logs  (logs/synthetic/)"
remove_dir  "$PROJECT_ROOT/logs/synthetic"      "logs/synthetic/"
recreate_dir "$PROJECT_ROOT/logs/synthetic"     "logs/synthetic/"

# ── 3. Compliance / audit artefacts ──────────────────────────────────────────
section "Compliance & Audit  (compliance/)"
remove_glob "$PROJECT_ROOT/compliance" "*.db"    "compliance/*.db  (audit SQLite)"
remove_glob "$PROJECT_ROOT/compliance" "*.txt"   "compliance/*.txt (reports)"
remove_glob "$PROJECT_ROOT/compliance" "*.json"  "compliance/*.json"

# ── 4. Python bytecode cache ──────────────────────────────────────────────────
section "Python Bytecode Cache  (__pycache__/)"
find "$PROJECT_ROOT" \
     -not -path "$PROJECT_ROOT/.venv/*" \
     -type d -name "__pycache__" | while read -r cache; do
  remove_dir "$cache" "${cache#$PROJECT_ROOT/}"
done

# ── 5. Individual device reset (optional) ────────────────────────────────────
# You can scope the reset to a single device by setting DEVICE_ID:
#   DEVICE_ID=cam-01 bash reset_data.sh
if [[ -n "${DEVICE_ID:-}" ]]; then
  section "Single-device reset  (device: $DEVICE_ID)"
  DEV_JSONL="$PROJECT_ROOT/logs/live/${DEVICE_ID}.jsonl"
  if [ -f "$DEV_JSONL" ]; then
    if $DRY_RUN; then
      info "Would remove: $DEV_JSONL"
    else
      rm -f "$DEV_JSONL"
      ok "Removed: logs/live/${DEVICE_ID}.jsonl"
    fi
  else
    skip "logs/live/${DEVICE_ID}.jsonl"
  fi
  # Also purge that device's entry from _all_latest.json using Python
  ALL_LATEST="$PROJECT_ROOT/logs/live/_all_latest.json"
  if [ -f "$ALL_LATEST" ] && ! $DRY_RUN; then
    python3 - <<PYEOF
import json, sys
path = "$ALL_LATEST"
try:
    with open(path) as f:
        data = json.load(f)
    data.pop("$DEVICE_ID", None)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  \033[32m✔\033[0m  Removed '$DEVICE_ID' from _all_latest.json")
except Exception as e:
    print(f"  \033[33m⊘\033[0m  Could not update _all_latest.json: {e}")
PYEOF
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════${RESET}"
if $DRY_RUN; then
  echo -e "${BOLD}${YELLOW}  [DRY RUN] No files were deleted.${RESET}"
else
  echo -e "${BOLD}${GREEN}  ✔  Reset complete. System is clean.${RESET}"
fi
echo -e "${BOLD}${GREEN}═══════════════════════════════════════${RESET}"
echo ""
echo -e "  Next steps:"
echo -e "  ${CYAN}1.${RESET} python train_models.py   ${YELLOW}# only if models are missing${RESET}"
echo -e "  ${CYAN}2.${RESET} python main.py            ${YELLOW}# start the dashboard${RESET}"
echo -e "  ${CYAN}3.${RESET} python data/simulate_attack.py --device cam-01 --attack dns_tunnel"
echo ""
