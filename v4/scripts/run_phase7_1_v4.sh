#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY_RYU="${ROOT}/.venv-ryu/bin/python"
if [[ ! -x "$PY_RYU" ]]; then PY_RYU="python3"; fi
export PAML_WINDOW_SIZE="${PAML_WINDOW_SIZE:-5}"
if [[ -n "${PAML_ATTACK_THRESHOLD:-}" ]]; then export PAML_ATTACK_THRESHOLD; fi
if [[ -n "${PAML_PERSISTENCE:-}" ]]; then export PAML_PERSISTENCE; fi
export PAML_ATTACK_RULE_HARD_TIMEOUT="${PAML_ATTACK_RULE_HARD_TIMEOUT:-1}"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"
mkdir -p "$ROOT/results/raw" "$ROOT/results/statistics"
rm -f "$ROOT/results/raw/controller_events.csv" "$ROOT/results/raw/controller_metrics_live.json" "$ROOT/results/raw/live_paml_features.csv"
# The controller reads the calibrated threshold/persistence from models unless
# explicit environment overrides are provided.
echo "[V4] Starting Ryu controller..."
"$ROOT/scripts/start_ryu.sh" &
RYU_PID=$!
cleanup(){ kill "$RYU_PID" 2>/dev/null || true; sudo mn -c >/dev/null 2>&1 || true; }
trap cleanup EXIT
sleep 4
SYSTEM_PY="/usr/bin/python3"
"$SYSTEM_PY" "$ROOT/experiments/phase7_experiment.py" --quick --duration "${PAML_DURATION:-5}" --mode PAML
"$PY_RYU" "$ROOT/phase7_report.py"
"$PY_RYU" "$ROOT/tools/compare_feature_distributions_v4.py" || true
"$PY_RYU" "$ROOT/tools/summarize_v4.py" || true
