#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/.venv-ryu/bin/python"
RYU="$ROOT/.venv-ryu/bin/ryu-manager"

if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv-ryu not found. Activate/create the Python 3.9 Ryu environment first."
  exit 1
fi
if [[ ! -x "$RYU" ]]; then
  echo "ERROR: ryu-manager not found in .venv-ryu."
  exit 1
fi

export PAML_MODE="${PAML_MODE:-PAML}"
export PAML_NTL_PERIOD="${PAML_NTL_PERIOD:-30}"
export PAML_FLOW_PACKETS="${PAML_FLOW_PACKETS:-20}"
export PAML_FLOW_IDLE="${PAML_FLOW_IDLE:-0.75}"
export PAML_WINDOW_SIZE="${PAML_WINDOW_SIZE:-5}"
export PAML_ATTACK_THRESHOLD="${PAML_ATTACK_THRESHOLD:-0.60}"
export PAML_PERSISTENCE="${PAML_PERSISTENCE:-2}"
export PAML_ATTACK_RULE_HARD_TIMEOUT="${PAML_ATTACK_RULE_HARD_TIMEOUT:-1}"
export PAML_ATTACKER_IPS="${PAML_ATTACKER_IPS:-10.0.0.40,10.0.0.41,10.0.0.42,10.0.0.43,10.0.0.44,10.0.0.45,10.0.0.46,10.0.0.47,10.0.0.48,10.0.0.49}"
export PAML_BENIGN_IPS="${PAML_BENIGN_IPS:-10.0.0.30,10.0.0.31,10.0.0.32}"

mkdir -p results/raw results/processed results/statistics
rm -f results/raw/controller_events.csv results/raw/controller_metrics_live.json \
      results/raw/phase7_measurements.csv results/raw/ryu_phase7_1.log \
      results/statistics/phase7_final_report_v3.txt

cleanup() {
  set +e
  sudo mn -c >/dev/null 2>&1 || true
  if [[ -n "${RYU_PID:-}" ]]; then
    kill "$RYU_PID" >/dev/null 2>&1 || true
    wait "$RYU_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

sudo mn -c >/dev/null 2>&1 || true

echo "============================================================"
echo " PAML-ATC PHASE 7.1 FINAL v3 — ONE COMMAND REAL TESTBED"
echo "============================================================"
echo

echo "[1/4] Starting Ryu controller on TCP/6653..."
"$RYU" --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py \
  > results/raw/ryu_phase7_1.log 2>&1 &
RYU_PID=$!

for _ in $(seq 1 20); do
  if ss -ltn 2>/dev/null | grep -q ':6653 '; then break; fi
  sleep 1
done
if ! kill -0 "$RYU_PID" >/dev/null 2>&1; then
  echo "ERROR: Ryu stopped during startup."
  cat results/raw/ryu_phase7_1.log
  exit 1
fi
if ! ss -ltn 2>/dev/null | grep -q ':6653 '; then
  echo "ERROR: Ryu did not open TCP/6653."
  cat results/raw/ryu_phase7_1.log
  exit 1
fi

echo "Ryu is listening on TCP/6653."
echo

echo "[2/4] Running Mininet + benign-only NTL learning + live traffic..."
# Mininet is installed by apt, so its supported system Python is used here.
# Environment variables are preserved with sudo -E.
sudo -E /usr/bin/python3 experiments/phase7_experiment.py \
  --quick --controller 127.0.0.1 --port 6653 \
  --mode "$PAML_MODE" --duration "${PAML_DURATION:-5}"

echo
# Give the controller monitor a moment to write its final snapshot.
sleep 1.0
echo "[3/4] Generating final report from measured artifacts..."
"$PY" tools/phase7_report.py

echo
echo "[4/4] Evidence files are ready under results/."
