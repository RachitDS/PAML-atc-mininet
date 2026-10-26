#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$BASE/v4"
PY="${PAML_PYTHON:-$BASE/.venv-ml/bin/python}"
RYU="${PAML_RYU_MANAGER:-$BASE/.venv-ryu/bin/ryu-manager}"
NAME="${1:?campaign name}"; MODE="${2:-MONITOR}"; SEEDS="${3:-11}"
PROFILES="${4:-150:1,300:3,1000:3}"
OUTPUT_ROOT="${PAML_OUTPUT_ROOT:-$BASE/outputs}"
OUT="$OUTPUT_ROOT/$NAME"
if [[ -e "$OUT/controller.log" || -e "$OUT/scenarios.json" ]]; then
  echo "Campaign output already exists: $OUT. Choose a new name." >&2
  exit 1
fi
mkdir -p "$OUT" "$ROOT/results/raw" "$ROOT/results/processed" "$ROOT/results/statistics"
RUNTIME="$(mktemp -d /tmp/cn-roadmap.XXXXXX)"
mkdir -p "$RUNTIME/raw"
echo "$RUNTIME" > "$OUT/runtime_path.txt"
cd "$ROOT"
export PYTHONPATH="$ROOT" PYTHONUNBUFFERED=1 PAML_MODE="$MODE"
export PAML_TRUTH_MANIFEST="$RUNTIME/truth.json" PAML_PACKET_LOG="$RUNTIME/packet_observations.csv" PAML_RAW_DIR="$RUNTIME/raw"
DEFAULT_MODELS="$ROOT/models"
if [[ -f "$ROOT/models_live/training_report.json" ]]; then DEFAULT_MODELS="$ROOT/models_live"; fi
export PAML_MODEL_DIR="${PAML_MODEL_DIR:-$DEFAULT_MODELS}" OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
export PAML_BUFFER_LOGS=1
export PAML_CAPTURE_DIR="$RUNTIME/pcaps"
"$PY" "$BASE/scripts/record_run.py" "$OUT"
mn -c > "$OUT/cleanup.log" 2>&1
"$RYU" --ofp-listen-host 127.0.0.1 --ofp-tcp-listen-port 6653 controller/auditable_controller.py > "$OUT/controller.log" 2>&1 &
PID=$!
cleanup(){
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  cp -a "$RUNTIME/raw" "$OUT/"
  for FILE in packet_observations.csv truth.json; do
    if [[ -f "$RUNTIME/$FILE" ]]; then cp "$RUNTIME/$FILE" "$OUT/"; fi
  done
  mn -c >> "$OUT/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
for _ in $(seq 1 40); do
  kill -0 "$PID" 2>/dev/null || { tail -30 "$OUT/controller.log"; exit 1; }
  if ss -ltn | grep -q ':6653 '; then break; fi
  sleep 1
done
EXTRA=()
if [[ -n "${5:-}" ]]; then EXTRA+=(--skip-json "$5"); fi
if [[ -n "${6:-}" ]]; then EXTRA+=(--only-json "$6"); fi
"$PY" experiments/roadmap_experiment.py --seeds "$SEEDS" --profiles "$PROFILES" --output "$OUT" "${EXTRA[@]}" > "$OUT/experiment.log" 2>&1
sleep 1
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
echo "Completed $NAME $MODE seeds=$SEEDS"
