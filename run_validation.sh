#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${PAML_PYTHON:-$BASE/.venv-ml/bin/python}"
export PAML_MODEL_DIR="$BASE/v4/models_live"
SEEDS='121,132,143,154,165,176,187,198,209,220'
OUTPUT_ROOT="${PAML_OUTPUT_ROOT:-$BASE/outputs}"
for MODE in MONITOR NONE FIXED PAML; do
  bash "$BASE/run_campaign.sh" "validation-$MODE" "$MODE" "$SEEDS" '150:1,500:3,1000:3'
  "$PY" "$BASE/audit_campaign.py" "$OUTPUT_ROOT/validation-$MODE" > "$OUTPUT_ROOT/validation-$MODE/audit.log"
done
