#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .venv-ryu/bin/activate ]]; then
  source .venv-ryu/bin/activate
elif [[ -f .venv/bin/activate ]]; then
  source .venv/bin/activate
else
  echo "No Ryu virtual environment found (.venv-ryu or .venv)." >&2
  exit 1
fi
ryu-manager --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py
