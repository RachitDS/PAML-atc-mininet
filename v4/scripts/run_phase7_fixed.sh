#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
export PAML_MODE=FIXED
export FIXED_THRESHOLD_PPS=200
export PAML_ATTACKER_IPS="10.0.0.40,10.0.0.41,10.0.0.42,10.0.0.43,10.0.0.44,10.0.0.45,10.0.0.46,10.0.0.47,10.0.0.48,10.0.0.49"
ryu-manager --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py
