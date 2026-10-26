#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PAML_SETUP_PYTHON:-python3.12}"
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-venv python3-dev \
  tcpdump iperf3 iputils-ping net-tools build-essential
"$PYTHON" -m venv "$BASE/.venv-ml"
"$BASE/.venv-ml/bin/python" -m pip install -r "$BASE/requirements-ml.lock.txt"
"$PYTHON" -m venv "$BASE/.venv-ryu"
"$BASE/.venv-ryu/bin/python" -m pip install setuptools==67.6.1 wheel==0.48.0
"$BASE/.venv-ryu/bin/python" -m pip install --no-build-isolation -r "$BASE/requirements-ryu.lock.txt"
"$BASE/.venv-ryu/bin/python" "$BASE/scripts/patch_ryu_compat.py"
echo 'Environments ready. See README.md for tests and live campaigns.'
