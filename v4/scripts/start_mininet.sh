#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sudo python3 mininet_lab/ics_topology.py --controller 127.0.0.1 --port 6653
