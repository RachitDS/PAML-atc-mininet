"""Convenience entry point for Phase 7.

Examples:
  python phase7.py --check        # offline checks
  sudo python3 phase7.py --quick  # real Mininet run; Ryu must already run
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--check', action='store_true')
    p.add_argument('--quick', action='store_true')
    p.add_argument('--mode', choices=['PAML','FIXED','NONE'], default='PAML')
    args=p.parse_args()
    if args.check:
        raise SystemExit(subprocess.call([sys.executable,'-m','pytest','-q'], cwd=ROOT))
    cmd=[sys.executable,'experiments/phase7_experiment.py']
    if args.quick: cmd.append('--quick')
    cmd += ['--mode',args.mode]
    raise SystemExit(subprocess.call(cmd, cwd=ROOT))
