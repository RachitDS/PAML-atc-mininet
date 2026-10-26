"""Print a compact V4 diagnostic summary after a live run."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
for p in [ROOT/"results/processed/training_metrics_v4.json", ROOT/"results/statistics/v4_feature_drift.json"]:
    if p.exists():
        print(f"\n=== {p.name} ===")
        d=json.loads(p.read_text())
        if "mean" in d: print("10-seed mean:",d["mean"]); print("10-seed SD:",d["sd"])
        if "flags" in d:
            print("Live-vs-training |SMD| >= 1:", [k for k,v in d["flags"].items() if v])
