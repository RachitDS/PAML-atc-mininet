"""Post-process Phase-7 raw CSV into mean/SD summaries."""
from __future__ import annotations

from pathlib import Path
import pandas as pd


def summarize(raw_path: str | Path, out_path: str | Path):
    df = pd.read_csv(raw_path)
    numeric = [c for c in df.columns if c not in {"seed", "scenario", "protocol", "mode"}]
    summary = df.groupby(["scenario", "protocol", "mode"])[numeric].agg(["mean", "std"])
    summary.to_csv(out_path)
    return summary
