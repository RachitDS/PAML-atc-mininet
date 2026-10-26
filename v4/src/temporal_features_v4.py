"""Exact offline/online temporal feature construction for V4."""
from __future__ import annotations
from collections import defaultdict, deque
import numpy as np
import pandas as pd
from src.v4_schema import BASE_FEATURES_V4, TEMPORAL_FEATURES_V4, ALL_FEATURES_V4

AUX = ["syn_flag_count", "fin_flag_count", "packet_length_variance"]
TEMPORAL_BASE = ["flow_packets_per_sec", "fwd_iat_mean", "syn_flag_count"]

def build_temporal_row(flow: dict, history: deque) -> dict:
    history.append(dict(flow))
    vals = list(history)
    row = dict(flow)
    for feature in TEMPORAL_BASE:
        a = np.asarray([float(v.get(feature, 0.0)) for v in vals], dtype=float)
        row[f"{feature}_rm"] = float(a.mean())
        row[f"{feature}_rs"] = float(a.std(ddof=0))
        row[f"{feature}_delta"] = float(a[-1] - a[-2]) if len(a) > 1 else 0.0
    syn = float(row.get("syn_flag_count", 0.0))
    fin = float(row.get("fin_flag_count", 0.0))
    variance = float(row.get("packet_length_variance", 0.0))
    row["syn_fin_ratio"] = float(np.clip(syn / (fin + 1e-3), 0.0, 100.0))
    row["packet_variability_inverse"] = float(1.0 / (variance + 1.0))
    if len(vals) >= 3:
        iat = np.asarray([float(v.get("fwd_iat_mean", 0.0)) for v in vals], dtype=float)
        row["iat_acceleration"] = float(iat[-1] - 2.0 * iat[-2] + iat[-3])
    else:
        row["iat_acceleration"] = 0.0
    return row

def add_temporal_features_v4(df: pd.DataFrame, window_size: int = 5) -> pd.DataFrame:
    required = set(BASE_FEATURES_V4) | set(AUX) | {"sequence_id", "flow_index"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing V4 temporal columns: {sorted(missing)}")
    out = df.sort_values(["sequence_id", "flow_index"], kind="stable").copy()
    histories = defaultdict(lambda: deque(maxlen=window_size))
    rows = []
    for rec in out.to_dict(orient="records"):
        row = build_temporal_row(rec, histories[rec["sequence_id"]])
        rows.append(row)
    result = pd.DataFrame(rows, index=out.index).sort_index()
    for col in ALL_FEATURES_V4:
        out[col] = result[col].to_numpy()
    return out.reset_index(drop=True)
