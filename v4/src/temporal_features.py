"""Five-flow temporal feature extraction for PAML-ATC V2."""

from __future__ import annotations

import pandas as pd

from config import WINDOW_SIZE

TEMPORAL_BASE = ["flow_packets_per_sec", "fwd_iat_mean", "syn_flag_count"]

TEMPORAL_FEATURES = [
    "flow_packets_per_sec_rm",
    "flow_packets_per_sec_rs",
    "flow_packets_per_sec_delta",
    "fwd_iat_mean_rm",
    "fwd_iat_mean_rs",
    "fwd_iat_mean_delta",
    "syn_flag_count_rm",
    "syn_flag_count_rs",
    "syn_flag_count_delta",
    "syn_fin_ratio",
    "packet_variability_inverse",
    "iat_acceleration",
]


def add_temporal_features(df: pd.DataFrame, window_size: int = WINDOW_SIZE) -> pd.DataFrame:
    """Add temporal features independently inside each ordered sequence.

    The function never sorts or shuffles rows. It expects sequence_id and
    flow_index to describe the chronological order produced by the simulator.
    """
    required = {"sequence_id", "flow_index", "syn_flag_count", "fin_flag_count", "packet_length_variance", "fwd_iat_mean"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns for temporal extraction: {sorted(missing)}")

    out = df.sort_values(["sequence_id", "flow_index"], kind="stable").copy()

    grouped = out.groupby("sequence_id", sort=False)
    for feature in TEMPORAL_BASE:
        rolling = grouped[feature].rolling(window=window_size, min_periods=1)
        out[f"{feature}_rm"] = rolling.mean().reset_index(level=0, drop=True)
        out[f"{feature}_rs"] = rolling.std(ddof=0).fillna(0).reset_index(level=0, drop=True)
        out[f"{feature}_delta"] = grouped[feature].diff().fillna(0)

    out["syn_fin_ratio"] = (out["syn_flag_count"] / (out["fin_flag_count"] + 1e-3)).clip(0, 100)
    out["packet_variability_inverse"] = 1.0 / (out["packet_length_variance"] + 1.0)
    out["iat_acceleration"] = grouped["fwd_iat_mean"].diff().groupby(out["sequence_id"]).diff().fillna(0)

    return out.reset_index(drop=True)
