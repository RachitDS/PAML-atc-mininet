"""Realistic synthetic CIC-DDoS2019-inspired traffic generator for Phase 1B.

This remains SYNTHETIC data. It is designed as a methodology/development
benchmark, not as a replacement for the original CIC-DDoS2019 dataset.

Phase 1B adds controlled overlap between benign and attack traffic, benign
burst cases, weak/evasive attacks, per-flow noise, temporal intensity changes,
and randomized protocol metadata so that the detector faces non-trivial
false-positive and false-negative cases.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

from config import RANDOM_SEED

BASE_FEATURES = [
    "flow_duration", "fwd_packet_length_mean", "bwd_packet_length_mean",
    "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_iat_mean",
    "bwd_iat_mean", "active_mean", "idle_mean", "fwd_packets_per_sec",
    "bwd_packets_per_sec", "packet_length_variance", "fin_flag_count",
    "syn_flag_count", "rst_flag_count", "protocol_encoded", "down_up_ratio",
]

ATTACK_TYPES = ["ICMP_Flood", "SYN_Flood", "UDP_Flood", "HTTP_Flood", "Slowloris"]
CLASSES = ["Benign"] + ATTACK_TYPES
RATE_FEATURES = {"flow_packets_per_sec", "fwd_packets_per_sec", "bwd_packets_per_sec", "flow_bytes_per_sec"}

# Synthetic calibration values. They intentionally overlap after Phase-1B
# perturbations; they are not measurements from a live network.
PROFILES: Dict[str, Dict[str, Tuple[float, float, float, float]]] = {
    "Benign": {
        "flow_duration": (2_500_000, 3_000_000, 100, 120_000_000),
        "fwd_packet_length_mean": (520, 380, 0, 1500), "bwd_packet_length_mean": (480, 350, 0, 1500),
        "flow_bytes_per_sec": (45_000, 80_000, 0, 1_000_000), "flow_packets_per_sec": (120, 200, 0.1, 5_000),
        "fwd_iat_mean": (25_000, 40_000, 10, 500_000), "bwd_iat_mean": (28_000, 45_000, 10, 500_000),
        "active_mean": (800_000, 600_000, 0, 5_000_000), "idle_mean": (1_200_000, 900_000, 0, 10_000_000),
        "fwd_packets_per_sec": (60, 100, 0.1, 2_500), "bwd_packets_per_sec": (60, 100, 0.1, 2_500),
        "packet_length_variance": (85_000, 70_000, 0, 500_000), "fin_flag_count": (1.2, 1.5, 0, 10),
        "syn_flag_count": (1.1, 1.3, 0, 8), "rst_flag_count": (0.3, 0.8, 0, 5), "down_up_ratio": (1.05, 0.3, 0, 5),
    },
    "UDP_Flood": {
        "flow_duration": (15_000, 8_000, 100, 60_000), "fwd_packet_length_mean": (1400, 80, 1000, 1500),
        "bwd_packet_length_mean": (0, 5, 0, 20), "flow_bytes_per_sec": (1_800_000, 400_000, 500_000, 5_000_000),
        "flow_packets_per_sec": (28_000, 8_000, 5_000, 100_000), "fwd_iat_mean": (35, 20, 5, 500),
        "bwd_iat_mean": (0, 1, 0, 10), "active_mean": (12_000, 5_000, 1_000, 50_000), "idle_mean": (500, 200, 50, 2_000),
        "fwd_packets_per_sec": (28_000, 8_000, 5_000, 100_000), "bwd_packets_per_sec": (0.5, 0.5, 0, 5),
        "packet_length_variance": (800, 400, 100, 5_000), "fin_flag_count": (0, .1, 0, 1), "syn_flag_count": (0, .1, 0, 1),
        "rst_flag_count": (0, .1, 0, 1), "down_up_ratio": (0, .01, 0, .1),
    },
    "SYN_Flood": {
        "flow_duration": (8_000, 3_000, 500, 30_000), "fwd_packet_length_mean": (60, 15, 40, 80),
        "bwd_packet_length_mean": (0, 5, 0, 20), "flow_bytes_per_sec": (850_000, 300_000, 100_000, 3_000_000),
        "flow_packets_per_sec": (22_000, 8_000, 3_000, 80_000), "fwd_iat_mean": (45, 25, 5, 500),
        "bwd_iat_mean": (0, 1, 0, 10), "active_mean": (7_000, 3_000, 500, 30_000), "idle_mean": (300, 100, 50, 1_000),
        "fwd_packets_per_sec": (22_000, 8_000, 3_000, 80_000), "bwd_packets_per_sec": (.2, .3, 0, 3),
        "packet_length_variance": (200, 80, 50, 1_000), "fin_flag_count": (0, .1, 0, 1), "syn_flag_count": (18.5, 5, 5, 50),
        "rst_flag_count": (.1, .3, 0, 3), "down_up_ratio": (0, .01, 0, .1),
    },
    "ICMP_Flood": {
        "flow_duration": (12_000, 5_000, 100, 50_000), "fwd_packet_length_mean": (64, 8, 56, 84),
        "bwd_packet_length_mean": (0, 2, 0, 10), "flow_bytes_per_sec": (1_200_000, 350_000, 200_000, 4_000_000),
        "flow_packets_per_sec": (18_000, 6_000, 2_000, 70_000), "fwd_iat_mean": (55, 20, 10, 400),
        "bwd_iat_mean": (0, 1, 0, 5), "active_mean": (10_000, 4_000, 1_000, 40_000), "idle_mean": (400, 150, 50, 1_500),
        "fwd_packets_per_sec": (18_000, 6_000, 2_000, 70_000), "bwd_packets_per_sec": (.1, .2, 0, 2),
        "packet_length_variance": (50, 20, 10, 200), "fin_flag_count": (0, 0, 0, 0), "syn_flag_count": (0, 0, 0, 0),
        "rst_flag_count": (0, 0, 0, 0), "down_up_ratio": (0, .01, 0, .1),
    },
    "HTTP_Flood": {
        "flow_duration": (180_000, 120_000, 10_000, 600_000), "fwd_packet_length_mean": (450, 200, 100, 1500),
        "bwd_packet_length_mean": (380, 180, 50, 1500), "flow_bytes_per_sec": (380_000, 200_000, 50_000, 1_500_000),
        "flow_packets_per_sec": (1_800, 800, 200, 8_000), "fwd_iat_mean": (550, 300, 50, 5_000),
        "bwd_iat_mean": (600, 320, 50, 5_000), "active_mean": (150_000, 80_000, 10_000, 500_000), "idle_mean": (25_000, 15_000, 1_000, 100_000),
        "fwd_packets_per_sec": (900, 400, 100, 4_000), "bwd_packets_per_sec": (900, 400, 100, 4_000),
        "packet_length_variance": (65_000, 40_000, 5_000, 300_000), "fin_flag_count": (1.8, 1.2, 0, 8),
        "syn_flag_count": (1.5, 1.0, 0, 6), "rst_flag_count": (.8, .9, 0, 5), "down_up_ratio": (.95, .25, .2, 3),
    },
    "Slowloris": {
        "flow_duration": (8_000_000, 3_000_000, 1_000_000, 30_000_000), "fwd_packet_length_mean": (200, 100, 50, 500),
        "bwd_packet_length_mean": (150, 80, 30, 400), "flow_bytes_per_sec": (1_200, 600, 100, 8_000),
        "flow_packets_per_sec": (8, 4, 1, 30), "fwd_iat_mean": (12_000, 5_000, 2_000, 50_000),
        "bwd_iat_mean": (15_000, 6_000, 3_000, 60_000), "active_mean": (7_000_000, 2_000_000, 500_000, 20_000_000),
        "idle_mean": (80_000, 40_000, 10_000, 300_000), "fwd_packets_per_sec": (4, 2, .5, 15),
        "bwd_packets_per_sec": (4, 2, .5, 15), "packet_length_variance": (25_000, 15_000, 2_000, 100_000),
        "fin_flag_count": (.1, .3, 0, 3), "syn_flag_count": (.8, .5, 0, 4), "rst_flag_count": (.1, .3, 0, 3),
        "down_up_ratio": (.9, .3, .2, 2.5),
    },
}

PROTOCOL = {"UDP_Flood": 1, "SYN_Flood": 0, "ICMP_Flood": 2, "HTTP_Flood": 0, "Slowloris": 0}


def _sample(rng: np.random.Generator, spec: Tuple[float, float, float, float]) -> float:
    mean, std, lo, hi = spec
    if std == 0:
        return float(mean)
    return float(np.clip(rng.normal(mean, std), lo, hi))


def _blend(a: float, b: float, weight_b: float) -> float:
    return a * (1.0 - weight_b) + b * weight_b


def _profile_value(rng, label: str, feature: str, intensity: float) -> float:
    value = _sample(rng, PROFILES[label][feature])
    if feature in RATE_FEATURES:
        value *= intensity
    return value


def generate_sequence(label: str, sequence_id: int, n_flows: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate one ordered sequence using vectorized NumPy sampling."""
    phase = float(rng.uniform(0, 2 * np.pi))
    base_trend = float(rng.normal(0.0, 0.045))
    flow_index = np.arange(n_flows)
    wave = 0.055 * np.sin(phase + flow_index / 4.5)
    drift = base_trend * (flow_index / max(1, n_flows - 1))
    intensity = np.clip(1.0 + wave + drift + rng.normal(0, 0.045, n_flows), 0.68, 1.38)

    hard_case = rng.random()
    if label == "Benign" and hard_case < 0.22:
        burst_target = str(rng.choice(ATTACK_TYPES))
        blend_strength = float(rng.uniform(0.35, 0.70))
    elif label != "Benign" and hard_case < 0.28:
        burst_target = "Benign"
        blend_strength = float(rng.uniform(0.30, 0.62))
    else:
        burst_target = None
        blend_strength = 0.0

    data = {
        "sequence_id": np.full(n_flows, sequence_id, dtype=int),
        "flow_index": flow_index,
        "label": np.full(n_flows, int(label != "Benign"), dtype=int),
        "attack_type": [label] * n_flows,
        "hard_case": np.full(n_flows, int(burst_target is not None), dtype=int),
    }

    for feature in BASE_FEATURES:
        if feature == "protocol_encoded":
            if label == "Benign":
                data[feature] = rng.choice([0, 1, 2], size=n_flows, p=[0.50, 0.30, 0.20]).astype(float)
            else:
                expected = PROTOCOL[label]
                vals = np.full(n_flows, expected, dtype=float)
                mask = rng.random(n_flows) < 0.25
                vals[mask] = rng.choice([0, 1, 2], size=int(mask.sum()))
                data[feature] = vals
            continue

        mean, std, lo, hi = PROFILES[label][feature]
        if std == 0:
            value = np.full(n_flows, mean, dtype=float)
        else:
            value = rng.normal(mean, std, n_flows)
            value = np.clip(value, lo, hi)
        if feature in RATE_FEATURES:
            value *= intensity

        if burst_target is not None:
            bmean, bstd, blo, bhi = PROFILES[burst_target][feature]
            if bstd == 0:
                reference = np.full(n_flows, bmean, dtype=float)
            else:
                reference = np.clip(rng.normal(bmean, bstd, n_flows), blo, bhi)
            if feature in RATE_FEATURES:
                reference *= intensity
            value = _blend(value, reference, blend_strength)

        if feature in RATE_FEATURES or feature in {"fwd_iat_mean", "bwd_iat_mean", "flow_duration", "active_mean", "idle_mean"}:
            value *= rng.lognormal(mean=0.0, sigma=0.10, size=n_flows)
        else:
            value += rng.normal(0, np.maximum(np.abs(value) * 0.06, 1e-6), n_flows)
        data[feature] = value

    df = pd.DataFrame(data)
    avg_len = np.maximum(40.0, (df["fwd_packet_length_mean"].to_numpy() + df["bwd_packet_length_mean"].to_numpy()) / 2.0)
    pps = np.maximum(0.05, df["flow_packets_per_sec"].to_numpy())
    fwd = np.maximum(0.05, pps * rng.uniform(0.45, 0.95, n_flows))
    bwd = np.maximum(0.02, pps - fwd) * rng.uniform(0.75, 1.20, n_flows)
    df["flow_packets_per_sec"] = pps
    df["flow_bytes_per_sec"] = np.maximum(0.0, pps * avg_len * rng.uniform(0.55, 1.35, n_flows))
    df["fwd_packets_per_sec"] = fwd
    df["bwd_packets_per_sec"] = bwd
    df["down_up_ratio"] = np.clip((bwd + 0.1) / (fwd + 0.1) * rng.uniform(0.75, 1.25, n_flows), 0, 8)
    for feature in ["fin_flag_count", "syn_flag_count", "rst_flag_count"]:
        df[feature] = np.maximum(0.0, df[feature].to_numpy())
    return df


def generate_dataset(sequences_per_class: int = 120, flows_per_sequence: int = 40, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Generate ordered sequences without shuffling."""
    rng = np.random.default_rng(seed)
    frames = []
    sequence_id = 0
    for label in CLASSES:
        for _ in range(sequences_per_class):
            frames.append(generate_sequence(label, sequence_id, flows_per_sequence, rng))
            sequence_id += 1
    return pd.concat(frames, ignore_index=True)


if __name__ == "__main__":
    df = generate_dataset()
    print(df.head(10).to_string(index=False))
    print("\nClass counts:")
    print(df.groupby("attack_type").size())
    print("\nHard-case sequences:")
    print(df.groupby("attack_type")["hard_case"].max())
