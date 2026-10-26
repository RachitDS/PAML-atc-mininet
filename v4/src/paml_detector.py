"""Operational PAML detection engine for Phase 2.

The detector wraps the Phase-1B trained Random Forest models and converts an
ordered stream of flow records into a stateful PAML decision. Temporal
features are calculated only from the current stream's recent history, so the
inference path mirrors an online sliding-window detector rather than using
future rows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Deque, Dict, Iterable, Optional, Hashable

import joblib
import numpy as np
import pandas as pd

from src.dataset import BASE_FEATURES, CLASSES
from src.temporal_features import TEMPORAL_BASE


@dataclass(frozen=True)
class PAMLDecision:
    """One online PAML inference decision."""

    is_attack: bool
    state: str
    attack_probability: float
    attack_type: str
    attack_type_probability: float
    consecutive_positive: int
    window_size: int


class PAMLDetector:
    """Stateful online detector using Phase-1B PAML models.

    REUSED: Phase-1B Random Forest/scaler artifacts.
    MODIFIED: inference is stateful and computes temporal features online.
    NEW: persistence-based operational decision states.
    """

    def __init__(
        self,
        model_dir: str | Path,
        window_size: int = 5,
        attack_threshold: float = 0.65,
        persistence: int = 3,
    ) -> None:
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        if not 0.0 < attack_threshold < 1.0:
            raise ValueError("attack_threshold must be between 0 and 1")
        if persistence < 1:
            raise ValueError("persistence must be at least 1")

        model_dir = Path(model_dir)
        self.binary_model = joblib.load(model_dir / "paml_binary_rf_phase1b.joblib")
        self.multiclass_model = joblib.load(model_dir / "paml_multiclass_rf_phase1b.joblib")
        self.scaler = joblib.load(model_dir / "paml_scaler_phase1b.joblib")

        feature_file = model_dir / "paml_features_phase1b.txt"
        self.features = [x.strip() for x in feature_file.read_text(encoding="utf-8").splitlines() if x.strip()]
        expected = BASE_FEATURES + [
            "flow_packets_per_sec_rm", "flow_packets_per_sec_rs", "flow_packets_per_sec_delta",
            "fwd_iat_mean_rm", "fwd_iat_mean_rs", "fwd_iat_mean_delta",
            "syn_flag_count_rm", "syn_flag_count_rs", "syn_flag_count_delta",
            "syn_fin_ratio", "packet_variability_inverse", "iat_acceleration",
        ]
        if self.features != expected:
            raise ValueError("Phase-1B feature list does not match the expected online feature schema")

        self.window_size = window_size
        self.attack_threshold = attack_threshold
        self.persistence = persistence
        # Keep temporal history per flow stream. A global history would mix
        # unrelated benign/attack flows from different hosts and corrupt the
        # five-flow temporal signature in a real SDN network.
        self.histories: Dict[Hashable, Deque[Dict[str, float]]] = {}
        self.positive_counts: Dict[Hashable, int] = {}

    def reset(self) -> None:
        """Reset stream history and persistence state."""
        self.histories.clear()
        self.positive_counts.clear()

    def _stream_key(self, flow: Dict[str, float], stream_id=None):
        if stream_id is not None:
            return stream_id
        return (flow.get("src_ip", ""), flow.get("dst_ip", ""), flow.get("protocol", ""))

    def _temporal_row(self, flow: Dict[str, float], stream_id=None) -> Dict[str, float]:
        key = self._stream_key(flow, stream_id)
        history = self.histories.setdefault(key, deque(maxlen=self.window_size))
        history.append(dict(flow))
        frame = pd.DataFrame(list(history))
        row = dict(flow)

        for feature in TEMPORAL_BASE:
            values = pd.to_numeric(frame[feature], errors="coerce").fillna(0.0).to_numpy(dtype=float)
            row[f"{feature}_rm"] = float(values.mean())
            row[f"{feature}_rs"] = float(values.std(ddof=0))
            row[f"{feature}_delta"] = float(values[-1] - values[-2]) if len(values) > 1 else 0.0

        syn = float(row.get("syn_flag_count", 0.0))
        fin = float(row.get("fin_flag_count", 0.0))
        variance = float(row.get("packet_length_variance", 0.0))
        row["syn_fin_ratio"] = float(np.clip(syn / (fin + 1e-3), 0.0, 100.0))
        row["packet_variability_inverse"] = float(1.0 / (variance + 1.0))
        if len(frame) >= 3:
            iat = pd.to_numeric(frame["fwd_iat_mean"], errors="coerce").fillna(0.0).to_numpy(dtype=float)
            row["iat_acceleration"] = float(iat[-1] - 2.0 * iat[-2] + iat[-3])
        else:
            row["iat_acceleration"] = 0.0
        return row, key, len(history)

    def predict_flow_timed(self, flow: Dict[str, float], stream_id=None):
        """Infer one flow and separately time temporal construction and ML inference."""
        missing = set(BASE_FEATURES) - set(flow)
        if missing:
            raise ValueError(f"Missing base features: {sorted(missing)}")

        t_feature = perf_counter_ns()
        row, key, history_len = self._temporal_row(flow, stream_id)
        feature_ms = (perf_counter_ns() - t_feature) / 1_000_000.0

        values = pd.DataFrame([[float(row[name]) for name in self.features]], columns=self.features)
        t_model = perf_counter_ns()
        X = self.scaler.transform(values)
        binary_probs = self.binary_model.predict_proba(X)[0]
        binary_classes = list(self.binary_model.classes_)
        if 1 not in binary_classes:
            raise ValueError("Binary PAML model must contain attack class 1")
        attack_probability = float(binary_probs[binary_classes.index(1)])
        binary_positive = attack_probability >= self.attack_threshold
        count = self.positive_counts.get(key, 0)
        count = count + 1 if binary_positive else 0
        self.positive_counts[key] = count

        multi_probs = self.multiclass_model.predict_proba(X)[0]
        class_index = int(np.argmax(multi_probs))
        multi_classes = list(self.multiclass_model.classes_)
        class_id = int(multi_classes[class_index])
        attack_type = CLASSES[class_id]
        attack_type_probability = float(multi_probs[class_index])
        inference_ms = (perf_counter_ns() - t_model) / 1_000_000.0

        if not binary_positive:
            state = "BENIGN"
        elif count < self.persistence:
            state = "SUSPICIOUS"
        else:
            state = "ATTACK"

        decision = PAMLDecision(
            is_attack=state == "ATTACK",
            state=state,
            attack_probability=attack_probability,
            attack_type=attack_type,
            attack_type_probability=attack_type_probability,
            consecutive_positive=count,
            window_size=history_len,
        )
        return decision, feature_ms, inference_ms

    def predict_flow(self, flow: Dict[str, float], stream_id=None) -> PAMLDecision:
        """Infer one flow without using future observations."""
        missing = set(BASE_FEATURES) - set(flow)
        if missing:
            raise ValueError(f"Missing base features: {sorted(missing)}")

        row, key, history_len = self._temporal_row(flow, stream_id)
        values = pd.DataFrame([[float(row[name]) for name in self.features]], columns=self.features)
        X = self.scaler.transform(values)

        binary_probs = self.binary_model.predict_proba(X)[0]
        binary_classes = list(self.binary_model.classes_)
        if 1 not in binary_classes:
            raise ValueError("Binary PAML model must contain attack class 1")
        attack_probability = float(binary_probs[binary_classes.index(1)])
        binary_positive = attack_probability >= self.attack_threshold
        count = self.positive_counts.get(key, 0)
        count = count + 1 if binary_positive else 0
        self.positive_counts[key] = count

        multi_probs = self.multiclass_model.predict_proba(X)[0]
        class_index = int(np.argmax(multi_probs))
        multi_classes = list(self.multiclass_model.classes_)
        class_id = int(multi_classes[class_index])
        attack_type = CLASSES[class_id]
        attack_type_probability = float(multi_probs[class_index])

        if not binary_positive:
            state = "BENIGN"
        elif count < self.persistence:
            state = "SUSPICIOUS"
        else:
            state = "ATTACK"

        return PAMLDecision(
            is_attack=state == "ATTACK",
            state=state,
            attack_probability=attack_probability,
            attack_type=attack_type,
            attack_type_probability=attack_type_probability,
            consecutive_positive=count,
            window_size=history_len,
        )

    def predict_dataframe(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Run online inference over an already ordered stream."""
        missing = set(BASE_FEATURES) - set(flows.columns)
        if missing:
            raise ValueError(f"Missing base features: {sorted(missing)}")
        outputs = []
        for record in flows[BASE_FEATURES].to_dict(orient="records"):
            outputs.append(self.predict_flow(record))
        return pd.DataFrame([d.__dict__ for d in outputs])
