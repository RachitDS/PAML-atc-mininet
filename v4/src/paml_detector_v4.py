"""V4 deployment-aligned, stateful PAML detector.

Key V4 changes:
- exactly 20 model inputs = 8 base + 12 temporal;
- exact same temporal row builder is used offline and online;
- per-stream five-flow histories and persistence;
- NumPy-only feature matrix construction on the hot path (no per-inference
  pandas DataFrame creation);
- optional raw feature-vector logging for deployment-drift diagnostics.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from time import monotonic_ns
from typing import Dict, Hashable
import csv
import json
import joblib
import numpy as np
from src.v4_schema import BASE_FEATURES_V4, ALL_FEATURES_V4
from src.temporal_features_v4 import build_temporal_row
from src.dataset import CLASSES

@dataclass(frozen=True)
class PAMLDecisionV4:
    is_attack: bool
    state: str
    attack_probability: float
    attack_type: str
    attack_type_probability: float
    consecutive_positive: int
    window_size: int

class PAMLDetectorV4:
    def __init__(self, model_dir: str | Path, window_size=5, attack_threshold=0.50,
                 persistence=1, feature_log_path=None):
        if not 0 < attack_threshold < 1:
            raise ValueError("attack_threshold must be between 0 and 1")
        if window_size < 2 or persistence < 1:
            raise ValueError("window_size>=2 and persistence>=1 required")
        model_dir = Path(model_dir)
        self.binary_model = joblib.load(model_dir / "paml_v4_binary_rf.joblib")
        self.multiclass_model = joblib.load(model_dir / "paml_v4_multiclass_rf.joblib")
        # Ryu runs inference in Eventlet's cooperative event loop. Joblib's
        # parallel forest prediction can deadlock there; training may still
        # use parallel workers, but live prediction must stay serial.
        self.binary_model.set_params(n_jobs=1)
        self.multiclass_model.set_params(n_jobs=1)
        self.scaler = joblib.load(model_dir / "paml_v4_scaler.joblib")
        feature_path = model_dir / "paml_v4_features.txt"
        self.features = [x.strip() for x in feature_path.read_text().splitlines() if x.strip()]
        if self.features != ALL_FEATURES_V4:
            raise ValueError(f"V4 feature schema mismatch: {self.features}")
        self.window_size = int(window_size)
        self.attack_threshold = float(attack_threshold)
        self.persistence = int(persistence)
        self.histories: Dict[Hashable, deque] = {}
        self.positive_counts: Dict[Hashable, int] = {}
        self.feature_log_path = Path(feature_log_path) if feature_log_path else None
        if self.feature_log_path:
            self.feature_log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.feature_log_path.exists():
                with self.feature_log_path.open("w", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow(["timestamp_ns", "stream_id", *ALL_FEATURES_V4])

    def reset(self):
        self.histories.clear(); self.positive_counts.clear()

    def _key(self, flow, stream_id=None):
        return stream_id if stream_id is not None else (flow.get("src_ip"), flow.get("dst_ip"), flow.get("protocol"))

    def _vector(self, flow, key):
        missing = set(BASE_FEATURES_V4) - set(flow)
        if missing:
            raise ValueError(f"Missing V4 base features: {sorted(missing)}")
        hist = self.histories.setdefault(key, deque(maxlen=self.window_size))
        row = build_temporal_row(flow, hist)
        return np.asarray([[float(row[name]) for name in ALL_FEATURES_V4]], dtype=np.float64), row, len(hist)

    def predict_flow_timed(self, flow, stream_id=None):
        return self.predict_flows_timed([flow], [stream_id])[0]

    def predict_flows_timed(self, flows, stream_ids=None):
        if not flows:
            return []
        if stream_ids is None:
            stream_ids = [None] * len(flows)
        if len(stream_ids) != len(flows):
            raise ValueError("One stream ID is required per flow")
        t0 = monotonic_ns()
        vectors, metadata = [], []
        for flow, stream_id in zip(flows, stream_ids):
            key = self._key(flow, stream_id)
            X, row, hlen = self._vector(flow, key)
            vectors.append(X[0])
            metadata.append((key, row, hlen))
        feature_ms = (monotonic_ns() - t0) / 1e6 / len(flows)
        t1 = monotonic_ns()
        Xs = self.scaler.transform(np.asarray(vectors))
        bp = self.binary_model.predict_proba(Xs)
        classes = list(self.binary_model.classes_)
        mp = self.multiclass_model.predict_proba(Xs)
        mc = list(self.multiclass_model.classes_)
        inference_ms = (monotonic_ns() - t1) / 1e6 / len(flows)
        result = []
        for index, (key, row, hlen) in enumerate(metadata):
            p_attack = float(bp[index, classes.index(1)])
            positive = p_attack >= self.attack_threshold
            count = self.positive_counts.get(key, 0) + 1 if positive else 0
            self.positive_counts[key] = count
            mi = int(np.argmax(mp[index])); atype = CLASSES[int(mc[mi])]
            state = "ATTACK" if positive and count >= self.persistence else ("SUSPICIOUS" if positive else "BENIGN")
            d = PAMLDecisionV4(state == "ATTACK", state, p_attack, atype, float(mp[index, mi]), count, hlen)
            self._log_vector(key, row)
            result.append((d, feature_ms, inference_ms, row))
        return result

    def _log_vector(self, key, row):
        if not self.feature_log_path: return
        sid = json.dumps(list(key) if isinstance(key, tuple) else str(key), separators=(",", ":"))
        with self.feature_log_path.open("a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([monotonic_ns(), sid, *[f"{float(row[n]):.10g}" for n in ALL_FEATURES_V4]])
