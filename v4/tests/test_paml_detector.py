from pathlib import Path

import pandas as pd
import pytest

from src.dataset import BASE_FEATURES, PROFILES
from src.paml_detector import PAMLDetector

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"


def _benign_flow():
    row = {}
    for feature, spec in PROFILES["Benign"].items():
        row[feature] = spec[0]
    row["protocol_encoded"] = 0.0
    # Dataset derives these values later, but the trained feature schema
    # requires the base fields to be present here.
    row["flow_packets_per_sec"] = 120.0
    row["fwd_packets_per_sec"] = 60.0
    row["bwd_packets_per_sec"] = 60.0
    row["flow_bytes_per_sec"] = 45000.0
    return {name: float(row[name]) for name in BASE_FEATURES}


def test_detector_builds_online_temporal_features():
    detector = PAMLDetector(MODEL_DIR, window_size=5, attack_threshold=0.65, persistence=3)
    flow = _benign_flow()
    decision = detector.predict_flow(flow)
    assert 0.0 <= decision.attack_probability <= 1.0
    assert decision.window_size == 1
    assert decision.state in {"BENIGN", "SUSPICIOUS", "ATTACK"}


def test_persistence_prevents_single_positive_from_being_attack(monkeypatch):
    detector = PAMLDetector(MODEL_DIR, window_size=5, attack_threshold=0.65, persistence=3)

    monkeypatch.setattr(detector.binary_model, "predict_proba", lambda X: [[0.2, 0.8]])
    monkeypatch.setattr(detector.multiclass_model, "predict_proba", lambda X: [[0.0, 0.0, 0.0, 0.0, 1.0, 0.0]])

    first = detector.predict_flow(_benign_flow())
    second = detector.predict_flow(_benign_flow())
    third = detector.predict_flow(_benign_flow())

    assert first.state == "SUSPICIOUS"
    assert second.state == "SUSPICIOUS"
    assert third.state == "ATTACK"
    assert third.is_attack is True
