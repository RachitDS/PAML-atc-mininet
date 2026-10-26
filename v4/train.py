"""Phase 1B: train and evaluate binary + six-class PAML Random Forest models."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import (
    DATASET_PATH, FEATURES_PATH, MODEL_DIR, RANDOM_SEED, SCALER_PATH,
    SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, TEST_SIZE, TRAINING_METRICS_PATH,
)
from src.dataset import BASE_FEATURES, CLASSES, generate_dataset
from src.temporal_features import TEMPORAL_FEATURES, add_temporal_features

ALL_FEATURES = BASE_FEATURES + TEMPORAL_FEATURES
CLASS_TO_ID = {name: i for i, name in enumerate(CLASSES)}


def _model(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_leaf=4,
        max_features="sqrt",
        class_weight="balanced",
        random_state=seed,
        n_jobs=1,
    )


def _binary_metrics(y_true, pred):
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": float(fpr), "fnr": float(fnr), "confusion_matrix": cm.tolist(),
    }


def main() -> None:
    for path in [MODEL_DIR, DATASET_PATH.parent, TRAINING_METRICS_PATH.parent]:
        path.mkdir(parents=True, exist_ok=True)

    print("Generating ordered Phase-1B synthetic traffic sequences...")
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, RANDOM_SEED)
    df = add_temporal_features(df)
    df.to_csv(DATASET_PATH, index=False)

    # Sequence-level split is mandatory: no flow from a sequence may appear in
    # both train and test, preventing temporal leakage.
    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_SEED)
    train_idx, test_idx = next(splitter.split(df, df["label"], groups=df["sequence_id"]))
    train = df.iloc[train_idx].copy()
    test = df.iloc[test_idx].copy()

    scaler = StandardScaler()
    X_train = scaler.fit_transform(train[ALL_FEATURES])
    X_test = scaler.transform(test[ALL_FEATURES])

    # Train one detector for the operational decision and one classifier for
    # attack-type identification.
    y_train_bin = train["label"].to_numpy()
    y_test_bin = test["label"].to_numpy()
    y_train_multi = train["attack_type"].map(CLASS_TO_ID).to_numpy()
    y_test_multi = test["attack_type"].map(CLASS_TO_ID).to_numpy()

    binary_model = _model(RANDOM_SEED)
    t0 = time.perf_counter()
    binary_model.fit(X_train, y_train_bin)
    binary_fit_s = time.perf_counter() - t0
    pred_bin = binary_model.predict(X_test)
    binary = _binary_metrics(y_test_bin, pred_bin)

    multi_model = _model(RANDOM_SEED + 1)
    multi_model.fit(X_train, y_train_multi)
    pred_multi = multi_model.predict(X_test)
    multi_report = classification_report(
        y_test_multi, pred_multi, labels=list(range(len(CLASSES))), target_names=CLASSES,
        output_dict=True, zero_division=0,
    )
    multi_cm = confusion_matrix(y_test_multi, pred_multi, labels=list(range(len(CLASSES))))
    multiclass = {
        "accuracy": float(accuracy_score(y_test_multi, pred_multi)),
        "macro_precision": float(precision_score(y_test_multi, pred_multi, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_test_multi, pred_multi, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_test_multi, pred_multi, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test_multi, pred_multi, average="weighted", zero_division=0)),
        "confusion_matrix": multi_cm.tolist(),
        "report": multi_report,
    }

    # Store a compact inference benchmark for later latency comparison.
    sample = X_test[: min(1000, len(X_test))]
    t0 = time.perf_counter()
    for row in sample:
        binary_model.predict(row.reshape(1, -1))
    inference_ms_per_flow = (time.perf_counter() - t0) * 1000.0 / len(sample)

    metrics = {
        "phase": "1B",
        "data_type": "synthetic_CIC_DDoS2019_inspired",
        "methodology_note": "Synthetic development benchmark only; not the original CIC-DDoS2019 dataset.",
        "classes": CLASSES,
        "binary": binary,
        "multiclass": multiclass,
        "train_sequences": int(train["sequence_id"].nunique()),
        "test_sequences": int(test["sequence_id"].nunique()),
        "train_flows": int(len(train)), "test_flows": int(len(test)),
        "feature_count": len(ALL_FEATURES), "base_feature_count": len(BASE_FEATURES),
        "temporal_feature_count": len(TEMPORAL_FEATURES), "window_size": 5,
        "hard_case_sequences_total": int(df.groupby("sequence_id")["hard_case"].max().sum()),
        "seed": RANDOM_SEED,
        "binary_fit_seconds": float(binary_fit_s),
        "binary_inference_ms_per_flow": float(inference_ms_per_flow),
    }

    joblib.dump(binary_model, MODEL_DIR / "paml_binary_rf_phase1b.joblib")
    joblib.dump(multi_model, MODEL_DIR / "paml_multiclass_rf_phase1b.joblib")
    joblib.dump(scaler, SCALER_PATH)
    FEATURES_PATH.write_text("\n".join(ALL_FEATURES) + "\n", encoding="utf-8")
    (MODEL_DIR / "paml_class_mapping.json").write_text(json.dumps(CLASS_TO_ID, indent=2), encoding="utf-8")
    TRAINING_METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("\n=== PAML-ATC V2 Phase-1B Training ===")
    print(f"Features: {len(ALL_FEATURES)} = {len(BASE_FEATURES)} base + {len(TEMPORAL_FEATURES)} temporal")
    print(f"Train sequences: {metrics['train_sequences']}")
    print(f"Test sequences : {metrics['test_sequences']}")
    print(f"Hard-case sequences: {metrics['hard_case_sequences_total']}")
    print("\n--- Binary: Benign vs Attack ---")
    for key in ["accuracy", "precision", "recall", "f1", "fpr", "fnr"]:
        print(f"{key.upper():<10}: {binary[key] * 100:.2f}%")
    print("\n--- Multiclass: 6 classes ---")
    print(f"Accuracy    : {multiclass['accuracy'] * 100:.2f}%")
    print(f"Macro F1    : {multiclass['macro_f1'] * 100:.2f}%")
    print(f"Weighted F1 : {multiclass['weighted_f1'] * 100:.2f}%")
    print("\nMulticlass report:")
    print(classification_report(y_test_multi, pred_multi, labels=list(range(len(CLASSES))), target_names=CLASSES, zero_division=0))
    print(f"Binary inference: {inference_ms_per_flow:.4f} ms/flow (development benchmark)")
    print(f"Saved dataset -> {DATASET_PATH}")
    print(f"Saved binary model -> {MODEL_DIR / 'paml_binary_rf_phase1b.joblib'}")
    print(f"Saved multiclass model -> {MODEL_DIR / 'paml_multiclass_rf_phase1b.joblib'}")
    print(f"Saved metrics -> {TRAINING_METRICS_PATH}")


if __name__ == "__main__":
    main()
