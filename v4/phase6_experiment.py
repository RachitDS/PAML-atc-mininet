"""Phase-6: 10-seed A1-A4 controlled evaluation.

This phase evaluates the already-built PAML/ATC/MTD/deception stack under the
same traffic traces for every configuration. Network metrics are produced by
a documented synthetic capacity/congestion model; they are NOT live network
measurements. The experiment is designed to provide a reproducible simulator
baseline before Mininet/Ryu validation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from time import perf_counter_ns

import numpy as np
import pandas as pd
from scipy.stats import ttest_rel, wilcoxon
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import MODEL_DIR
from config_phase2 import PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE, PAML_WINDOW_SIZE
from src.dataset import ATTACK_TYPES, generate_dataset
from src.paml_detector import PAMLDetector
from src.defense_orchestrator import DefenseOrchestrator
from src.adaptive_atc import AdaptiveATC

SEEDS = list(range(10))
CONFIGS = ["A1_Baseline", "A2_PAML", "A3_PAML_ATC", "A4_FULL"]
CAPACITY_PPS = 10000
SEQUENCES_PER_CLASS = 2
FLOWS_PER_SEQUENCE = 10
ROTATION_INTERVAL = 5
DECEPTION_PROBABILITY = 0.25


def _binary_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
    }


def _percentile(values, q):
    return float(np.percentile(np.asarray(values, dtype=float), q)) if values else 0.0


def _safe_stats(a, b):
    """Paired t-test and Wilcoxon with explicit handling of zero differences."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    diff = a - b
    if np.allclose(diff, 0.0):
        return {"paired_t_p": 1.0, "wilcoxon_p": 1.0, "note": "all paired differences are zero"}
    t_p = float(ttest_rel(a, b).pvalue)
    try:
        w_p = float(wilcoxon(a, b, zero_method="wilcox", alternative="two-sided").pvalue)
    except ValueError:
        w_p = 1.0
    return {"paired_t_p": t_p, "wilcoxon_p": w_p, "note": "paired tests across identical seeds"}


def _network_outcome(offered_benign, offered_attack, effective_attack, config, rng):
    """Documented synthetic capacity/congestion model.

    The model represents one evaluation interval. Benign traffic is protected
    preferentially. Congestion reduces benign PDR and increases RTT when the
    post-policy offered load exceeds switch capacity.
    """
    benign = float(max(0.0, offered_benign))
    attack = float(max(0.0, effective_attack))
    total = benign + attack
    congestion = max(0.0, (total - CAPACITY_PPS) / max(total, 1.0))
    benign_pdr = min(1.0, CAPACITY_PPS / max(total, 1.0)) if total > 0 else 1.0
    benign_pdr = max(0.0, min(1.0, benign_pdr))

    # Policy overhead is deliberately small but measurable in this simulator.
    cpu_overhead = {
        "A1_Baseline": 0.0,
        "A2_PAML": 3.0,
        "A3_PAML_ATC": 5.0,
        "A4_FULL": 7.0,
    }[config]
    cpu = 8.0 + 24.0 * min(1.0, total / CAPACITY_PPS) + cpu_overhead
    cpu = min(100.0, cpu + float(rng.normal(0, 0.35)))

    rtt = 8.0 + 35.0 * congestion + 0.025 * cpu_overhead
    rtt += float(rng.normal(0, 0.25))
    rtt = max(1.0, rtt)

    total_pdr = (benign * benign_pdr + attack * (1.0 - congestion)) / max(benign + attack, 1.0)
    return benign_pdr, total_pdr, cpu, rtt


def run_seed(seed: int):
    rng = np.random.default_rng(seed + 9000)
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, seed)

    # Compute PAML once per seed and reuse the identical predictions for A2-A4.
    # This guarantees paired comparisons and avoids repeatedly loading the
    # same model artifacts for every sequence/configuration.
    detector = PAMLDetector(MODEL_DIR, PAML_WINDOW_SIZE, PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE)
    paml_by_seq = {}
    for sid, seq in df.groupby("sequence_id", sort=True):
        detector.reset()
        seq = seq.sort_values("flow_index")
        outputs = []
        for rec in seq.to_dict(orient="records"):
            decision, feature_elapsed_ms, inference_elapsed_ms = detector.predict_flow_timed(rec)
            outputs.append((rec, decision, feature_elapsed_ms, inference_elapsed_ms))
        paml_by_seq[int(sid)] = outputs

    rows = []
    for config in CONFIGS:
        y_true, y_pred = [], []
        benign_offered = 0.0
        attack_offered = 0.0
        effective_attack = 0.0
        feature_ms, inference_ms, control_ms = [], [], []
        attack_decisions = 0
        mtd_rotations = 0
        decoy_hits = 0

        for sid, outputs in paml_by_seq.items():
            label = int(outputs[0][0]["label"])
            # Each sequence is an independent stream. The orchestrator is
            # reset per sequence so MTD/deception state cannot leak between
            # unrelated sources.
            defense = None
            if config == "A3_PAML_ATC":
                defense = AdaptiveATC(capacity_pps=CAPACITY_PPS)
            elif config == "A4_FULL":
                defense = DefenseOrchestrator(
                    capacity_pps=CAPACITY_PPS,
                    rotation_interval=ROTATION_INTERVAL,
                    deception_probability=DECEPTION_PROBABILITY,
                )

            for rec, decision, feature_elapsed_ms, inference_elapsed_ms in outputs:
                offered = float(rec["flow_packets_per_sec"])
                if label == 0:
                    benign_offered += offered
                else:
                    attack_offered += offered

                if config == "A1_Baseline":
                    pred = 0
                    effective = offered if label else 0.0
                else:
                    pred = int(decision.is_attack)
                    # Current PAMLDetector measures temporal-feature construction
                    # and model inference as one online operation. We report this
                    # end-to-end online inference path rather than fabricating a
                    # sub-timing for feature extraction.
                    inference_ms.append(inference_elapsed_ms)
                    feature_ms.append(feature_elapsed_ms)
                    effective = offered if label else 0.0

                    if config == "A2_PAML":
                        effective = offered if label else 0.0
                    else:
                        t1 = perf_counter_ns()
                        if config == "A3_PAML_ATC":
                            dd = defense.decide(decision, source_id=f"src-{sid}")
                        else:
                            dd = defense.decide(decision, source_id=f"src-{sid}", flow_index=int(rec["flow_index"]))
                        control_ms.append((perf_counter_ns() - t1) / 1_000_000.0)
                        if decision.state == "BENIGN":
                            effective = 0.0
                        else:
                            atc_action = dd if config == "A3_PAML_ATC" else dd.atc
                            effective = min(offered, atc_action.rate_limit_pps) * (1.0 - atc_action.drop_probability)
                            if decision.state == "ATTACK":
                                attack_decisions += 1
                                if config == "A4_FULL":
                                    if dd.mtd_event is not None:
                                        mtd_rotations += 1
                                    if dd.deception.routed_to_decoy:
                                        decoy_hits += 1
                                        effective *= 0.20

                y_true.append(label)
                y_pred.append(pred)
                effective_attack += effective

        metrics = _binary_metrics(y_true, y_pred)
        benign_pdr, total_pdr, cpu, rtt = _network_outcome(
            benign_offered, attack_offered, effective_attack, config, rng
        )
        # For A3/A4 the control-path latency is PAML online inference plus the
        # local policy decision. A1/A2 have no control decision stage.
        total_latency = []
        if config in {"A3_PAML_ATC", "A4_FULL"}:
            n = min(len(inference_ms), len(control_ms))
            total_latency = [inference_ms[i] + control_ms[i] for i in range(n)]
        else:
            total_latency = inference_ms

        rows.append({
            "seed": seed,
            "configuration": config,
            **metrics,
            "benign_pdr": benign_pdr,
            "overall_pdr": total_pdr,
            "cpu_percent": cpu,
            "rtt_ms": rtt,
            "feature_extraction_ms_mean": float(np.mean(feature_ms)) if feature_ms else 0.0,
            "feature_extraction_ms_p95": _percentile(feature_ms, 95),
            "inference_ms_mean": float(np.mean(inference_ms)) if inference_ms else 0.0,
            "inference_ms_p95": _percentile(inference_ms, 95),
            "control_decision_ms_mean": float(np.mean(control_ms)) if control_ms else 0.0,
            "control_decision_ms_p95": _percentile(control_ms, 95),
            "packet_in_to_flow_mod_ms_mean": float(np.mean(total_latency)) if total_latency else 0.0,
            "packet_in_to_flow_mod_ms_p95": _percentile(total_latency, 95),
            "attack_offered_pps": attack_offered,
            "attack_effective_pps": effective_attack,
            "attack_decisions": attack_decisions,
            "mtd_rotations": mtd_rotations,
            "decoy_hits": decoy_hits,
        })

    return rows

def summarize(raw):
    metric_cols = [
        "accuracy", "precision", "recall", "f1", "fpr", "fnr",
        "benign_pdr", "overall_pdr", "cpu_percent", "rtt_ms",
        "feature_extraction_ms_mean", "feature_extraction_ms_p95",
        "inference_ms_mean", "inference_ms_p95",
        "packet_in_to_flow_mod_ms_mean", "packet_in_to_flow_mod_ms_p95",
        "attack_effective_pps", "attack_decisions", "mtd_rotations", "decoy_hits",
    ]
    grouped = raw.groupby("configuration")
    out = []
    for config, g in grouped:
        row = {"configuration": config, "n_seeds": len(g)}
        for m in metric_cols:
            row[f"{m}_mean"] = g[m].mean()
            row[f"{m}_std"] = g[m].std(ddof=1)
        out.append(row)
    return pd.DataFrame(out)


def statistical_tests(raw):
    metrics = ["f1", "fpr", "fnr", "benign_pdr", "overall_pdr", "cpu_percent", "rtt_ms", "packet_in_to_flow_mod_ms_mean"]
    results = []
    for metric in metrics:
        pivot = raw.pivot(index="seed", columns="configuration", values=metric)
        for comparison in [("A4_FULL", "A1_Baseline"), ("A4_FULL", "A3_PAML_ATC")]:
            a, b = comparison
            stats = _safe_stats(pivot[a].values, pivot[b].values)
            results.append({"metric": metric, "comparison": f"{a} vs {b}", **stats})
    return pd.DataFrame(results)


def main():
    all_rows = []
    for seed in SEEDS:
        print(f"Running seed {seed + 1}/{len(SEEDS)}...")
        all_rows.extend(run_seed(seed))

    raw = pd.DataFrame(all_rows)
    summary = summarize(raw)
    stats = statistical_tests(raw)

    raw_path = ROOT / "results" / "raw" / "phase6_seed_results.csv"
    summary_path = ROOT / "results" / "processed" / "phase6_mean_sd.csv"
    stats_path = ROOT / "results" / "statistics" / "phase6_paired_tests.csv"
    raw.to_csv(raw_path, index=False)
    summary.to_csv(summary_path, index=False)
    stats.to_csv(stats_path, index=False)

    meta = {
        "seeds": SEEDS,
        "configurations": CONFIGS,
        "sequences_per_class": SEQUENCES_PER_CLASS,
        "flows_per_sequence": FLOWS_PER_SEQUENCE,
        "paml_window": PAML_WINDOW_SIZE,
        "paml_threshold": PAML_ATTACK_THRESHOLD,
        "paml_persistence": PAML_PERSISTENCE,
        "note": "Network CPU/RTT/PDR are generated by the documented synthetic capacity/congestion model; latency is local simulator timing. Final claims require Mininet/Ryu/live measurements.",
    }
    (ROOT / "results" / "processed" / "phase6_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print("\n=== Phase-6 A1-A4 Evaluation ===")
    display_cols = ["configuration", "f1_mean", "f1_std", "fpr_mean", "fpr_std", "fnr_mean", "fnr_std", "benign_pdr_mean", "benign_pdr_std", "cpu_percent_mean", "rtt_ms_mean"]
    print(summary[display_cols].round(4).to_string(index=False))
    print("\nPaired statistical tests:")
    print(stats.round(6).to_string(index=False))
    print(f"\nSaved raw results   -> {raw_path}")
    print(f"Saved mean +/- SD  -> {summary_path}")
    print(f"Saved paired tests -> {stats_path}")


if __name__ == "__main__":
    main()
