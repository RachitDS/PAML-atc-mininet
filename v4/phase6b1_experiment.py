"""Phase-6B.1: measurable MTD + deception refinement.

REUSED: Phase-6B 10-seed A1-A4 evaluation framework and PAML/ATC pipeline.
MODIFIED: A4 now reports explicit MTD/deception operational metrics instead of
          relying mainly on attack-block-rate differences.
NEW: target coverage, rotation rate, attack redirect/capture rate, diverted
     attack traffic, and a compact A3-vs-A4 effect report.

IMPORTANT: this remains a synthetic control-plane/service-capacity simulator.
It is not a live SDN/Mininet measurement.
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
from src.dataset import generate_dataset
from src.paml_detector import PAMLDetector
from src.defense_orchestrator import DefenseOrchestrator
from src.adaptive_atc import AdaptiveATC

SEEDS = list(range(10))
CONFIGS = ["A1_StaticThreshold", "A2_PAML", "A3_PAML_ATC", "A4_FULL"]
CAPACITY_PPS = 10000.0
SEQUENCES_PER_CLASS = 2
FLOWS_PER_SEQUENCE = 10
ROTATION_INTERVAL = 5
DECEPTION_PROBABILITY = 0.25
MTD_TARGETS = ["PLC-A", "PLC-B", "PLC-C"]

STATIC_THRESHOLD_PPS = 1500.0
STATIC_LIMIT_PPS = 600.0
STATIC_DROP_PROBABILITY = 0.75


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
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    diff = a - b
    if np.allclose(diff, 0.0):
        return {"paired_t_p": 1.0, "wilcoxon_p": 1.0, "note": "all paired differences are zero"}
    t_p = float(ttest_rel(a, b).pvalue)
    try:
        w_p = float(wilcoxon(a, b, zero_method="wilcox", alternative="two-sided").pvalue)
    except ValueError:
        w_p = 1.0
    return {"paired_t_p": t_p, "wilcoxon_p": w_p, "note": "paired tests across identical seeds"}


def _static_baseline(offered_pps: float) -> tuple[int, float, str]:
    positive = offered_pps >= STATIC_THRESHOLD_PPS
    if positive:
        return 1, STATIC_DROP_PROBABILITY, "STATIC_RATE_LIMIT"
    return 0, 0.0, "ALLOW"


def _network_outcome(benign_service_pps, attack_service_pps, benign_offered_pps, attack_offered_pps, config, rng):
    benign_service_pps = max(0.0, float(benign_service_pps))
    attack_service_pps = max(0.0, float(attack_service_pps))
    service_load = benign_service_pps + attack_service_pps
    congestion = max(0.0, (service_load - CAPACITY_PPS) / max(service_load, 1.0))
    capacity_factor = min(1.0, CAPACITY_PPS / max(service_load, 1.0)) if service_load else 1.0

    benign_pdr = (benign_service_pps / max(benign_offered_pps, 1e-9)) * capacity_factor
    attack_pdr = (attack_service_pps / max(attack_offered_pps, 1e-9)) * capacity_factor
    benign_pdr = float(np.clip(benign_pdr, 0.0, 1.0))
    attack_pdr = float(np.clip(attack_pdr, 0.0, 1.0))
    overall_pdr = (benign_offered_pps * benign_pdr + attack_offered_pps * attack_pdr) / max(benign_offered_pps + attack_offered_pps, 1.0)

    overhead = {
        "A1_StaticThreshold": 1.0,
        "A2_PAML": 3.0,
        "A3_PAML_ATC": 5.0,
        "A4_FULL": 7.0,
    }[config]
    cpu = 8.0 + 24.0 * min(1.0, service_load / CAPACITY_PPS) + overhead + float(rng.normal(0, 0.35))
    cpu = min(100.0, max(0.0, cpu))
    rtt = max(1.0, 8.0 + 35.0 * congestion + 0.025 * overhead + float(rng.normal(0, 0.25)))
    return benign_pdr, attack_pdr, overall_pdr, cpu, rtt


def run_seed(seed: int):
    rng = np.random.default_rng(seed + 12000)
    df = generate_dataset(SEQUENCES_PER_CLASS, FLOWS_PER_SEQUENCE, seed)

    detector = PAMLDetector(MODEL_DIR, PAML_WINDOW_SIZE, PAML_ATTACK_THRESHOLD, PAML_PERSISTENCE)
    paml_by_seq = {}
    for sid, seq in df.groupby("sequence_id", sort=True):
        detector.reset()
        outputs = []
        for rec in seq.sort_values("flow_index").to_dict(orient="records"):
            decision, feature_ms, inference_ms = detector.predict_flow_timed(rec)
            outputs.append((rec, decision, feature_ms, inference_ms))
        paml_by_seq[int(sid)] = outputs

    rows = []
    for config in CONFIGS:
        y_true, y_pred = [], []
        benign_offered = benign_service = 0.0
        attack_offered = attack_service = 0.0
        feature_ms, inference_ms, control_ms = [], [], []
        attack_decisions = 0
        paml_attack_decisions = 0
        static_positive = 0

        # Explicit A4 observability counters.
        mtd_rotations = 0
        mtd_attack_events = 0
        target_history = []
        decoy_hits = 0
        deception_attack_decisions = 0
        diverted_attack_pps = 0.0
        decoy_attack_pps = 0.0

        for sid, outputs in paml_by_seq.items():
            defense = None
            if config == "A3_PAML_ATC":
                defense = AdaptiveATC(capacity_pps=int(CAPACITY_PPS))
            elif config == "A4_FULL":
                defense = DefenseOrchestrator(
                    capacity_pps=int(CAPACITY_PPS),
                    rotation_interval=ROTATION_INTERVAL,
                    deception_probability=DECEPTION_PROBABILITY,
                )

            for rec, decision, f_ms, i_ms in outputs:
                label = int(rec["label"])
                offered = float(rec["flow_packets_per_sec"])
                if label == 0:
                    benign_offered += offered
                else:
                    attack_offered += offered

                if config == "A1_StaticThreshold":
                    pred, drop_p, _ = _static_baseline(offered)
                    static_positive += pred
                    if label == 0:
                        benign_service += offered * (1.0 - drop_p)
                    else:
                        attack_service += min(offered, STATIC_LIMIT_PPS) * (1.0 - drop_p)
                else:
                    pred = int(decision.is_attack)
                    feature_ms.append(f_ms)
                    inference_ms.append(i_ms)
                    paml_attack_decisions += int(decision.is_attack)

                    if config == "A2_PAML":
                        if label == 0:
                            benign_service += offered
                        else:
                            attack_service += offered
                    else:
                        t0 = perf_counter_ns()
                        if config == "A3_PAML_ATC":
                            dd = defense.decide(decision, source_id=f"src-{sid}")
                        else:
                            dd = defense.decide(decision, source_id=f"src-{sid}", flow_index=int(rec["flow_index"]))
                        control_ms.append((perf_counter_ns() - t0) / 1_000_000.0)

                        atc_action = dd if config == "A3_PAML_ATC" else dd.atc
                        if label == 0:
                            benign_service += offered if decision.state == "BENIGN" else min(offered, atc_action.rate_limit_pps) * (1.0 - atc_action.drop_probability)
                        else:
                            protected_before_deception = (
                                offered if decision.state == "BENIGN"
                                else min(offered, atc_action.rate_limit_pps) * (1.0 - atc_action.drop_probability)
                            )
                            protected = protected_before_deception
                            if decision.state != "BENIGN":
                                attack_decisions += 1

                            if config == "A4_FULL":
                                target_history.append(dd.active_target)
                                if dd.mtd_event is not None:
                                    mtd_rotations += 1
                                if decision.state == "ATTACK":
                                    mtd_attack_events += 1
                                deception_attack_decisions += int(dd.deception.reason != "Deception only engages after confirmed attack state")
                                if dd.deception.routed_to_decoy:
                                    decoy_hits += 1
                                    decoy_attack_pps += protected_before_deception
                                    diverted_attack_pps += protected_before_deception * 0.90
                                    protected *= 0.10
                            attack_service += protected

                y_true.append(label)
                y_pred.append(pred)

        metrics = _binary_metrics(y_true, y_pred)
        benign_pdr, attack_pdr, overall_pdr, cpu, rtt = _network_outcome(
            benign_service, attack_service, benign_offered, attack_offered, config, rng
        )
        attack_block_rate = float(np.clip(1.0 - attack_service / max(attack_offered, 1e-9), 0.0, 1.0))
        total_latency = []
        if config in {"A3_PAML_ATC", "A4_FULL"}:
            n = min(len(inference_ms), len(control_ms))
            total_latency = [inference_ms[i] + control_ms[i] for i in range(n)]
        else:
            total_latency = inference_ms

        if config == "A4_FULL":
            unique_targets = len(set(target_history))
            target_coverage = unique_targets / len(MTD_TARGETS)
            rotation_rate = mtd_rotations / max(mtd_attack_events, 1)
            redirect_rate = decoy_hits / max(deception_attack_decisions, 1)
            diversion_rate = diverted_attack_pps / max(attack_offered, 1e-9)
        else:
            unique_targets = 1 if config != "A1_StaticThreshold" else 1
            target_coverage = 1.0 / len(MTD_TARGETS)
            rotation_rate = 0.0
            redirect_rate = 0.0
            diversion_rate = 0.0

        rows.append({
            "seed": seed,
            "configuration": config,
            **metrics,
            "benign_pdr": benign_pdr,
            "attack_pdr": attack_pdr,
            "overall_pdr": overall_pdr,
            "attack_block_rate": attack_block_rate,
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
            "benign_offered_pps": benign_offered,
            "attack_offered_pps": attack_offered,
            "benign_service_pps": benign_service,
            "attack_service_pps": attack_service,
            "attack_decisions": attack_decisions,
            "paml_attack_decisions": paml_attack_decisions,
            "static_positive": static_positive,
            "mtd_rotations": mtd_rotations,
            "mtd_attack_events": mtd_attack_events,
            "mtd_rotation_rate": rotation_rate,
            "mtd_unique_target_count": unique_targets if config == "A4_FULL" else 1,
            "mtd_target_coverage": target_coverage if config == "A4_FULL" else 1.0 / len(MTD_TARGETS),
            "decoy_hits": decoy_hits,
            "deception_attack_decisions": deception_attack_decisions,
            "deception_capture_rate": redirect_rate,
            "attack_redirect_rate": redirect_rate,
            "diverted_attack_pps": diverted_attack_pps,
            "decoy_attack_pps": decoy_attack_pps,
            "attack_diversion_rate": diversion_rate,
        })
    return rows


def summarize(raw):
    metrics = [
        "accuracy", "precision", "recall", "f1", "fpr", "fnr",
        "benign_pdr", "attack_pdr", "overall_pdr", "attack_block_rate",
        "cpu_percent", "rtt_ms", "feature_extraction_ms_mean", "feature_extraction_ms_p95",
        "inference_ms_mean", "inference_ms_p95", "control_decision_ms_mean",
        "control_decision_ms_p95", "packet_in_to_flow_mod_ms_mean", "packet_in_to_flow_mod_ms_p95",
        "attack_decisions", "mtd_rotations", "mtd_attack_events", "mtd_rotation_rate",
        "mtd_unique_target_count", "mtd_target_coverage", "decoy_hits",
        "deception_attack_decisions", "deception_capture_rate", "attack_redirect_rate",
        "diverted_attack_pps", "decoy_attack_pps", "attack_diversion_rate",
    ]
    out = []
    for config, g in raw.groupby("configuration", sort=False):
        row = {"configuration": config, "n_seeds": len(g)}
        for m in metrics:
            row[f"{m}_mean"] = float(g[m].mean())
            row[f"{m}_std"] = float(g[m].std(ddof=1))
        out.append(row)
    return pd.DataFrame(out)


def statistical_tests(raw):
    metrics = [
        "f1", "fpr", "fnr", "benign_pdr", "attack_pdr", "overall_pdr",
        "attack_block_rate", "cpu_percent", "rtt_ms", "packet_in_to_flow_mod_ms_mean",
        "mtd_rotation_rate", "deception_capture_rate", "attack_redirect_rate", "attack_diversion_rate",
    ]
    comparisons = [
        ("A2_PAML", "A1_StaticThreshold"),
        ("A3_PAML_ATC", "A2_PAML"),
        ("A4_FULL", "A3_PAML_ATC"),
        ("A4_FULL", "A1_StaticThreshold"),
    ]
    results = []
    for metric in metrics:
        pivot = raw.pivot(index="seed", columns="configuration", values=metric)
        for a, b in comparisons:
            s = _safe_stats(pivot[a].values, pivot[b].values)
            results.append({"metric": metric, "comparison": f"{a} vs {b}", **s})
    return pd.DataFrame(results)


def build_effect_report(raw):
    """Report A4's added observability relative to A3 without inventing causal claims."""
    a3 = raw[raw.configuration == "A3_PAML_ATC"].set_index("seed")
    a4 = raw[raw.configuration == "A4_FULL"].set_index("seed")
    rows = []
    for metric in ["attack_block_rate", "benign_pdr", "cpu_percent", "rtt_ms"]:
        delta = a4[metric] - a3[metric]
        rows.append({
            "metric": metric,
            "A3_mean": float(a3[metric].mean()),
            "A4_mean": float(a4[metric].mean()),
            "A4_minus_A3_mean": float(delta.mean()),
            "A4_minus_A3_std": float(delta.std(ddof=1)),
        })
    for metric in ["mtd_rotations", "mtd_rotation_rate", "mtd_unique_target_count", "mtd_target_coverage", "decoy_hits", "deception_capture_rate", "attack_redirect_rate", "diverted_attack_pps", "attack_diversion_rate"]:
        rows.append({
            "metric": metric,
            "A3_mean": float(a3[metric].mean()),
            "A4_mean": float(a4[metric].mean()),
            "A4_minus_A3_mean": float((a4[metric] - a3[metric]).mean()),
            "A4_minus_A3_std": float((a4[metric] - a3[metric]).std(ddof=1)),
        })
    return pd.DataFrame(rows)


def main():
    all_rows = []
    for seed in SEEDS:
        print(f"Running seed {seed + 1}/{len(SEEDS)}...")
        all_rows.extend(run_seed(seed))

    raw = pd.DataFrame(all_rows)
    summary = summarize(raw)
    stats = statistical_tests(raw)
    effects = build_effect_report(raw)

    raw_path = ROOT / "results" / "raw" / "phase6b1_seed_results.csv"
    summary_path = ROOT / "results" / "processed" / "phase6b1_mean_sd.csv"
    stats_path = ROOT / "results" / "statistics" / "phase6b1_paired_tests.csv"
    effect_path = ROOT / "results" / "statistics" / "phase6b1_a4_effect_report.csv"
    meta_path = ROOT / "results" / "processed" / "phase6b1_metadata.json"
    raw.to_csv(raw_path, index=False)
    summary.to_csv(summary_path, index=False)
    stats.to_csv(stats_path, index=False)
    effects.to_csv(effect_path, index=False)

    meta = {
        "phase": "6B.1",
        "purpose": "Make MTD and deception contributions explicitly measurable while preserving Phase-6B policy behavior.",
        "seeds": SEEDS,
        "configurations": CONFIGS,
        "sequences_per_class": SEQUENCES_PER_CLASS,
        "flows_per_sequence": FLOWS_PER_SEQUENCE,
        "capacity_pps": CAPACITY_PPS,
        "static_threshold_pps": STATIC_THRESHOLD_PPS,
        "static_limit_pps": STATIC_LIMIT_PPS,
        "static_drop_probability": STATIC_DROP_PROBABILITY,
        "paml_window": PAML_WINDOW_SIZE,
        "paml_threshold": PAML_ATTACK_THRESHOLD,
        "paml_persistence": PAML_PERSISTENCE,
        "mtd_targets": MTD_TARGETS,
        "rotation_interval": ROTATION_INTERVAL,
        "deception_probability": DECEPTION_PROBABILITY,
        "new_metrics": [
            "mtd_rotations", "mtd_attack_events", "mtd_rotation_rate",
            "mtd_unique_target_count", "mtd_target_coverage", "decoy_hits",
            "deception_attack_decisions", "deception_capture_rate",
            "attack_redirect_rate", "diverted_attack_pps", "decoy_attack_pps",
            "attack_diversion_rate",
        ],
        "important_note": "A4 metrics are observability/operational metrics in a synthetic simulator. They do not prove real-world MTD or honeypot effectiveness; that requires Phase 7 real datasets and later Mininet/Ryu validation.",
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print("\n=== Phase-6B.1 A4 MTD + Deception Refinement ===")
    cols = [
        "configuration", "f1_mean", "f1_std", "fpr_mean", "fnr_mean",
        "benign_pdr_mean", "attack_pdr_mean", "attack_block_rate_mean",
        "cpu_percent_mean", "rtt_ms_mean", "mtd_rotations_mean",
        "mtd_rotation_rate_mean", "mtd_target_coverage_mean", "decoy_hits_mean",
        "deception_capture_rate_mean", "attack_diversion_rate_mean",
    ]
    print(summary[cols].round(4).to_string(index=False))
    print("\nA3 vs A4 operational effect report:")
    print(effects.round(4).to_string(index=False))
    print("\nPaired statistical tests:")
    print(stats.round(6).to_string(index=False))
    print(f"\nSaved raw results       -> {raw_path}")
    print(f"Saved mean +/- SD      -> {summary_path}")
    print(f"Saved paired tests     -> {stats_path}")
    print(f"Saved A4 effect report -> {effect_path}")
    print(f"Saved metadata         -> {meta_path}")


if __name__ == "__main__":
    main()
