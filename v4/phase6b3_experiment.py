"""Phase-6B.3: explicit packet accounting and defensible PDR evaluation.

REUSED: Phase-6B/6B.1 A1-A4 framework, PAML detector, ATC, MTD and deception.
MODIFIED: packet outcomes are now accumulated as explicit integer packet
          counters derived from flow PPS and flow duration.
NEW: benign/attack/total offered and delivered packet counters, attack
     diversion counters, PDR computed only from those counters, validation,
     and packet-accounting consistency tests.

SCOPE: synthetic service-capacity/control-plane simulation. This does not claim
live packet capture, Mininet, Ryu, or OpenFlow wire measurements.
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
from src.packet_accounting import PacketAccounting, pdr

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


def _static_baseline(offered_pps: float):
    positive = offered_pps >= STATIC_THRESHOLD_PPS
    if positive:
        return 1, STATIC_LIMIT_PPS, STATIC_DROP_PROBABILITY
    return 0, 10**12, 0.0


def _capacity_factor(total_offered_pps: float) -> float:
    return float(min(1.0, CAPACITY_PPS / max(float(total_offered_pps), 1.0)))


def run_seed(seed: int):
    rng = np.random.default_rng(seed + 32000)
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
        accounting = PacketAccounting(CAPACITY_PPS)
        y_true, y_pred = [], []
        feature_ms, inference_ms, control_ms = [], [], []
        attack_decisions = 0
        paml_attack_decisions = 0
        static_positive = 0
        mtd_rotations = 0
        mtd_attack_events = 0
        target_history = []
        decoy_hits = 0
        deception_attack_decisions = 0
        diverted_attack_pps = 0.0
        decoy_attack_pps = 0.0
        service_pps = 0.0
        offered_pps_total = 0.0

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

            # Capacity is evaluated at the sequence stream level. The same
            # offered traffic trace is used for all configurations.
            sequence_offered_pps = sum(float(r["flow_packets_per_sec"]) for r, *_ in outputs)
            capacity_factor = _capacity_factor(sequence_offered_pps)

            for rec, decision, f_ms, i_ms in outputs:
                label = int(rec["label"])
                offered = float(rec["flow_packets_per_sec"])
                duration_us = float(rec["flow_duration"])
                offered_pps_total += offered

                if config == "A1_StaticThreshold":
                    pred, rate_limit, drop_prob = _static_baseline(offered)
                    static_positive += pred
                    admitted = accounting.policy_admission(
                        accounting.offered_packets(offered, duration_us),
                        int(rate_limit), drop_prob, duration_us
                    )
                    outcome = accounting.record_flow(
                        label=label,
                        offered_pps=offered,
                        flow_duration_us=duration_us,
                        rate_limit_pps=int(rate_limit),
                        drop_probability=drop_prob,
                        capacity_factor=capacity_factor,
                    )
                else:
                    pred = int(decision.is_attack)
                    feature_ms.append(f_ms)
                    inference_ms.append(i_ms)
                    paml_attack_decisions += int(decision.is_attack)

                    if config == "A2_PAML":
                        rate_limit, drop_prob = 10**12, 0.0
                        outcome = accounting.record_flow(
                            label=label, offered_pps=offered, flow_duration_us=duration_us,
                            rate_limit_pps=rate_limit, drop_probability=drop_prob,
                            capacity_factor=capacity_factor,
                        )
                    else:
                        t0 = perf_counter_ns()
                        if config == "A3_PAML_ATC":
                            dd = defense.decide(decision, source_id=f"src-{sid}")
                        else:
                            dd = defense.decide(decision, source_id=f"src-{sid}", flow_index=int(rec["flow_index"]))
                        control_ms.append((perf_counter_ns() - t0) / 1_000_000.0)
                        atc_action = dd if config == "A3_PAML_ATC" else dd.atc

                        diverted_fraction = 0.0
                        if label == 1 and config == "A4_FULL" and dd.deception.routed_to_decoy:
                            diverted_fraction = 0.90
                            decoy_hits += 1
                            decoy_attack_pps += offered
                            diverted_attack_pps += offered * diverted_fraction
                        outcome = accounting.record_flow(
                            label=label, offered_pps=offered, flow_duration_us=duration_us,
                            rate_limit_pps=atc_action.rate_limit_pps,
                            drop_probability=atc_action.drop_probability,
                            capacity_factor=capacity_factor,
                            diverted_fraction=diverted_fraction,
                        )

                        if label == 1 and decision.state != "BENIGN":
                            attack_decisions += 1
                        if config == "A4_FULL":
                            target_history.append(dd.active_target)
                            if dd.mtd_event is not None:
                                mtd_rotations += 1
                            if decision.state == "ATTACK":
                                mtd_attack_events += 1
                            deception_attack_decisions += int(
                                dd.deception.reason != "Deception only engages after confirmed attack state"
                            )

                service_pps += outcome.delivered_packets / max(duration_us / 1_000_000.0, 1e-9)
                y_true.append(label)
                y_pred.append(pred)

        counters = accounting.counters()
        benign_pdr = pdr(counters["benign_delivered_packets"], counters["benign_offered_packets"])
        attack_pdr = pdr(counters["attack_delivered_packets"], counters["attack_offered_packets"])
        overall_pdr = pdr(counters["total_delivered_packets"], counters["total_offered_packets"])
        attack_block_rate = 1.0 - attack_pdr

        # Operational resource metrics remain synthetic model outputs, but are
        # derived from the same offered/service trace rather than hard-coded PDR.
        overhead = {"A1_StaticThreshold": 1.0, "A2_PAML": 3.0, "A3_PAML_ATC": 5.0, "A4_FULL": 7.0}[config]
        load_ratio = min(1.0, offered_pps_total / max(CAPACITY_PPS, 1.0))
        cpu = min(100.0, max(0.0, 8.0 + 24.0 * load_ratio + overhead + float(rng.normal(0, 0.35))))
        congestion = max(0.0, load_ratio - 1.0)
        rtt = max(1.0, 8.0 + 35.0 * congestion + 0.025 * overhead + float(rng.normal(0, 0.25)))

        total_latency = [inference_ms[i] + control_ms[i] for i in range(min(len(inference_ms), len(control_ms)))] if config in {"A3_PAML_ATC", "A4_FULL"} else inference_ms
        if config == "A4_FULL":
            unique_targets = len(set(target_history))
            target_coverage = unique_targets / len(MTD_TARGETS)
            rotation_rate = mtd_rotations / max(mtd_attack_events, 1)
            redirect_rate = decoy_hits / max(deception_attack_decisions, 1)
            diversion_rate = counters["attack_diverted_packets"] / max(counters["attack_offered_packets"], 1)
        else:
            unique_targets, target_coverage, rotation_rate, redirect_rate, diversion_rate = 1, 1.0 / len(MTD_TARGETS), 0.0, 0.0, 0.0

        metrics = _binary_metrics(y_true, y_pred)
        rows.append({
            "seed": seed, "configuration": config, **metrics,
            "benign_pdr": benign_pdr, "attack_pdr": attack_pdr, "overall_pdr": overall_pdr,
            "attack_block_rate": attack_block_rate, "cpu_percent": cpu, "rtt_ms": rtt,
            "feature_extraction_ms_mean": float(np.mean(feature_ms)) if feature_ms else 0.0,
            "feature_extraction_ms_p95": _percentile(feature_ms, 95),
            "inference_ms_mean": float(np.mean(inference_ms)) if inference_ms else 0.0,
            "inference_ms_p95": _percentile(inference_ms, 95),
            "control_decision_ms_mean": float(np.mean(control_ms)) if control_ms else 0.0,
            "control_decision_ms_p95": _percentile(control_ms, 95),
            "packet_in_to_flow_mod_ms_mean": float(np.mean(total_latency)) if total_latency else 0.0,
            "packet_in_to_flow_mod_ms_p95": _percentile(total_latency, 95),
            "attack_decisions": attack_decisions, "paml_attack_decisions": paml_attack_decisions,
            "static_positive": static_positive,
            "mtd_rotations": mtd_rotations, "mtd_attack_events": mtd_attack_events,
            "mtd_rotation_rate": rotation_rate, "mtd_unique_target_count": unique_targets,
            "mtd_target_coverage": target_coverage, "decoy_hits": decoy_hits,
            "deception_attack_decisions": deception_attack_decisions,
            "deception_capture_rate": redirect_rate, "attack_redirect_rate": redirect_rate,
            "diverted_attack_pps": diverted_attack_pps, "decoy_attack_pps": decoy_attack_pps,
            "attack_diversion_rate": diversion_rate,
            **counters,
        })

    return rows


def summarize(raw):
    metrics = [
        "accuracy", "precision", "recall", "f1", "fpr", "fnr", "benign_pdr", "attack_pdr", "overall_pdr",
        "attack_block_rate", "cpu_percent", "rtt_ms", "feature_extraction_ms_mean", "feature_extraction_ms_p95",
        "inference_ms_mean", "inference_ms_p95", "control_decision_ms_mean", "control_decision_ms_p95",
        "packet_in_to_flow_mod_ms_mean", "packet_in_to_flow_mod_ms_p95", "attack_decisions", "mtd_rotations",
        "mtd_attack_events", "mtd_rotation_rate", "mtd_unique_target_count", "mtd_target_coverage", "decoy_hits",
        "deception_attack_decisions", "deception_capture_rate", "attack_redirect_rate", "diverted_attack_pps",
        "decoy_attack_pps", "attack_diversion_rate", "benign_offered_packets", "benign_delivered_packets",
        "attack_offered_packets", "attack_delivered_packets", "attack_diverted_packets", "decoy_delivered_packets",
        "total_offered_packets", "total_delivered_packets", "total_policy_admitted_packets", "total_dropped_packets",
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
    metrics = ["f1", "fpr", "fnr", "benign_pdr", "attack_pdr", "overall_pdr", "attack_block_rate", "cpu_percent", "rtt_ms", "packet_in_to_flow_mod_ms_mean"]
    comparisons = [("A2_PAML", "A1_StaticThreshold"), ("A3_PAML_ATC", "A2_PAML"), ("A4_FULL", "A3_PAML_ATC"), ("A4_FULL", "A1_StaticThreshold")]
    rows = []
    for metric in metrics:
        pivot = raw.pivot(index="seed", columns="configuration", values=metric)
        for a, b in comparisons:
            rows.append({"metric": metric, "comparison": f"{a} vs {b}", **_safe_stats(pivot[a].values, pivot[b].values)})
    return pd.DataFrame(rows)


def validate_packet_accounting(raw):
    issues = []
    required = ["benign_offered_packets", "benign_delivered_packets", "attack_offered_packets", "attack_delivered_packets", "total_offered_packets", "total_delivered_packets"]
    missing = [c for c in required if c not in raw.columns]
    if missing:
        issues.append("MISSING_PACKET_FIELDS: " + ", ".join(missing))
        return issues
    for c in required:
        if (pd.to_numeric(raw[c], errors="coerce") < 0).any():
            issues.append(f"NEGATIVE_PACKET_COUNT: {c}")
    if (raw.benign_delivered_packets > raw.benign_offered_packets).any():
        issues.append("BENIGN_DELIVERED_GT_OFFERED")
    if (raw.attack_delivered_packets > raw.attack_offered_packets).any():
        issues.append("ATTACK_DELIVERED_GT_OFFERED")
    if not np.allclose(raw.total_offered_packets, raw.benign_offered_packets + raw.attack_offered_packets):
        issues.append("TOTAL_OFFERED_NOT_SUM")
    if not np.allclose(raw.total_delivered_packets, raw.benign_delivered_packets + raw.attack_delivered_packets):
        issues.append("TOTAL_DELIVERED_NOT_SUM")
    recomputed = raw.total_delivered_packets / raw.total_offered_packets
    if not np.allclose(raw.overall_pdr, recomputed, rtol=0, atol=1e-12):
        issues.append("OVERALL_PDR_NOT_FROM_PACKET_COUNTS")
    if not raw.overall_pdr.between(0, 1).all():
        issues.append("OVERALL_PDR_OUT_OF_RANGE")
    return issues


def main():
    raw_rows = []
    for seed in SEEDS:
        print(f"Running seed {seed + 1}/10...")
        raw_rows.extend(run_seed(seed))
    raw = pd.DataFrame(raw_rows)
    summary = summarize(raw)
    stats = statistical_tests(raw)
    issues = validate_packet_accounting(raw)

    raw_dir = ROOT / "results" / "raw"
    processed_dir = ROOT / "results" / "processed"
    stats_dir = ROOT / "results" / "statistics"
    for d in (raw_dir, processed_dir, stats_dir):
        d.mkdir(parents=True, exist_ok=True)

    raw_path = raw_dir / "phase6b3_seed_results.csv"
    summary_path = processed_dir / "phase6b3_mean_sd.csv"
    stats_path = stats_dir / "phase6b3_paired_tests.csv"
    validation_path = stats_dir / "phase6b3_packet_validation.txt"
    metadata_path = processed_dir / "phase6b3_metadata.json"

    raw.to_csv(raw_path, index=False)
    summary.to_csv(summary_path, index=False)
    stats.to_csv(stats_path, index=False)
    validation_path.write_text(
        "PAML-ATC V2 Phase-6B.3 Packet Accounting Validation\n" + "=" * 55 + "\n" +
        "PDR definition: delivered packets to the intended service / offered packets.\n" +
        "Attack packets diverted to decoys are counted separately and are not counted\n" +
        "as attack delivery to the intended PLC.\n\n" +
        ("STATUS: PASS\nNONE" if not issues else "STATUS: FAIL\n" + "\n".join(issues)),
        encoding="utf-8",
    )
    metadata_path.write_text(json.dumps({
        "phase": "6B.3", "seeds": SEEDS, "configurations": CONFIGS,
        "capacity_pps": CAPACITY_PPS, "duration_unit": "microseconds",
        "pdr_rule": "total_delivered_packets / total_offered_packets",
        "attack_pdr_rule": "attack_delivered_packets / attack_offered_packets",
        "decoy_packets_excluded_from_attack_pdr": True,
        "validation_issues": issues,
    }, indent=2), encoding="utf-8")

    print("\n=== Phase-6B.3 Explicit Packet Accounting Evaluation ===")
    print(summary[[
        "configuration", "f1_mean", "fpr_mean", "fnr_mean", "benign_pdr_mean", "attack_pdr_mean",
        "overall_pdr_mean", "attack_block_rate_mean", "benign_offered_packets_mean",
        "benign_delivered_packets_mean", "attack_offered_packets_mean", "attack_delivered_packets_mean",
        "attack_diverted_packets_mean", "cpu_percent_mean", "rtt_ms_mean"
    ]].round(6).to_string(index=False))
    print("\nPacket accounting validation:")
    print("  PASS" if not issues else "  FAIL\n  " + "\n  ".join(issues))
    print(f"\nSaved raw results   -> {raw_path}")
    print(f"Saved mean +/- SD   -> {summary_path}")
    print(f"Saved paired tests  -> {stats_path}")
    print(f"Saved validation    -> {validation_path}")
    print(f"Saved metadata      -> {metadata_path}")


if __name__ == "__main__":
    main()
