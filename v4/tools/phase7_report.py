"""Generate the Phase 7.1 FINAL real-testbed terminal report.

All network values come from explicit Mininet measurements; controller values
come from the Ryu metrics snapshot/event log. Missing values are reported as
0/N/A rather than fabricated.
"""
from __future__ import annotations

import csv
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "results/raw/controller_events.csv"
LIVE = ROOT / "results/raw/controller_metrics_live.json"
MEASURE = ROOT / "results/raw/phase7_measurements.csv"
REPORT = ROOT / "results/statistics/phase7_final_report_v3.txt"


def cmd(c):
    try:
        return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "N/A"


def pct(x):
    return f"{100.0 * float(x):.2f} %"


def num(x, unit=""):
    return f"{float(x):.3f}{unit}"


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def f(row, key, default=0.0):
    try:
        return float(row.get(key, default))
    except (TypeError, ValueError):
        return default


def main():
    live = json.loads(LIVE.read_text(encoding="utf-8")) if LIVE.exists() else {}
    events = read_csv(EVENTS)
    rows = read_csv(MEASURE)

    eligible = [r for r in events if r.get("evaluation_eligible", "0") == "1"]
    tp = sum(1 for r in eligible if r.get("category") == "attack" and r.get("detected") == "1")
    tn = sum(1 for r in eligible if r.get("category") == "benign" and r.get("detected") == "0")
    fp = sum(1 for r in eligible if r.get("category") == "benign" and r.get("detected") == "1")
    fn = sum(1 for r in eligible if r.get("category") == "attack" and r.get("detected") == "0")
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    benign_sent = sum(int(f(r, "benign_offered_packets")) for r in rows)
    benign_recv = sum(int(f(r, "benign_delivered_packets")) for r in rows)
    attack_sent = sum(int(f(r, "attack_offered_packets")) for r in rows)
    attack_recv = sum(int(f(r, "attack_delivered_packets")) for r in rows)
    total_sent = benign_sent + attack_sent
    total_recv = benign_recv + attack_recv
    overall_pdr = total_recv / total_sent if total_sent else 0.0
    benign_pdr = benign_recv / benign_sent if benign_sent else 0.0
    attack_pdr = attack_recv / attack_sent if attack_sent else 0.0

    attack_decision_events = tp + fn
    captured = int(live.get("attack_captured", 0))
    capture_rate = captured / attack_decision_events if attack_decision_events else 0.0
    # Action counters are derived from the complete event log when available,
    # so the report does not depend on the monitor thread's last snapshot.
    action_rows = [r for r in events if r.get("action")]
    forwarded = sum(1 for r in action_rows if r.get("action") == "FORWARD")
    rate_limited = sum(1 for r in action_rows if r.get("action") == "RATE_LIMIT")
    dropped = sum(1 for r in action_rows if r.get("action") == "DROP")
    redirected = sum(1 for r in action_rows if r.get("action") == "REDIRECT")
    defended = dropped + rate_limited + redirected
    attack_packet_in = sum(1 for r in events if r.get("category") == "attack")
    blocked_rate = defended / attack_packet_in if attack_packet_in else 0.0

    # Recompute controller latency directly from the event log. This avoids
    # stale snapshots and excludes NTL/flow-collection events.
    feature_vals = [f(r, "feature_ms") for r in eligible if f(r, "feature_ms") > 0]
    infer_vals = [f(r, "inference_ms") for r in eligible if f(r, "inference_ms") > 0]
    flow_vals = [f(r, "flow_mod_ms") for r in eligible if r.get("flow_mod_ms") not in (None, "") and f(r, "flow_mod_ms") >= 0]
    def p95(vals):
        if not vals: return 0.0
        vals = sorted(vals); pos = 0.95 * (len(vals)-1); lo = int(pos); hi = min(lo+1, len(vals)-1); frac = pos-lo
        return vals[lo] + frac*(vals[hi]-vals[lo])
    feature_mean = mean(feature_vals) if feature_vals else 0.0
    infer_mean = mean(infer_vals) if infer_vals else 0.0
    flow_mean = mean(flow_vals) if flow_vals else 0.0

    rtts = [f(r, "benign_rtt_ms") for r in rows if r.get("benign_rtt_ms") not in (None, "")]
    rtt = mean(rtts) if rtts else f(live, "rtt_ms_mean")

    mn = cmd("command -v mn >/dev/null 2>&1 && mn --version")
    if mn == "N/A":
        mn = cmd("/usr/bin/mn --version")
    ovs = cmd("ovs-vsctl --version | head -1")
    ryu = cmd("ryu-manager --version")
    if ryu == "N/A":
        ryu = "N/A (run inside .venv-ryu)"

    lines = []
    add = lines.append
    add("=" * 60)
    add("        PAML-ATC REAL SDN/ICS TESTBED")
    add("        PHASE 7.1 FINAL v3")
    add("=" * 60)
    add("")
    add("[1] ENVIRONMENT")
    add(f"Python       : {platform.python_version()}")
    add(f"Ryu          : {ryu}")
    add("OpenFlow     : 1.3")
    add(f"Mininet      : {mn}")
    add(f"Open vSwitch : {ovs.replace('Open vSwitch ', '') if ovs != 'N/A' else ovs}")
    add("")
    add("[2] TOPOLOGY")
    add("Switches     : 3")
    add("PLC          : 3")
    add("RTU          : 1")
    add("Benign hosts : 3")
    add("Attackers    : 10")
    add("Honeypot     : 1")
    add("")
    add("[3] PAML MODEL")
    add("Model        : Random Forest")
    add("Features     : 20")
    add("Window       : 5 flows")
    add("Threshold    : 0.60")
    add("Persistence  : 2")
    add("")
    add("[4] NTL")
    add(f"Learning period : {live.get('ntl_period', os.getenv('PAML_NTL_PERIOD', '30'))} seconds")
    add(f"Learned flows   : {live.get('ntl_learned_flows', 0)}")
    add(f"NTL bypass      : {live.get('ntl_bypass_events', 0)}")
    add("")
    add("[5] LIVE TRAFFIC")
    add(f"Benign packets  : {benign_sent}")
    add(f"Attack packets  : {attack_sent}")
    add("")
    add("[6] PAML DETECTION")
    add(f"Accuracy        : {pct(accuracy)}")
    add(f"Precision       : {pct(precision)}")
    add(f"Recall          : {pct(recall)}")
    add(f"F1 Score        : {pct(f1)}")
    add(f"FPR             : {pct(fpr)}")
    add(f"FNR             : {pct(fnr)}")
    add(f"Evaluation flows: {total}")
    add("")
    add("[7] ADAPTIVE ATC")
    add(f"Forwarded       : {forwarded}")
    add(f"Rate limited    : {rate_limited}")
    add(f"Dropped         : {dropped}")
    add(f"Blocked rate    : {pct(blocked_rate)}")
    add("")
    add("[8] MTD + DECEPTION")
    add(f"MTD rotations   : {live.get('mtd_rotations', 0)}")
    add(f"Decoy redirects : {live.get('decoy_redirects', 0)}")
    add(f"Attack captured : {pct(capture_rate)}")
    add("")
    add("[9] NETWORK PERFORMANCE")
    add(f"CPU usage       : {num(live.get('cpu_percent_mean', 0), ' %')}")
    add(f"RTT             : {num(rtt, ' ms')}")
    add(f"PDR             : {pct(overall_pdr)}")
    add(f"  benign PDR    : {pct(benign_pdr)}")
    add(f"  attack PDR    : {pct(attack_pdr)}")
    add("")
    add("[10] LATENCY")
    add(f"Feature extraction     : {num(feature_mean, ' ms')} (P95 {num(p95(feature_vals), ' ms')})")
    add(f"PAML inference         : {num(infer_mean, ' ms')} (P95 {num(p95(infer_vals), ' ms')})")
    add(f"Packet-In -> Flow-Mod  : {num(flow_mean, ' ms')} (P95 {num(p95(flow_vals), ' ms')})")
    add(f"Latency samples       : {len(flow_vals)} valid / {int(live.get('latency_invalid_count', 0))} rejected")
    add("")
    add("[11] VALIDATION NOTES")
    add("PDR source       : explicit Mininet ping counters + attack tcpdump capture")
    add("Latency source   : single monotonic perf_counter_ns timebase")
    add("Latency meaning  : Packet-In -> controller FLOW_MOD submission (not switch install acknowledgement)")
    add("Detection source : controller event ground truth from configured lab IPs")
    add("NTL policy       : benign<->protected flows only; no attacker admission")
    add("Flow collection  : no forwarding FLOW_MOD until a flow is emitted to PAML")
    add("Model caveat     : use matching sklearn/NumPy model artifacts for final paper runs")
    add("")
    add("[12] RESULT FILES")
    add(f"Controller events : {EVENTS}")
    add(f"Live metrics      : {LIVE}")
    add(f"Experiment data   : {MEASURE}")
    add(f"Report            : {REPORT}")
    add("")
    add("=" * 60)
    add("              EXPERIMENT COMPLETED")
    add("=" * 60)

    text = "\n".join(lines) + "\n"
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
