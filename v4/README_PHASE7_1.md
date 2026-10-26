# PAML-ATC V2 — Phase 7.1

Phase 7.1 is a corrected, run-ready version of Phase 7. It preserves the real Mininet/Ryu/OpenFlow/PAML/ATC/MTD pipeline and adds three concrete improvements:

- **MODIFIED — benign/NTL handling:** only configured benign hosts communicating with protected PLCs are learned; reverse directions are learned too; attackers are never admitted to NTL; sparse traffic is forwarded without forcing a one-packet PAML inference.
- **MODIFIED — live metrics:** controller event metrics are reset per run and track TP/TN/FP/FN, forwarding, rate-limit, drop, redirect, MTD and deception counters, plus mean/p95 latency and CPU.
- **NEW — `tools/phase7_report.py`:** combines controller metrics and real Mininet packet measurements into a formatted terminal report. The experiment calls the report automatically when it finishes.
- **NEW — `scripts/run_phase7_1.sh`:** one-command quick-run wrapper that starts Ryu, runs the Mininet experiment, and prints the report.

## Recommended run

From WSL2/Linux, from this project directory:

```bash
cd ~/PAML_ATC_V2_PHASE7
chmod +x scripts/run_phase7_1.sh
./scripts/run_phase7_1.sh
```

The wrapper uses the Python 3.9 Ryu environment at `.venv-ryu`. It runs a controlled ICMP/UDP quick experiment. The controller's default NTL learning period is 30 seconds, so the quick run intentionally waits for that learning window after benign warm-up traffic.

## Standalone report

After a run:

```bash
.venv-ryu/bin/python tools/phase7_report.py
```

## Evidence files

- `results/raw/controller_events.csv` — per-controller-event evidence
- `results/raw/controller_metrics_live.json` — live summary snapshot
- `results/raw/phase7_measurements.csv` — Mininet scenario measurements
- `results/processed/phase7_mean_sd.csv` — scenario aggregation
- `results/statistics/phase7_latency_summary.csv` — latency/CPU summary
- `results/statistics/phase7_validation.txt` — measurement notes

## Important research note

The report does not fabricate an overall PDR. It reports benign PDR from real Mininet ping counters and attack PDR from real offered-packet/packet-capture counts. The live detection confusion matrix is based on configured lab IP ground truth and controller events. Before final paper results, retrain/export the model under the same runtime versions used by the Ryu controller to remove cross-version serialization warnings.
