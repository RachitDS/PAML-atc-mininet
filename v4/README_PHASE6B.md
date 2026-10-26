# PAML-ATC V2 — Phase 6B

## Purpose
Phase 6B is a correction/upgrade of the Phase-6 evaluation. It keeps the 10-seed reproducible simulator but makes the A1-A4 comparison operationally meaningful.

### A1 — Static conventional baseline
A conventional detector uses a fixed `flow_packets_per_sec >= 1500` threshold and a fixed mitigation policy. This baseline can create both false positives and false negatives.

### A2 — PAML
PAML performs stateful temporal detection, but no traffic-control action is applied. This isolates detection quality from mitigation.

### A3 — PAML + Adaptive ATC
PAML decisions drive attack-type-aware adaptive traffic control.

### A4 — FULL
PAML + Adaptive ATC + MTD + selective deception. MTD/deception are evaluated mainly through protected-service attack load, rotations and decoy captures rather than being incorrectly expected to change the classifier's F1.

## Metrics
Detection:
- Accuracy
- Precision
- Recall
- F1
- FPR
- FNR

Operational:
- Benign PDR
- Attack PDR at the protected service
- Overall PDR
- Attack block rate
- CPU load
- RTT
- Feature extraction latency
- ML inference latency
- Control decision latency
- Packet-in to flow-mod latency
- MTD rotations
- Decoy captures

## Important limitation
This remains a **synthetic simulator**. CPU, RTT and PDR are generated from a documented capacity/congestion model. These values must not be presented as live Mininet/Ryu or physical-ICS measurements.

## Run
```powershell
python -m pytest
python phase6b_experiment.py
python visualization/plot_phase6b.py
```

Outputs:
- `results/raw/phase6b_seed_results.csv`
- `results/processed/phase6b_mean_sd.csv`
- `results/statistics/phase6b_paired_tests.csv`
- `results/processed/phase6b_metadata.json`
- `plots/phase6b_*.png`
