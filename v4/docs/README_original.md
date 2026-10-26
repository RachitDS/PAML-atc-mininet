# PAML-ATC V2 — Phase 7.1 FINAL V4

V4 is the deployment-alignment revision of the real Mininet/Ryu PAML-ATC
laboratory package.

## V4 headline

**20 model features = 8 base + 12 temporal.** The offline training path and
live Ryu path use the same temporal feature builder. V4 also records every live
PAML feature vector and provides training-vs-live distribution diagnostics.

## Run order

### 1. Train the V4 calibration model

```bash
python3 train_v4.py
```

This produces a ten-seed synthetic deployment-calibration benchmark and saves
the selected deployment candidate under `models/paml_v4_*`.

### 2. Run the real Mininet/Ryu testbed

Use the Ryu Python environment prepared for the project:

```bash
bash scripts/run_phase7_1_v4.sh
```

The experiment remains restricted to the RFC1918 Mininet laboratory topology.

### 3. Inspect the evidence

- `results/statistics/phase7_final_report_v4.txt`
- `results/raw/controller_events.csv`
- `results/raw/live_paml_features.csv`
- `results/statistics/v4_feature_drift.json`
- `models/paml_v4_feature_stats.json`
- `results/processed/training_metrics_v4.json`

## REUSED / MODIFIED / NEW

### REUSED
- PAML temporal-detection concept and Random Forest family.
- Ryu/OpenFlow 1.3 controller path.
- Mininet ICS topology.
- Adaptive ATC.
- MTD/deception components.
- Explicit PDR/RTT packet measurements.

### MODIFIED
- Explicit 8+12=20 feature schema.
- Shared offline/online temporal feature implementation.
- Packet-level short-flow calibration generation.
- Validation-driven threshold selection.
- Faster inference path without pandas DataFrame creation per decision.
- Monotonic latency instrumentation with raw timestamp evidence.

### NEW
- Live feature-vector CSV.
- Training feature-distribution baseline.
- KS/SMD drift diagnostic.
- Ten-seed deployment-calibration benchmark.

## Scientific validity

The ten-seed calibration result is **synthetic development evidence**. It is
not a live Mininet accuracy result and it is not a replacement for the
original CIC-DDoS2019 evaluation. A better live score must come from an actual
rerun under the same test protocol.

V4 is specifically designed to answer the V3 failure mode: if live detection
still underperforms, `v4_feature_drift.json` identifies whether the problem is
feature-distribution mismatch rather than hiding the mismatch by tuning the
reported result.
