# PAML-ATC V4 — deployment-aligned live-testbed package

## What V4 changes

**REUSED**
- PAML Random Forest concept and five-flow temporal design.
- Ryu/OpenFlow 1.3 + Mininet ICS topology.
- Adaptive ATC, MTD and deception components.
- Explicit packet accounting and real ping/tcpdump measurements.

**MODIFIED**
- The model schema is now explicit: **8 base + 12 temporal = 20 model inputs**.
- Offline and online temporal feature construction share the same implementation.
- Training calibration is generated from the same short 20-packet flow aggregation semantics used by the live adapter.
- Threshold and persistence are selected from validation evidence rather than manually lowered to make the result look better.
- Controller inference avoids pandas construction on the hot path.
- Latency uses `monotonic_ns()` consistently and stores raw packet-in/flow-mod timestamps for audit.

**NEW**
- `models/paml_v4_feature_stats.json` training distribution baseline.
- `results/raw/live_paml_features.csv` exact live 20-feature vectors.
- `tools/compare_feature_distributions_v4.py` KS/SMD deployment-drift diagnostic.
- Ten-seed synthetic deployment-calibration benchmark.
- V4 report with explicit latency-integrity checks.

## Important scientific rule

V4 does **not** promise a higher live accuracy. The point is to remove the main source of uncertainty seen in V3: the training and deployment feature definitions/distributions must match before interpreting a live score. A real Mininet rerun is still required.

The synthetic calibration benchmark is not a substitute for CIC-DDoS2019 and must not be presented as real-testbed accuracy.

## Run

1. Train the V4 model using the same Python environment intended for Ryu/model inference:

```bash
python3 train_v4.py
```

2. Run the quick real Mininet/Ryu test:

```bash
bash scripts/run_phase7_1_v4.sh
```

3. Inspect:
- `results/statistics/phase7_final_report_v4.txt`
- `results/raw/controller_events.csv`
- `results/raw/live_paml_features.csv`
- `results/statistics/v4_feature_drift.json`

## How to interpret the drift file

- `SMD` near 0: live and training feature means are close relative to pooled spread.
- large `|SMD|` or KS distance: deployment mismatch remains and should be investigated before model tuning.
- A better live F1 is meaningful only when it comes from a real rerun with the same evaluation protocol.
