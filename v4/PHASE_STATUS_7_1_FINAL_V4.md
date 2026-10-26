# Phase 7.1 FINAL V4 status

## Completed

- [x] Exact 20-feature schema: 8 base + 12 temporal.
- [x] Shared temporal feature implementation for offline and online paths.
- [x] Packet-level deployment-calibration generator using the live short-flow aggregation semantics.
- [x] Ten-seed calibration benchmark.
- [x] Validation-driven threshold selection.
- [x] Per-stream temporal history and persistence.
- [x] Live 20-feature vector logging.
- [x] Training feature-distribution baseline.
- [x] KS/SMD deployment-drift diagnostic.
- [x] Monotonic controller latency instrumentation with raw timestamp fields.
- [x] Targeted regression tests pass.

## Calibration benchmark

Mean over 10 seeds:
- Accuracy: 97.42%
- Precision: 98.80%
- Recall: 97.99%
- F1: 98.39%
- FPR: 5.40%
- FNR: 2.01%

SD over 10 seeds:
- Accuracy: 0.56 percentage points
- Precision: 0.46 pp
- Recall: 0.57 pp
- F1: 0.39 pp
- FPR: 2.42 pp
- FNR: 0.57 pp

**These are synthetic deployment-calibration results, not live-testbed results.**

## Still required before final paper claims

1. Execute a real Mininet/Ryu V4 run.
2. Check `v4_feature_drift.json` before interpreting accuracy.
3. Confirm latency samples are valid and non-rejected.
4. Repeat the final protocol across the requested ten experimental seeds.
5. Use the resulting real-testbed mean ± SD for CPU, RTT, PDR, F1, FPR and FNR.
