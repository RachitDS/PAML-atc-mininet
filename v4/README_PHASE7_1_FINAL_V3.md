# PAML-ATC Phase 7.1 FINAL v3

## Why v3 exists

FINAL v3 exposed an important deployment gap: the offline PAML model was trained on feature distributions that were substantially different from the short Mininet flows produced by the live experiment. In addition, the online detector kept one global temporal history, which could mix unrelated hosts and protocols.

v3 addresses those two issues without using attack ground-truth to make controller decisions.

## Main changes

1. **Deployment-calibrated PAML model**
   - New synthetic development/calibration dataset matches the Phase-7 live flow envelope (roughly 300–2200 PPS floods, realistic benign rates, short 20-packet flows).
   - Same 20-feature schema and same temporal feature implementation are used for training and online inference.
   - Random Forest increased to 180 trees, depth 18, minimum leaf 2, balanced-subsample weighting.
   - Benchmark is explicitly synthetic and is NOT claimed to be original CIC-DDoS2019 performance.

2. **Per-stream temporal history**
   - Five-flow temporal history is now maintained independently for each `(src_ip, dst_ip, protocol)` stream.
   - Persistence is also per stream, preventing unrelated flows from contaminating each other's evidence.

3. **No premature forced PAML inference**
   - The live controller no longer forces a flow to expire just to obtain an immediate one-packet PAML decision.
   - A flow is emitted by the configured packet/idle rule, preserving the intended short-flow aggregation.

4. **Benign observation remains live**
   - A benign PAML decision is forwarded with PacketOut but does not install a long-lived forwarding FLOW_MOD. This keeps subsequent short flows visible to the controller so temporal evidence can accumulate.

5. **Short lab attack rule lifetime**
   - Attack DROP rules use a configurable one-second hard timeout by default. This is a laboratory observability setting, not a production recommendation. It allows repeated PAML decisions during a continuous five-second attack trace.

6. **Operational defaults**
   - Window: 5 flows
   - Attack threshold: 0.60
   - Persistence: 2 consecutive positive flow decisions

## Offline deployment-calibration benchmark

The v3 calibration benchmark produced approximately 99% binary accuracy and 99.6% F1 on its held-out synthetic test sequences at the selected operating threshold. These are development/calibration numbers only; they must not be presented as measured real-network accuracy.

## What to report

Use the real Mininet/Ryu run for the live-testbed table. The offline v3 calibration score should be shown separately as **Deployment-Calibrated Offline Validation**.

The final real-testbed run remains the authoritative source for live Accuracy, Precision, Recall, F1, FPR, FNR, CPU, RTT, PDR, action counts, and controller latency.
