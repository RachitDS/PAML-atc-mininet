# FINAL v3 change log

## Goal
Improve live-testbed detection robustness by aligning offline model training with the actual short Mininet flow regime and preserving temporal locality in the online detector.

## Changes
- Deployment-calibrated synthetic training data for the Phase-7 rate envelope.
- New RF artifacts trained from that calibration dataset.
- Per-stream five-flow temporal history instead of one global history.
- Per-stream persistence counters.
- Removed forced one-packet PAML inference from the controller path.
- Benign PAML decisions stay observable via Packet-Out rather than installing a long-lived forwarding rule.
- Attack mitigation rules use a short configurable hard timeout in the lab so repeated decisions remain observable during evaluation.
- Default PAML threshold changed to 0.60 and persistence to 2.
- Fixed NTL latency-event variable handling.

## Evidence
The deployment-calibration held-out synthetic benchmark is approximately 99.2% binary accuracy and 99.5% F1 at the v3 0.60 operating threshold.

This is **not** a real-testbed result and must not be presented as such. The authoritative live numbers must come from the WSL Mininet/Ryu run.
