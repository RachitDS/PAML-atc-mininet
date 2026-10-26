# Phase 7.1 FINAL v3 status

Implemented: real Mininet topology, Ryu OpenFlow 1.3 controller, benign-only NTL, online flow aggregation, PAML inference, adaptive ATC, logical MTD/deception, real traffic, explicit PDR/RTT collection, and controller latency instrumentation.

Main v2 fix: all controller latency measurements use the same monotonic `perf_counter_ns` clock and the report rejects invalid samples.

Validation requirement: run the one-command script in Linux/WSL2. The resulting report is the authoritative real-testbed output; do not substitute synthetic Phase-6 values for real-testbed measurements.
