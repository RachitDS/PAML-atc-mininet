# PAML-ATC Phase 7.1 FINAL v3

## Purpose
This revision preserves the Phase 7.1 real Mininet/Ryu testbed and fixes the final measurement path.

### FIXED
- Controller latency uses one monotonic `time.perf_counter_ns()` timebase.
- PAML latency samples exclude NTL bypass and flow-collection events.
- Invalid/negative/absurd latency samples are rejected rather than reported.
- Feature, inference, and Packet-In -> FLOW_MOD latency each report mean and P95.
- Final report derives action counts from the complete controller event log, reducing dependence on snapshot timing.
- NTL remains benign<->protected only; attacker flows are never admitted to the NTL table.
- Mininet is launched with the system Python because its apt package is installed there.

## One-command run
Activate `.venv-ryu`, then run:

```bash
./scripts/run_phase7_1.sh
```

The script starts Ryu, launches the Mininet testbed, performs benign-only NTL warm-up, generates live attack/benign traffic, collects evidence, and writes the report.

## Evidence
- `results/raw/controller_events.csv`
- `results/raw/controller_metrics_live.json`
- `results/raw/phase7_measurements.csv`
- `results/statistics/phase7_final_report_v2.txt`
- `results/raw/ryu_phase7_1.log`

## Important interpretation
`Packet-In -> Flow-Mod` is the controller-side reaction time from receipt of Packet-In to submission of the OpenFlow FLOW_MOD. It is not a switch acknowledgement latency. Network PDR/RTT remain based on explicit Mininet measurements.

No performance values are fabricated. A poor real-testbed PAML score is a valid experimental result and should trigger model-range analysis/retraining rather than manual metric adjustment.
