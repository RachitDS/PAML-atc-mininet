# PAML-ATC V2 — Phase 7.1 FINAL

This version is the cleaned real-testbed handoff built on Phase 7. It keeps the real Mininet/Ryu/OpenFlow 1.3 pipeline and fixes the main problems observed during the first live run.

## What changed

### MODIFIED — benign / NTL handling
- NTL admits only configured benign hosts communicating with protected PLC IPs.
- Both directions are learned during the benign-only window.
- No forwarding FLOW_MOD is installed while a flow is being collected.
- This is important: installing a forwarding rule before the 20-packet flow record is complete would stop subsequent packets from reaching PAML.
- Known NTL traffic bypasses PAML after learning and is explicitly counted as NTL bypass.

### MODIFIED — live metric collection
The controller now records:
- Packet-In events by benign/attack source.
- PAML-eligible flow decisions and TP/TN/FP/FN.
- Forwarded/dropped/redirected actions.
- NTL learned-flow and bypass counters.
- MTD rotations and deception redirects/captures.
- Feature-extraction, inference and Packet-In -> Flow-Mod latency.
- Controller CPU samples.

The experiment records real network evidence:
- benign packets sent/received from Mininet `ping`;
- benign RTT;
- attack packets offered by the lab attack process;
- attack packets observed at the PLC interface using `tcpdump`.

### NEW — `phase7_report.py`
A root-level convenience command is provided:

```bash
python phase7_report.py
```

It reads the live controller and Mininet artifacts and produces the formatted terminal report plus:

```text
results/statistics/phase7_final_report.txt
```

### NEW — one-command runner

```bash
chmod +x scripts/run_phase7_1.sh
./scripts/run_phase7_1.sh
```

The runner:
1. cleans stale Mininet state;
2. starts Ryu;
3. waits for TCP/6653;
4. starts the ICS topology;
5. performs benign-only NTL learning;
6. waits for NTL completion;
7. runs controlled ICMP/UDP lab traffic;
8. collects measurements;
9. generates the final report;
10. cleans up the testbed.

## Important interpretation rule

The report does not fabricate missing metrics. Detection statistics are computed only from PAML-eligible controller decisions. Network PDR is computed from explicit offered/delivered packet counts. Controller latency comes from `perf_counter_ns` instrumentation.

The bundled model artifacts were originally serialized under a different scikit-learn runtime. For final publication-quality results, retrain/export the model using the same runtime stack used by the Ryu controller and record those versions in the experiment log.
