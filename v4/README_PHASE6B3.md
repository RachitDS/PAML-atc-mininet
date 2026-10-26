# PAML-ATC V2 — Phase 6B.3

## Explicit Packet Accounting & Defensible PDR

**REUSED:** Phase-6B/6B.1 A1–A4 evaluation framework, PAML detector, adaptive ATC, MTD and deception.

**MODIFIED:** The evaluation no longer needs to infer aggregate PDR from PPS/service estimates. Each flow is converted into an explicit integer offered-packet count using `flow_packets_per_sec × flow_duration` and then passed through deterministic policy/capacity accounting.

**NEW:**
- `benign_offered_packets`
- `benign_delivered_packets`
- `attack_offered_packets`
- `attack_delivered_packets`
- `attack_diverted_packets`
- `decoy_delivered_packets`
- total offered/delivered/dropped counters
- PDR validation against packet counts
- 10-seed raw, mean±SD and paired-test outputs

### PDR definitions

```text
benign_pdr = benign_delivered_packets / benign_offered_packets
attack_pdr = attack_delivered_packets / attack_offered_packets
overall_pdr = total_delivered_packets / total_offered_packets
```

For A4, packets redirected to a decoy are **not** counted as successful delivery to the intended PLC. They are reported separately as `attack_diverted_packets` / `decoy_delivered_packets`.

### Important scope statement

This is still a **synthetic service-capacity/control-plane simulator**. The packet counts are deterministic simulated counters, not packets observed from a live NIC, Mininet, Ryu, OpenFlow switch, or packet capture. The phase fixes the denominator problem without making a real-network claim.

## Run

```powershell
python -m pytest
python phase6b3_experiment.py
```

Expected validation at the end:

```text
Packet accounting validation:
  PASS
```

Outputs:

```text
results/raw/phase6b3_seed_results.csv
results/processed/phase6b3_mean_sd.csv
results/statistics/phase6b3_paired_tests.csv
results/statistics/phase6b3_packet_validation.txt
results/processed/phase6b3_metadata.json
```
