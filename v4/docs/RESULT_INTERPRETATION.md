# Phase 7 result interpretation

## Real measurements

The following values are intended to come from the actual Mininet/Ryu run:

- benign PDR: ICMP echo replies received / echo requests sent;
- attack PDR: packets observed at the protected PLC / packets reported sent by the isolated attacker namespaces;
- RTT: Linux `ping` output;
- controller CPU: `psutil` process CPU sampling;
- feature extraction latency: `perf_counter_ns` around online temporal/flow feature construction;
- RF inference latency: `perf_counter_ns` around scaler + Random Forest prediction;
- packet-in → flow-mod: time from Ryu PACKET_IN handler entry to `datapath.send_msg()`.

## What not to do

Do not copy values from Phase 6B.3 into Phase 7 tables. Do not label synthetic
Phase-6B.3 CPU/RTT/PDR as real Mininet measurements. Do not reconstruct packet
denominators from a PDR field.

## Model limitation to report

The Phase-1B Random Forest was trained on synthetic CIC-DDoS2019-inspired flow
records. The real adapter is therefore a testbed integration, not a claim of
CIC-DDoS2019-trained real-world generalization. If a real testbed attack falls
outside the model's learned feature/rate distribution, the raw probability,
classification and mitigation behavior should be reported rather than silently
recalibrated.
