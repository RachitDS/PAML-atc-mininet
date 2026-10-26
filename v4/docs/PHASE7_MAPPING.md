# Phase 7 mapping to the research requirements

| Requirement | Implementation |
|---|---|
| Packet-in → NTL bypass | `controller/ryu_paml_controller.py` |
| Temporal feature extraction | `controller/flow_features.py` + `src/paml_detector.py` |
| ML inference | Phase-1B Random Forest artifacts loaded by `PAMLDetector` |
| Adaptive ATC | `src/adaptive_atc.py` |
| MTD | `controller/mtd_manager.py` |
| Deception | Ryu redirects confirmed ICMP/UDP/SYN attack flows toward honeypot when its port is learned |
| Real SDN | Ryu + OpenFlow 1.3 |
| Real topology | `mininet_lab/ics_topology.py` |
| Attack traffic | `attacks/run_attack.py` |
| CPU | `ControllerMetrics` + psutil |
| RTT | Linux `ping` from Mininet hosts |
| PDR | packets sent/received by controlled ping probe; not inferred from PDR |
| Flow-mod latency | `perf_counter_ns` around OpenFlow `send_msg` |
| Mean / p95 latency | `ControllerMetrics.mean_p95` |

## Scope caveat

The model is still trained using Phase-1B synthetic CIC-DDoS2019-inspired data. Real Mininet/Ryu measurements validate the control-plane implementation and network behavior, not the external validity of the training dataset.
