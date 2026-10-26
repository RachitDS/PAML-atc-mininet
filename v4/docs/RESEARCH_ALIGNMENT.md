# Research alignment

The reference architecture combines SDN controller applications (ATC and MTD)
with redundant/deceptive network resources. The original ATC performs normal
traffic learning so known benign flows can bypass controller processing, while
abnormal traffic is handled at the application layer. Phase 7 preserves that
architecture and adds the PAML temporal/ML decision path.

The supplied guideline asks for a real Ryu/Floodlight controller with Mininet,
30–90% botnet ratios, 300–2000 PPS, and measurements of CPU, RTT, PDR and
detection latency. Phase 7's topology therefore includes ten isolated attacker
hosts, allowing 3/6/9 attackers to represent 30/60/90% of the attacker pool.

The reference PAML-ATC paper reports a 50-node conceptual ICS-SDN model with
three switches and 2 Mbps switch bandwidth. This implementation uses a compact
role-preserving topology first; scaling to 50 hosts is a separate stress-test
and should be performed only after the control path is stable.
