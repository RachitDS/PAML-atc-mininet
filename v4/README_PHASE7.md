# PAML-ATC V2 — Phase 7 (7.1–7.7)

## Real SDN / Mininet / Ryu Testbed

This phase extends the verified Phase-6B.3 synthetic evaluation into a **real OpenFlow control-plane testbed** using Mininet and Ryu.

### Status model

- **REUSED:** Phase-6B.3 PAML detector, scaler/model artifacts, temporal feature definitions, adaptive ATC concepts, MTD/deception concepts, packet-accounting definitions.
- **MODIFIED:** The inference/control path is connected to real Ryu `PACKET_IN` events and OpenFlow `FLOW_MOD` rules.
- **NEW:** Mininet ICS topology, Ryu controller application, live flow aggregation, real packet counters, real RTT/PDR measurement, controller CPU measurement, packet-in → flow-mod latency measurement, attack traffic generators, and Phase-7 result collection.

The Phase-6B.3 experiment remains untouched and is the simulation reference. Do not replace its results with Phase-7 results.

## Phase 7.1–7.7

1. **7.1 Mininet ICS topology** — 3 OpenFlow switches, PLC/MTU/RTU-style hosts, benign clients, attacker hosts, and a honeypot.
2. **7.2 Ryu OpenFlow controller** — OpenFlow 1.3, table-miss, MAC learning, PACKET_IN handling, FLOW_MOD installation, counters.
3. **7.3 Real PAML inference** — online flow aggregation, 17 base features, five-flow temporal features, Random Forest inference.
4. **7.4 Real adaptive ATC** — benign bypass, suspicious rate-limit, persistent attack DROP/rate-limit rules.
5. **7.5 MTD + deception** — controller-managed rotating virtual protected targets and honeypot redirection.
6. **7.6 Real attack traffic** — ICMP, TCP SYN and UDP floods using standard Linux tools/Scapy. Run only inside the isolated Mininet testbed.
7. **7.7 Real measurements** — CPU, RTT, packet counters/PDR, detection latency, PACKET_IN→FLOW_MOD latency, mean and p95 latency.

## Architecture

```text
                         +---------------------------+
                         |       Ryu Controller      |
                         |---------------------------|
                         | NTL bypass                |
                         | Flow aggregation          |
                         | Temporal features        |
                         | PAML Random Forest       |
                         | Adaptive ATC              |
                         | MTD / Honeypot            |
                         | Metrics                   |
                         +-------------+-------------+
                                       |
                              OpenFlow 1.3
                                       |
              +------------------------+------------------------+
              |                        |                        |
          +---+---+                +---+---+                +---+---+
          |   s1  |----------------|   s2  |----------------|   s3  |
          +---+---+                +---+---+                +---+---+
              |                        |                        |
       benign / PLC              MTU / RTU               attacker / honey
```

## Environment

Use **Ubuntu 22.04/24.04 in a VM or WSL2**. Mininet is not a native Windows testbed. For the Ryu application, use a Python environment compatible with your installed Ryu package.

Recommended system packages:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iperf3 tcpdump tshark iputils-ping hping3 python3-pip python3-venv
```

Create an environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements_phase7_linux.txt
```

If your distribution's Ryu package is available through pip:

```bash
pip install ryu
```

If Ryu/eventlet is incompatible with the system Python, use a supported Python version/VM rather than modifying the research logic.

## Run order

### 7.1 + 7.2 connectivity

Terminal 1:

```bash
source .venv/bin/activate
ryu-manager --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py
```

Terminal 2:

```bash
sudo python3 mininet_lab/ics_topology.py --controller 127.0.0.1 --port 6653
```

Inside Mininet:

```text
mininet> pingall
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected: hosts can communicate and the controller receives switch connections.

### 7.3–7.5 full defense

The controller starts NTL learning. Generate benign traffic first:

```text
mininet> hbenign1 ping -c 20 10.0.0.10
mininet> hbenign2 ping -c 20 10.0.0.11
```

Then run the attack from an attacker namespace using Phase 7.6.

### 7.6 attack examples

ICMP:

```bash
sudo python3 attacks/run_attack.py --protocol ICMP --target 10.0.0.10 --pps 300 --duration 10
```

UDP:

```bash
sudo python3 attacks/run_attack.py --protocol UDP --target 10.0.0.10 --pps 500 --duration 10
```

TCP SYN:

```bash
sudo python3 attacks/run_attack.py --protocol TCP_SYN --target 10.0.0.10 --pps 300 --duration 10
```

These commands should be executed from an attacker namespace or inside the isolated Mininet network. The scripts intentionally refuse non-private/non-lab destinations.

### 7.7 measurements

Run:

```bash
python3 experiments/phase7_experiment.py --quick
```

For the complete matrix:

```bash
python3 experiments/phase7_experiment.py --full
```

Results are written to:

```text
results/raw/phase7_measurements.csv
results/processed/phase7_mean_sd.csv
results/statistics/phase7_latency_summary.csv
results/statistics/phase7_validation.txt
```

## Important interpretation rule

Phase 7 measurements are **real testbed measurements**, but they are not automatically equivalent to production ICS measurements. The topology is a controlled Mininet emulation and the ML model was trained in Phase 1B on synthetic CIC-DDoS2019-inspired flow records. Therefore the paper must distinguish:

- real OpenFlow/Mininet control-plane measurements;
- synthetic-model training data;
- Phase-6B.3 simulated packet accounting; and
- any future experiments using the original CIC-DDoS2019 dataset.

The reference PAML-ATC paper itself identifies real-world/testbed validation and scaling as future work, while describing Ryu/Mininet as the intended environment. 
