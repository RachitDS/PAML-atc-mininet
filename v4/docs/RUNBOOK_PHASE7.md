# Phase 7 runbook

## 1. Clean environment

```bash
sudo mn -c
sudo systemctl restart openvswitch-switch
```

## 2. Start Ryu

```bash
source .venv/bin/activate
ryu-manager --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py 2>&1 | tee ryu_phase7.log
```

## 3. Start Mininet

```bash
sudo python3 mininet_lab/ics_topology.py --controller 127.0.0.1 --port 6653
```

## 4. Verify OpenFlow

```text
mininet> pingall
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s2
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s3
```

## 5. NTL learning

Run benign pings only during the first 15 seconds. Do not generate attacks during learning.

## 6. Attack

Use an attacker namespace and a private 10.0.0.0/8 destination only.

## 7. Collect

Controller snapshot:
`results/raw/controller_metrics_live.json`

Host results:
`results/raw/phase7_measurements.csv`

Do not report a Phase-7 result as measured until the Mininet run actually completes and the corresponding raw file exists.
