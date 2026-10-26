# Fast Phase-7 procedure

## Terminal A — Ryu

```bash
cd PAML_ATC_V2_PHASE7
source .venv/bin/activate
export PAML_MODE=PAML
export PAML_ATTACKER_IPS="10.0.0.40,10.0.0.41,10.0.0.42,10.0.0.43,10.0.0.44,10.0.0.45,10.0.0.46,10.0.0.47,10.0.0.48,10.0.0.49"
ryu-manager --ofp-tcp-listen-port 6653 controller/ryu_paml_controller.py
```

## Terminal B — smoke test

```bash
cd PAML_ATC_V2_PHASE7
sudo python3 mininet_lab/ics_topology.py --controller 127.0.0.1 --port 6653
```

Use `pingall` and `ovs-ofctl dump-flows` in the CLI, then exit.

## Terminal B — Phase 7.7 quick experiment

```bash
python3 experiments/phase7_experiment.py --quick --mode PAML --duration 5
```

For a real Fixed-ATC comparison, stop Ryu and restart it with `PAML_MODE=FIXED`,
then repeat the same experiment. Keep the resulting CSV files separately named
so the comparison uses identical traffic conditions.

## Full experiment

The full driver uses 10 seeds, 3 botnet ratios (30/60/90%), 4 PPS values
(300/500/1000/2000), and ICMP/UDP/TCP-SYN. This is intentionally much longer
than the quick run.
