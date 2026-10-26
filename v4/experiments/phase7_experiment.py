"""One-command real Mininet/Ryu experiment driver for Phase 7.1 FINAL."""
from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet_lab.ics_topology import ICSTopo
from tools.traffic_probe import ping, start_capture, stop_capture

RAW = ROOT / "results/raw/phase7_measurements.csv"
MEAN = ROOT / "results/processed/phase7_mean_sd.csv"
LAT = ROOT / "results/statistics/phase7_latency_summary.csv"
VAL = ROOT / "results/statistics/phase7_validation.txt"


def run_attack_async(node, protocol, target, pps, duration):
    script = ROOT / "attacks/run_attack.py"
    return node.popen(
        ["python3", str(script), "--protocol", protocol, "--target", target,
         "--pps", str(pps), "--duration", str(duration)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def start_net(controller_ip, controller_port):
    net = Mininet(
        topo=ICSTopo(), controller=None, switch=OVSSwitch,
        autoSetMacs=False, autoStaticArp=True,
    )
    net.addController("c0", controller=RemoteController, ip=controller_ip, port=controller_port)
    net.start()
    for sw in net.switches:
        sw.cmd(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13")
    # Give Ryu enough time to receive all three switch-features messages.
    time.sleep(3.0)
    return net


def _attack_filter(protocol):
    return {
        "ICMP": "icmp",
        "UDP": "udp",
        "TCP_SYN": "tcp and tcp[tcpflags] & tcp-syn != 0",
    }[protocol]


def _parse_sent(outputs):
    total = 0
    for text in outputs:
        m = re.search(r"sent_packets=(\d+)", text)
        if m:
            total += int(m.group(1))
            continue
        m = re.search(r"(\d+) packets transmitted", text)
        if m:
            total += int(m.group(1))
            continue
        m = re.search(r"(\d+) packets sent", text)
        if m:
            total += int(m.group(1))
    return total


def _run_benign_probe(node, target, count=30):
    # 10 packets/s is enough to provide real PDR/RTT evidence without
    # dominating the attack experiment.
    return node.popen(
        ["ping", "-c", str(count), "-i", "0.1", "-W", "1", target],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def ntl_learning(net, ntl_period):
    info("*** Waiting for Ryu switch connections...\n")
    time.sleep(2.0)
    info("*** NTL: benign-only warm-up traffic\n")
    pairs = [("benign1", "10.0.0.10"), ("benign2", "10.0.0.11"), ("benign3", "10.0.0.12")]
    for host, target in pairs:
        result = ping(net.get(host), target, count=8)
        info(f"    {host} -> {target}: {result['received']}/{result['sent']} replies\n")
    info(f"*** Keeping NTL learning open for {ntl_period:.1f}s...\n")
    # Traffic was sent at the beginning of the window; keep the full window
    # intact so that NTL closes deterministically before attack traffic starts.
    time.sleep(max(0.0, ntl_period + 1.0))


def one_scenario(net, protocol, pps, seed, bot_ratio, duration):
    benign = net.get("benign1")
    plc = net.get("plc1")
    attacker_count = max(1, round(10 * bot_ratio))
    attackers = [net.get(f"attacker{i}") for i in range(1, attacker_count + 1)]

    baseline = ping(benign, "10.0.0.10", count=5)
    source_filter = ' or '.join(f'src host {node.IP()}' for node in attackers)
    capture_filter = f'({_attack_filter(protocol)}) and dst host 10.0.0.10 and ({source_filter})'
    capture = start_capture(plc, plc.intfList()[0].name, capture_filter)
    benign_proc = _run_benign_probe(benign, "10.0.0.10", count=max(20, int(duration * 10)))
    # Separate non-NTL benign traffic gives the live PAML evaluator genuine
    # benign decision events (TN/FP) without contaminating the protected PLC
    # NTL path.
    benign_paml_proc = _run_benign_probe(benign, "10.0.0.22", count=max(20, int(duration * 10)))
    start = time.perf_counter()
    procs = [run_attack_async(node, protocol, "10.0.0.10", pps, duration) for node in attackers]

    outputs = []
    for proc in procs:
        out, err = proc.communicate()
        outputs.append((out or "") + " " + (err or ""))
    elapsed = time.perf_counter() - start

    benign_out = benign_proc.communicate(timeout=max(10, duration + 10))[0]
    benign_paml_proc.communicate(timeout=max(10, duration + 10))
    time.sleep(0.5)
    cap = stop_capture(capture)

    # Parse the concurrent benign ping directly; fall back to the helper only
    # if ping produced no usable summary.
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", benign_out)
    if m:
        benign_sent, benign_received = map(int, m.groups())
        benign_pdr = benign_received / benign_sent if benign_sent else 0.0
        rtt_match = re.search(r"=\s*[\d.]+/([\d.]+)/", benign_out)
        benign_rtt = float(rtt_match.group(1)) if rtt_match else 0.0
    else:
        post = ping(benign, "10.0.0.10", count=5)
        benign_sent, benign_received = post["sent"], post["received"]
        benign_pdr, benign_rtt = post["pdr"], post["rtt_ms"]

    offered = _parse_sent(outputs)
    delivered = int(cap["packets_seen"])
    if cap['kernel_drops'] or delivered > offered or offered == 0:
        raise RuntimeError(f'Invalid attack packet evidence: offered={offered}, delivered={delivered}, kernel_drops={cap["kernel_drops"]}')
    attack_pdr = delivered / offered if offered else 0.0

    return {
        "seed": seed, "scenario": "PAML_ATC_REAL", "protocol": protocol,
        "mode": os.getenv("PAML_MODE", "PAML"), "bot_ratio": bot_ratio,
        "attacker_count": attacker_count, "per_attacker_pps": pps,
        "aggregate_target_pps": attacker_count * pps, "duration_s": elapsed,
        "baseline_benign_pdr": baseline["pdr"], "benign_offered_packets": benign_sent,
        "benign_delivered_packets": benign_received, "benign_pdr": benign_pdr,
        "benign_rtt_ms": benign_rtt, "attack_offered_packets": offered,
        "attack_delivered_packets": delivered, "attack_pdr": attack_pdr,
        "capture_kernel_drops": cap['kernel_drops'], "capture_file": cap['capture_path'],
        "attack_block_rate": 1.0 - attack_pdr if offered else 0.0,
        "attack_command_output": " || ".join(outputs)[:1500],
    }


def write_results(rows):
    RAW.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({k for r in rows for k in r})
    with RAW.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)

    import pandas as pd
    df = pd.DataFrame(rows)
    numeric = [c for c in [
        "benign_pdr", "benign_rtt_ms", "attack_pdr", "attack_block_rate",
        "duration_s", "benign_offered_packets", "benign_delivered_packets",
        "attack_offered_packets", "attack_delivered_packets",
    ] if c in df.columns]
    if numeric:
        df.groupby(["scenario", "protocol", "mode"])[numeric].agg(["mean", "std"]).to_csv(MEAN)

    live = ROOT / "results/raw/controller_metrics_live.json"
    live_data = {}
    if live.exists():
        import json
        live_data = json.loads(live.read_text(encoding="utf-8"))
    pd.DataFrame([{
        k: live_data.get(k, 0.0) for k in [
            "feature_extraction_ms_mean", "feature_extraction_ms_p95",
            "inference_ms_mean", "inference_ms_p95",
            "packet_in_to_flow_mod_ms_mean", "packet_in_to_flow_mod_ms_p95",
            "cpu_percent_mean", "cpu_percent_p95",
        ]
    }]).to_csv(LAT, index=False)

    VAL.write_text(
        "REAL TESTBED VALIDATION\n"
        f"Rows written: {len(rows)}\n"
        "Benign PDR: explicit ping transmitted/received counters during attack.\n"
        "Attack PDR: explicit offered packet counts from attack process + tcpdump packet capture at PLC.\n"
        "RTT: Linux ping output from a Mininet benign host.\n"
        "Controller latency: perf_counter_ns around real Ryu Packet-In handling.\n"
        "No network metric is reconstructed from a percentage field.\n",
        encoding="utf-8",
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--controller", default="127.0.0.1")
    p.add_argument("--port", type=int, default=6653)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--duration", type=float, default=5.0)
    p.add_argument("--mode", choices=["PAML", "FIXED", "NONE"], default="PAML")
    args = p.parse_args()
    setLogLevel("info")
    os.environ["PAML_MODE"] = args.mode

    protocols = ["ICMP", "UDP"] if args.quick else ["ICMP", "UDP", "TCP_SYN"]
    pps_values = [300] if args.quick else [300, 500, 1000, 2000]
    bot_ratios = [0.3] if args.quick else [0.3, 0.6, 0.9]
    seeds = [11] if args.quick else [11, 22, 33, 44, 55, 66, 77, 88, 99, 111]

    for path in [RAW, MEAN, LAT, VAL]:
        if path.exists(): path.unlink()

    ntl_period = float(os.getenv("PAML_NTL_PERIOD", "30"))
    net = start_net(args.controller, args.port)
    rows = []
    try:
        ntl_learning(net, ntl_period)
        for seed in seeds:
            for proto in protocols:
                for bot_ratio in bot_ratios:
                    for pps in pps_values:
                        info(f"*** {args.mode} {proto} bots={bot_ratio:.0%} {pps} PPS seed={seed}\n")
                        rows.append(one_scenario(net, proto, pps, seed, bot_ratio, args.duration))
    finally:
        net.stop()

    write_results(rows)
    print(f"Saved: {RAW}")
    print(f"Saved: {MEAN}")
    print(f"Saved: {LAT}")
    print(f"Saved: {VAL}")


if __name__ == "__main__":
    main()
