"""Reproducible collection and independent live evaluation inside Mininet."""
import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
sys.path.append('/usr/lib/python3/dist-packages')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from mininet_lab.ics_topology import ICSTopo
from tools.traffic_probe import start_capture, stop_capture


def manifest(path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--seeds', default='11')
    p.add_argument('--duration', type=float, default=3)
    p.add_argument('--profiles', default='150:1,300:3,1000:3')
    p.add_argument('--protocols', default='ICMP,UDP,TCP')
    p.add_argument('--output', required=True)
    p.add_argument('--skip-json')
    p.add_argument('--only-json')
    a = p.parse_args()
    output = Path(a.output); output.mkdir(parents=True, exist_ok=True)
    truth_path = Path(os.environ['PAML_TRUTH_MANIFEST'])
    skip = {r['run_id'] for r in json.loads(Path(a.skip_json).read_text())} if a.skip_json else set()
    only = {r['run_id'] for r in json.loads(Path(a.only_json).read_text())} if a.only_json else None
    net = Mininet(topo=ICSTopo(), controller=None, switch=OVSSwitch,
                  autoSetMacs=False, autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    records = []
    cap = None
    observation_cap = None
    jobs = []
    try:
        net.start()
        time.sleep(3)
        controller_ids = subprocess.check_output(['ovs-vsctl', '--bare', '--columns=_uuid', 'list', 'Controller'], text=True).split()
        for controller_id in controller_ids:
            subprocess.run(['ovs-vsctl', 'set', 'Controller', controller_id,
                'controller_rate_limit=100000', 'controller_burst_limit=100000'], check=True)
        for host in net.hosts:
            host.cmd('sysctl -w net.ipv4.icmp_ratelimit=0 >/dev/null')
        # Warm up OVS NORMAL MAC learning without adding any scored records.
        for host in ['benign1', 'benign2', 'benign3', 'attacker1', 'attacker2', 'attacker3']:
            net.get(host).cmd('ping -c 1 -W 1 10.0.0.10 >/dev/null')
        for seed in map(int, a.seeds.split(',')):
            for proto in a.protocols.split(','):
                for profile in a.profiles.split(','):
                    pps, count = map(int, profile.split(':'))
                    run_id = f'seed{seed}-{proto}-{pps}pps-{count}bots'
                    if run_id in skip:
                        continue
                    if only is not None and run_id not in only:
                        continue
                    flows, jobs = [], []
                    # Legitimate streams include variable timing and occasional
                    # bursts; protocol and packet sizes overlap the attack class.
                    rates = [12, 40, 90 if seed % 2 else 150]
                    specs = [(f'benign{i+1}', 'benign', rate, .8) for i, rate in enumerate(rates)]
                    specs += [(f'attacker{i+1}', 'attack', pps, .08) for i in range(count)]
                    for name, label, rate, jitter in specs:
                        flows.append(dict(src_ip=net.get(name).IP(), dst_ip='10.0.0.10',
                                          protocol=proto, ground_truth=label))
                    manifest(truth_path, dict(run_id=run_id, seed=seed, label_policy='request-direction only; replies unscored', flows=flows))
                    for _ in range(100):
                        live = Path(os.getenv('PAML_RAW_DIR', str(ROOT/'results/raw')))/'controller_metrics_live.json'
                        if live.exists() and json.loads(live.read_text()).get('manifest_run_id') == run_id:
                            break
                        time.sleep(.05)
                    else:
                        raise RuntimeError('Controller did not acknowledge experiment manifest')
                    plc = net.get('plc1')
                    cap = start_capture(plc, plc.intfList()[0].name, 'ip and dst host 10.0.0.10')
                    # Match the classifier observation before the PLC's egress
                    # queue; a second capture separately measures delivery.
                    observation_cap = start_capture(net.get('s1'), 's1-eth1', 'ip and dst host 10.0.0.10')
                    for i, (name, label, rate, jitter) in enumerate(specs):
                        host = net.get(name)
                        args = ['python3', str(ROOT/'attacks/lab_sender.py'), '--protocol', proto,
                            '--source', host.IP(), '--target', '10.0.0.10', '--pps', str(rate),
                            '--duration', str(a.duration), '--seed', str(seed*100+i),
                            '--jitter', str(jitter), '--port', str(10001+i)]
                        jobs.append((name, label, rate, host.popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)))
                    senders = []
                    for name, label, rate, proc in jobs:
                        out, err = proc.communicate(timeout=a.duration+15)
                        if proc.returncode:
                            raise RuntimeError(f'{name} failed: {err}')
                        senders.append(dict(json.loads(out), ground_truth=label, target_pps=rate))
                    # Offered load can leave HTB queues draining after senders
                    # exit. Close captures only after the observation link is quiet.
                    counter = Path('/sys/class/net/s1-eth1/statistics/rx_packets')
                    last = counter.read_text(); quiet_since = time.monotonic()
                    timeout = time.monotonic() + 15
                    while time.monotonic() < timeout:
                        time.sleep(.2)
                        current = counter.read_text()
                        if current != last:
                            last, quiet_since = current, time.monotonic()
                        if time.monotonic() - quiet_since >= 1.1:
                            break
                    else:
                        raise RuntimeError('Observation link did not drain before capture closure')
                    capture = stop_capture(cap)
                    observation_capture = stop_capture(observation_cap)
                    record = dict(run_id=run_id, seed=seed, protocol=proto, attack_pps=pps,
                        attackers=count, duration=a.duration, senders=senders, capture=capture,
                        observation_capture=observation_capture)
                    if capture['kernel_drops'] or observation_capture['kernel_drops']:
                        raise RuntimeError(f'Capture dropped packets: {record}')
                    records.append(record)
                    (output/'scenarios.json').write_text(json.dumps(records, indent=2))
                    print(f'COMPLETE {run_id} offered={sum(s["sent"] for s in senders)} received={capture["packets_seen"]}', flush=True)
                    time.sleep(.3)
        time.sleep(2)
    finally:
        for *_, proc in jobs:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
        if cap is not None and cap.poll() is None:
            stop_capture(cap)
        if observation_cap is not None and observation_cap.poll() is None:
            stop_capture(observation_cap)
        net.stop()


if __name__ == '__main__':
    setLogLevel('warning')
    main()
