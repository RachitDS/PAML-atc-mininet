"""Validate request accounting, identity, and deterministic feature replay."""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
import numpy as np
import joblib
from scapy.all import PcapReader, IP, TCP, UDP

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE/'v4'))
from controller.flow_features import OnlineFlowTable
from src.temporal_features_v4 import build_temporal_row
from src.v4_schema import ALL_FEATURES_V4


def audit(folder, partial=False, model_directory=None):
    folder = Path(folder)
    scenarios = json.loads((folder/'scenarios.json').read_text())
    runtime_file=folder/'runtime_path.txt'
    runtime=Path(runtime_file.read_text().strip()) if partial and runtime_file.exists() else None
    packet_log=runtime/'packet_observations.csv' if runtime else folder/'packet_observations.csv'
    observations = list(csv.DictReader(packet_log.open()))
    run_ids = {r['run_id'] for r in scenarios}
    observations = [r for r in observations if r['run_id'] in run_ids]
    observations_by_stream = defaultdict(list)
    for record in observations:
        observations_by_stream[(record['run_id'], record['src_ip'])].append(record)
    raw = runtime/'raw' if runtime else folder/'raw'
    counts = Counter((r['run_id'], r['src_ip']) for r in observations)
    packets = defaultdict(list)
    rows = []
    for scenario_index, scenario in enumerate(scenarios, 1):
        received = Counter()
        destination_capture=Path(scenario['capture']['capture_path'])
        if not destination_capture.is_absolute():destination_capture=BASE/destination_capture
        with PcapReader(str(destination_capture)) as reader:
            for pkt in reader:
                if IP in pkt and pkt[IP].dst == '10.0.0.10':
                    received[pkt[IP].src] += 1
        observation_capture=Path(scenario.get('observation_capture', scenario['capture'])['capture_path'])
        if not observation_capture.is_absolute():observation_capture=BASE/observation_capture
        with PcapReader(str(observation_capture)) as reader:
            for pkt in reader:
                if IP in pkt and pkt[IP].dst == '10.0.0.10':
                    packets[(scenario['run_id'], pkt[IP].src)].append((float(pkt.time), len(bytes(pkt))))
        for sender in scenario['senders']:
            key = scenario['run_id'], sender['source']
            seen = counts[key]
            wire = packets[key]
            assert 0 <= received[key[1]] <= len(wire) <= sender['sent'], (
                f'Invalid request accounting for {key}: delivered={received[key[1]]}, '
                f'at_observation={len(wire)}, offered={sender["sent"]}')
            recorded = observations_by_stream[key]
            length_match = Counter(int(r['size']) for r in recorded) == Counter(size for _, size in wire)
            observed_span = float(recorded[-1]['timestamp'])-float(recorded[0]['timestamp']) if len(recorded)>1 else None
            wire_span = wire[-1][0]-wire[0][0] if len(wire)>1 else None
            rows.append(dict(run_id=key[0], source=key[1], label=sender['ground_truth'],
                offered=sender['sent'], received=received[key[1]], observed=seen,
                wire_at_observation=len(wire),
                length_histogram_match=length_match,
                span_relative_error=(observed_span-wire_span)/wire_span if observed_span and wire_span else None))
        if scenario_index % 15 == 0:
            print(f'Packet audit {scenario_index}/{len(scenarios)} scenarios', flush=True)
    metrics = json.loads((raw/'controller_metrics_live.json').read_text())
    features_path = raw/'live_paml_features.csv'
    replay_errors = []
    replayed = []
    model_probability_checks = 0
    if observations:
        table = OnlineFlowTable(idle_timeout=.75, max_packets=20)
        histories = defaultdict(lambda: deque(maxlen=5))
        run_id = None
        for rec in observations:
            if rec['run_id'] != run_id:
                replayed.extend(table.expire(force=True))
                run_id = rec['run_id']
            replayed.extend(table.observe(rec['src_ip'], rec['dst_ip'], rec['protocol'], int(rec['size']),
                bool(int(rec['syn'])), bool(int(rec['fin'])), bool(int(rec['rst'])),
                now=float(rec['timestamp']), src_port=int(rec['src_port']), dst_port=int(rec['dst_port']),
                ground_truth=rec['ground_truth'], run_id=run_id))
        replayed.extend(table.expire(force=True))
        expected = {}
        def identity(rec):
            return (rec['run_id'], rec['src_ip'], rec['dst_ip'], rec['protocol'],
                    int(rec['src_port']), int(rec['dst_port']), round(float(rec['first_ts']), 8))
        for flow in replayed:
            key = tuple(flow[k] for k in ('run_id','observation_id','src_ip','dst_ip','protocol','src_port','dst_port'))
            expected[identity(flow)] = build_temporal_row(flow, histories[key])
        actual_path = features_path if features_path.exists() else raw/'controller_events.csv'
        actual = [r for r in csv.DictReader(actual_path.open()) if r['run_id'] in run_ids]
        assert len({r['flow_id'] for r in actual}) == len(actual), 'Duplicate scored flow IDs'
        assert len(actual) == len(expected), f'Missing scored flows: actual={len(actual)} expected={len(expected)}'
        for rec in actual:
            flow = expected[identity(rec)]
            assert rec['category'] == flow['ground_truth']
            assert rec['src_ip'] == flow['src_ip'] and rec['protocol'] == flow['protocol']
            assert int(rec['packet_count']) == flow['packet_count']
            if metrics['mode'] == 'FIXED':
                assert (rec['state']=='ATTACK') == (flow['flow_packets_per_sec']>=200)
            for feature in ALL_FEATURES_V4 if features_path.exists() else []:
                if not np.isclose(float(rec[feature]), flow[feature], rtol=1e-8, atol=1e-5):
                    replay_errors.append(dict(flow_id=rec['flow_id'], feature=feature,
                        logged=float(rec[feature]), replay=flow[feature]))
        assert not replay_errors, replay_errors[:3]
        assert metrics['inference_errors'] == 0
        if features_path.exists():
            configuration=folder/'run_configuration.json'
            if model_directory:
                model_dir=Path(model_directory)
            elif configuration.exists():
                model_dir=Path(json.loads(configuration.read_text())['model_directory'])
                if not model_dir.is_absolute():model_dir=BASE/model_dir
            else:
                model_dir = BASE/'v4'/('models_live' if folder.name.startswith('validation-') else 'models')
            rf = joblib.load(model_dir/'paml_v4_binary_rf.joblib'); rf.set_params(n_jobs=1)
            scaler = joblib.load(model_dir/'paml_v4_scaler.joblib')
            threshold = json.loads((model_dir/'paml_v4_threshold.json').read_text())['threshold']
            online = [r for r in actual if r.get('feature_origin', 'online') == 'online']
            x = np.asarray([[float(r[k]) for k in ALL_FEATURES_V4] for r in online])
            probabilities = rf.predict_proba(scaler.transform(x))[:,list(rf.classes_).index(1)]
            for record, probability in zip(online, probabilities):
                assert np.isclose(float(record['attack_probability']), probability, rtol=1e-9, atol=1e-10)
                assert (record['state']=='ATTACK') == (probability >= threshold)
            model_probability_checks = len(online)
    total_offered = sum(r['offered'] for r in rows)
    total_received = sum(r['received'] for r in rows)
    total_observed = sum(r['observed'] for r in rows)
    observation_wire = sum(r['wire_at_observation'] for r in rows)
    result = dict(mode=metrics['mode'], offered=total_offered, received=total_received,
        observations=total_observed, delivery=total_received/total_offered,
        observation_coverage=total_observed/observation_wire if observation_wire else None,
        observation_wire_packets=observation_wire,
        replayed_flows=len(replayed), feature_replay_errors=len(replay_errors),
        frozen_model_probability_checks=model_probability_checks,
        all_packet_lengths_match=all(r['length_histogram_match'] for r in rows),
        scenarios=len(scenarios), metrics=metrics, streams=rows)
    (folder/('audit-progress.json' if partial else 'audit.json')).write_text(json.dumps(result, indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in {'streams','metrics'}}, indent=2))
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('folder')
    parser.add_argument('--partial',action='store_true')
    parser.add_argument('--model-dir')
    arguments=parser.parse_args()
    audit(arguments.folder,arguments.partial,arguments.model_dir)
