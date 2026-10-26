"""Summarize frozen held-out results and fresh live evidence."""
import csv
import hashlib
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(BASE/'v4'))
from train_live import score
from src.v4_schema import ALL_FEATURES_V4


def main():
    training=json.loads((BASE/'v4/models_live/training_report.json').read_text())
    collection=json.loads((BASE/'collection-audited/audit.json').read_text())
    recoveries=json.loads((BASE/'collection-audited/feature_recovery.json').read_text())
    rows=[]; per_seed=[]; per_protocol=[]; audits={}
    for mode in ['MONITOR','NONE','FIXED','PAML']:
        folder=BASE/f'validation-{mode}'
        audit=json.loads((folder/'audit.json').read_text());audits[mode]=audit
        events=pd.read_csv(folder/'raw/controller_events.csv')
        eligible=events[events.evaluation_eligible==1].copy()
        if len(eligible) and eligible.flow_id.duplicated().any():
            raise ValueError('Duplicate scored identity')
        m=audit['metrics']
        row=dict(mode=mode,scenarios=audit['scenarios'],decisions=len(eligible),
            observations=audit['observations'],observation_coverage=audit['observation_coverage'],
            feature_replay_errors=audit['feature_replay_errors'],ml_loaded=m['ml_loaded'],
            inference_errors=m['inference_errors'],cpu_percent_mean=m['cpu_percent_mean'],
            inference_ms_amortized=float(eligible.inference_ms.mean()) if len(eligible) else None,
            decision_to_flowmod_ms=m['packet_in_to_flow_mod_ms_mean'])
        if len(eligible):
            row.update(score((eligible.ground_truth=='attack').astype(int),(eligible.state=='ATTACK').astype(int)))
            eligible['seed']=eligible.run_id.str.extract(r'^seed(\d+)').astype(int)
            for seed,part in eligible.groupby('seed'):
                per_seed.append(dict(mode=mode,seed=int(seed),**score((part.ground_truth=='attack').astype(int),(part.state=='ATTACK').astype(int))))
            for protocol,part in eligible.groupby('protocol'):
                per_protocol.append(dict(mode=mode,protocol=protocol,**score((part.ground_truth=='attack').astype(int),(part.state=='ATTACK').astype(int))))
        for label in ['benign','attack']:
            streams=[s for s in audit['streams'] if s['label']==label]
            offered=sum(s['offered'] for s in streams);received=sum(s['received'] for s in streams)
            row[label+'_offered']=offered;row[label+'_received']=received
            row[label+'_delivery']=received/offered if offered else None
        if mode in {'NONE','FIXED'} and m['ml_loaded']:
            raise ValueError('Baseline unexpectedly loaded ML')
        if mode=='MONITOR' and (audit['observation_coverage']!=1 or not audit['all_packet_lengths_match']):
            raise ValueError('Incomplete independent monitor observations')
        if audit['feature_replay_errors'] or m['inference_errors']:
            raise ValueError('Invalid feature or inference evidence')
        rows.append(row)
    pd.DataFrame(rows).to_csv(BASE/'live_comparison.csv',index=False)
    pd.DataFrame(per_seed).to_csv(BASE/'live_per_seed.csv',index=False)
    pd.DataFrame(per_protocol).to_csv(BASE/'live_per_protocol.csv',index=False)
    # Compare detectors on the SAME unmitigated fresh observations. Enforcing
    # modes censor subsequent traffic and are primarily network-policy tests.
    fresh=pd.read_csv(BASE/'validation-MONITOR/raw/live_paml_features.csv')
    fresh=fresh[fresh.category.isin(['benign','attack'])].copy()
    old_scaler=joblib.load(BASE/'v4/models/paml_v4_scaler.joblib')
    old_model=joblib.load(BASE/'v4/models/paml_v4_binary_rf.joblib');old_model.set_params(n_jobs=1)
    old_config=json.loads((BASE/'v4/models/paml_v4_threshold.json').read_text())
    assert old_config.get('persistence',1)==1
    old_prediction=old_model.predict_proba(old_scaler.transform(fresh[ALL_FEATURES_V4].to_numpy()))[:,list(old_model.classes_).index(1)]>=old_config['threshold']
    y=(fresh.category=='attack').astype(int)
    paired_fresh={
        'previous_v4':score(y,old_prediction),
        'retrained_v4':score(y,(fresh.state=='ATTACK').astype(int)),
        'fixed_200pps':score(y,(fresh.flow_packets_per_sec>=200).astype(int))}
    paired_rows=[]
    fresh['seed']=fresh.run_id.str.extract(r'^seed(\d+)').astype(int)
    for seed,part in fresh.groupby('seed'):
        indexes=fresh.index.get_indexer(part.index)
        for name,prediction in [('previous_v4',old_prediction[indexes]),
                                ('retrained_v4',(part.state=='ATTACK').astype(int)),
                                ('fixed_200pps',(part.flow_packets_per_sec>=200).astype(int))]:
            paired_rows.append(dict(seed=int(seed),detector=name,**score((part.category=='attack').astype(int),prediction)))
    pd.DataFrame(paired_rows).to_csv(BASE/'paired_fresh_per_seed.csv',index=False)
    stats={}
    for mode in ['MONITOR','FIXED','PAML']:
        part=[r for r in per_seed if r['mode']==mode]
        rng=np.random.default_rng(20261026)
        stats[mode]={}
        for metric in ['accuracy','balanced_accuracy','f1','fpr','recall']:
            values=np.array([r[metric] for r in part])
            bootstrap=np.mean(rng.choice(values,size=(10000,len(values)),replace=True),axis=1)
            stats[mode][metric]=dict(mean=float(values.mean()),sd=float(values.std(ddof=1)),
                seed_bootstrap_95_percent_interval=list(map(float,np.quantile(bootstrap,[.025,.975]))))
    summary=dict(training=training,collection={k:v for k,v in collection.items() if k not in {'streams','metrics'}},
        recovered_feature_rows=len(recoveries),live=rows,paired_fresh_detectors=paired_fresh,seed_statistics=stats,
        validation_plan_sha256=hashlib.sha256((BASE/'validation_plan.json').read_bytes()).hexdigest())
    (BASE/'RESULTS.json').write_text(json.dumps(summary,indent=2))
    def pct(v):return f'{v*100:.2f}%'
    old=training['test']['previous_model'];new=training['test']['retrained_model']
    monitor=next(r for r in rows if r['mode']=='MONITOR')
    text=['# Accuracy roadmap results — 26 October 2026','',
        f'On the same {paired_fresh["retrained_v4"]["decisions"]:,} fresh live request-flow records, the existing V4 model scored {pct(paired_fresh["previous_v4"]["accuracy"])} accuracy and the retrained V4 model scored {pct(paired_fresh["retrained_v4"]["accuracy"])}: an improvement of {(paired_fresh["retrained_v4"]["accuracy"]-paired_fresh["previous_v4"]["accuracy"])*100:.2f} percentage points. False-positive rate fell from {pct(paired_fresh["previous_v4"]["fpr"])} to {pct(paired_fresh["retrained_v4"]["fpr"])}. Attack recall changed from {pct(paired_fresh["previous_v4"]["recall"])} to {pct(paired_fresh["retrained_v4"]["recall"])}.',
        '',
        f'The frozen retrained model achieved {pct(new["accuracy"])} accuracy and {pct(new["f1"])} F1 on the registered held-out lab-flow records. The previous model scored {pct(old["accuracy"])} and {pct(old["f1"])} on those identical records.',
        f'Fresh live MONITOR evaluation achieved {pct(monitor["accuracy"])} accuracy, {pct(monitor["balanced_accuracy"])} balanced accuracy, {pct(monitor["f1"])} F1, and {pct(monitor["fpr"])} false-positive rate across ten new seeds.',
        '', 'The previous model is the existing V4 synthetic-trained model built on Ahalya’s work, not Ahalya’s original standalone model. The retrained model retains the V4 architecture and learns from measured generated Mininet traffic.',
        '', 'These results concern generated ICMP, UDP, and raw TCP SYN request streams inside Mininet. They are not public-dataset or real industrial-application accuracy. The old 37.84% trace used different collection, attribution, and scoring rules and is not a paired model comparison.',
        '', '## Held-out comparison', '', '| Model | Accuracy | Balanced accuracy | F1 | Recall | FPR |', '|---|---:|---:|---:|---:|---:|']
    for label,m in [('Existing V4, synthetic-trained',old),('V4 retrained on measured Mininet traffic',new)]:
        text.append('| '+label+' | '+' | '.join(pct(m[k]) for k in ['accuracy','balanced_accuracy','f1','recall','fpr'])+' |')
    text += ['', '## Paired detectors on the fresh monitoring trace','',
        'All three detectors below receive identical measured feature vectors. No detector changes the traffic in this comparison.',
        '', '| Detector | Accuracy | Balanced accuracy | F1 | Recall | FPR |', '|---|---:|---:|---:|---:|---:|']
    for label,key in [('Previous V4','previous_v4'),('Retrained V4','retrained_v4'),('Fixed 200 PPS','fixed_200pps')]:
        text.append('| '+label+' | '+' | '.join(pct(paired_fresh[key][k]) for k in ['accuracy','balanced_accuracy','f1','recall','fpr'])+' |')
    text += ['', '## Fresh live runs','', '| Mode | Decisions | Accuracy | F1 | Benign delivery | Attack delivery | ML loaded |','|---|---:|---:|---:|---:|---:|---|']
    for r in rows:
        text.append(f'| {r["mode"]} | {r["decisions"]} | {pct(r["accuracy"]) if "accuracy" in r else "N/A"} | {pct(r["f1"]) if "f1" in r else "N/A"} | {pct(r["benign_delivery"])} | {pct(r["attack_delivery"])} | {r["ml_loaded"]} |')
    text += ['', 'MONITOR is the unbiased detector benchmark. Enforcing PAML and FIXED change which packets remain observable, so their mode-specific decision accuracy is conditional on observed traffic. Compare delivery results against NONE before attributing loss to defense. FIXED is a PPS-only policy. All paths forward independently of classifier execution.',
        '', '## Reproducibility and measurement', '',
        f'- Audited collection: {collection["scenarios"]} scenarios, {collection["observations"]:,} observed requests, {collection["replayed_flows"]:,} feature rows, zero replay differences.',
        f'- {len(recoveries)} damaged/missing feature-log rows were reconstructed from intact packet observations and separately logged flow identities. `collection-audited/feature_recovery.json` identifies every recovered row; all other measured feature rows were checked against replay. Fresh validation logs use native WSL storage and serialized writes.',
        '- Training seeds: 11,22,33,44,55,66; validation: 77,88; final held-out test: 99,111. Complete runs remain in one partition. The scaler and models fit only training data. Validation selects the model and threshold. Frozen hashes precede test scoring.',
        '- Fresh seeds: 121,132,143,154,165,176,187,198,209,220. Profiles: 150 PPS × 1 attacker, 500 PPS × 3 attackers, 1000 PPS × 3 attackers. Each stream runs three seconds. Captures remain open until queues drain.',
        '- One observation switch; directional identities include ports; ground truth comes from an experiment manifest. Responses and unrelated traffic are unscored. Unknown requests still receive predictions but do not enter confusion matrices.',
        '- Classifier histories and persistence are independent per run and transport stream. Every emitted labeled flow has a unique ID and is scored once, including idle expirations.',
        '- PCAPs at the observation point and PLC distinguish observation coverage from delivery. Capture drops, packet counts and packet-length histograms are audited. Observation-time feature replay verifies exact pipeline consistency.',
        '- Controller feature times are processing/observation times, not hardware wire timestamps. Inference timings are amortized across a batch. Decision-local FlowMod submission timing excludes batch waiting and switch acknowledgement.',
        '- `live_per_seed.csv` and `RESULTS.json` report variation across seeds and bootstrap intervals. Flow records within a run are correlated; they are not treated as independent experiments.',
        '', '## Implementation', '',
        '- Corrected flow attribution, unique IDs, switch/port identity and expiry handling.',
        '- Cached independent ground truth, buffered logging, atomic snapshots and controller readiness checks.',
        '- OpenFlow NORMAL forwarding, single-switch observation, clean NONE/FIXED paths and non-enforcing MONITOR.',
        '- Batch RF inference with a sequential-equivalence regression test; serial tree prediction avoids the previous Eventlet/joblib deadlock.',
        '- Zero-origin IAT handling now uses packet counts, preserving valid timestamp zero in both directions; regression checks cover clock-origin invariance. Measured run timestamps were positive, so this correction does not change the archived live feature values.',
        '- The completed retrained model is the default for new controller/campaign launches; PAML_MODEL_DIR preserves an explicit model override. The registered validation already selected the retrained model explicitly.',
        '- Seeded traffic generation with overlapping packet-size distributions across labels and explicit sender-buffer error counts.',
        '- Fixed train/validation/test partitions and validation-only selection; prior models and supplied sources remain preserved.',
        '', '## Remaining research validation','',
        '- Expand legitimate traffic to application transactions and unseen traffic generators. Current legitimate streams include low-rate and burst traffic, but do not model full ICS workloads.',
        '- Run the full publication matrix of 30/60/90% attackers and 300/500/1000/2000 PPS across ten seeds and longer attacks. This first pass covers the registered smaller live matrix.',
        '- Add external-dataset evaluation with compatible feature definitions; evaluate HTTP and Slowloris separately.',
        '- Validate adaptive rate control, MTD address changes and deception end to end. This stage uses classifier-driven one-second drop rules; it makes no claims for those other mechanisms.',
        '', '## Files','',
        '- `v4/models_live/training_report.json`: model selection, frozen hashes, held-out and per-protocol results.',
        '- `collection-audited/`: training collection, PCAP references, packet observations and audit.',
        '- `validation-{MODE}/`: fresh per-mode logs, metrics, captures and audits.',
        '- `live_comparison.csv`, `live_per_seed.csv`, `RESULTS.json`: final comparisons.',
        '- `v4/README_ROADMAP.md`, `validation_plan.json`, `run_campaign.sh`, `run_validation.sh`: reproducible workflow.',
        '']
    (BASE/'ROADMAP_RESULTS.md').write_text('\n'.join(text))
    print(pd.DataFrame(rows)[['mode','decisions','benign_delivery','attack_delivery']].to_string(index=False))
    print('Wrote ROADMAP_RESULTS.md and RESULTS.json')


if __name__=='__main__':main()
