"""Train on measured Mininet requests with fixed, disjoint seed partitions.

Validation selects model and threshold. Test seeds are evaluated only after
the selected artifacts and configuration have been written and hashed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score, balanced_accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
from src.v4_schema import ALL_FEATURES_V4
from src.dataset import CLASSES

ROOT = Path(__file__).resolve().parent
PARTITIONS = dict(train=[11,22,33,44,55,66], validation=[77,88], test=[99,111])


def score(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0,1]).ravel()
    return dict(accuracy=float(accuracy_score(y,pred)), balanced_accuracy=float(balanced_accuracy_score(y,pred)),
        precision=float(precision_score(y,pred,zero_division=0)), recall=float(recall_score(y,pred,zero_division=0)),
        f1=float(f1_score(y,pred,zero_division=0)), fpr=float(fp/max(1,fp+tn)),
        fnr=float(fn/max(1,fn+tp)), tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp), decisions=int(len(y)))


def partition(df):
    sets = {k:df[df.seed.isin(seeds)].copy() for k,seeds in PARTITIONS.items()}
    for name, part in sets.items():
        if set(part.label) != {0,1} or set(part.protocol) != {'ICMP','UDP','TCP'}:
            raise ValueError(f'Insufficient class/protocol coverage in {name}')
    if sum(map(len, sets.values())) != len(df):
        raise ValueError('Unexpected seed outside the registered partitions')
    groups = {k:set(v.run_id) for k,v in sets.items()}
    for a in groups:
        for b in groups:
            if a != b and groups[a] & groups[b]:
                raise ValueError('Run leakage between partitions')
    return sets


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--collection', required=True)
    p.add_argument('--models', default=str(ROOT/'models_live'))
    a=p.parse_args()
    collection=Path(a.collection)
    if (Path(a.models)/'training_report.json').exists():
        raise ValueError('This registered holdout has already been evaluated; do not retune against it')
    audit=json.loads((collection/'audit.json').read_text())
    if audit['feature_replay_errors'] or audit['observation_coverage'] != 1 or not audit['all_packet_lengths_match']:
        raise ValueError('Collection evidence did not pass audit')
    source=collection/'raw/live_paml_features.csv'
    df=pd.read_csv(source)
    registered_runs = {r['run_id'] for r in json.loads((collection/'scenarios.json').read_text())}
    df=df[df.category.isin(['benign','attack']) & df.run_id.isin(registered_runs)].copy()
    if df.flow_id.duplicated().any():
        raise ValueError('Duplicate flow identity')
    df['seed']=df.run_id.str.extract(r'^seed(\d+)').astype(int)
    df['label']=(df.category=='attack').astype(int)
    df['attack_type']=np.where(df.label==0,'Benign',df.protocol.map({'ICMP':'ICMP_Flood','UDP':'UDP_Flood','TCP':'SYN_Flood'}))
    sets=partition(df); train, val, test=[sets[k] for k in ('train','validation','test')]
    scaler=StandardScaler().fit(train[ALL_FEATURES_V4].to_numpy())
    xtr=scaler.transform(train[ALL_FEATURES_V4].to_numpy())
    xv=scaler.transform(val[ALL_FEATURES_V4].to_numpy())
    candidates=[]; best=None
    for trees in [64,120]:
        for depth in [8,16,None]:
            rf=RandomForestClassifier(n_estimators=trees,max_depth=depth,min_samples_leaf=2,
                class_weight='balanced_subsample',random_state=20261026,n_jobs=-1)
            rf.fit(xtr,train.label)
            probs=rf.predict_proba(xv)[:,list(rf.classes_).index(1)]
            for threshold in np.arange(.2,.851,.025):
                m=score(val.label,(probs>=threshold).astype(int))
                objective=m['balanced_accuracy']-.5*max(0,m['fpr']-.05)
                config=dict(trees=trees,depth=depth,threshold=float(threshold),objective=objective,validation=m)
                candidates.append(config)
                if best is None or (objective,-trees)>(best[0],-best[1]['trees']):
                    best=(objective,config,rf)
    _,config,rf=best
    out=Path(a.models);out.mkdir(exist_ok=True,parents=True)
    rf.set_params(n_jobs=1)
    multi=RandomForestClassifier(n_estimators=config['trees'],max_depth=config['depth'],min_samples_leaf=2,
        class_weight='balanced_subsample',random_state=20261027,n_jobs=-1)
    mapping={c:i for i,c in enumerate(CLASSES)}
    multi.fit(xtr,train.attack_type.map(mapping));multi.set_params(n_jobs=1)
    joblib.dump(rf,out/'paml_v4_binary_rf.joblib'); joblib.dump(multi,out/'paml_v4_multiclass_rf.joblib')
    joblib.dump(scaler,out/'paml_v4_scaler.joblib')
    (out/'paml_v4_features.txt').write_text('\n'.join(ALL_FEATURES_V4)+'\n')
    (out/'paml_v4_class_mapping.json').write_text(json.dumps(mapping,indent=2))
    (out/'paml_v4_threshold.json').write_text(json.dumps(dict(threshold=config['threshold'],persistence=1,
        window_size=5,selection='Fixed train/validation seed groups; balanced accuracy with FPR penalty'),indent=2))
    frozen_hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in out.iterdir() if f.is_file()}
    # Final test is first accessed for scoring below, after freezing artifacts.
    report=dict(data_type='Measured generated Mininet lab traffic; request direction only',
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),partitions=PARTITIONS,
        selected=config, frozen_artifact_sha256=frozen_hashes, candidate_count=len(candidates),
        rows={k:len(v) for k,v in sets.items()},coverage='ICMP, UDP and raw TCP SYN; no HTTP/Slowloris or external dataset')
    report['feature_importance'] = dict(sorted(zip(ALL_FEATURES_V4, map(float,rf.feature_importances_)), key=lambda item:-item[1]))
    original_scaler=joblib.load(ROOT/'models/paml_v4_scaler.joblib')
    original_rf=joblib.load(ROOT/'models/paml_v4_binary_rf.joblib');original_rf.set_params(n_jobs=1)
    original_threshold=json.loads((ROOT/'models/paml_v4_threshold.json').read_text())['threshold']
    for name, data in [('validation',val),('test',test)]:
        new=rf.predict_proba(scaler.transform(data[ALL_FEATURES_V4].to_numpy()))[:,list(rf.classes_).index(1)]>=config['threshold']
        old=original_rf.predict_proba(original_scaler.transform(data[ALL_FEATURES_V4].to_numpy()))[:,list(original_rf.classes_).index(1)]>=original_threshold
        report[name]=dict(previous_model=score(data.label,old),retrained_model=score(data.label,new),
            by_protocol={proto:score(data.loc[data.protocol==proto,'label'],new[data.protocol==proto]) for proto in ['ICMP','UDP','TCP']})
    pred=multi.predict(scaler.transform(test[ALL_FEATURES_V4].to_numpy()))
    report['multiclass_test']=dict(accuracy=float(accuracy_score(test.attack_type.map(mapping),pred)),
        macro_f1=float(f1_score(test.attack_type.map(mapping),pred,average='macro')))
    test_predictions=test[['flow_id','run_id','seed','protocol','category','label']].copy()
    test_predictions['prediction']=new.astype(int)
    test_predictions.to_csv(out/'heldout_predictions.csv',index=False)
    (out/'training_report.json').write_text(json.dumps(report,indent=2))
    (out/'validation_candidates.json').write_text(json.dumps(candidates,indent=2))
    for name,part in sets.items():
        part.to_csv(out/f'{name}_dataset.csv',index=False)
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
