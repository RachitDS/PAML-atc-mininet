"""Reproduce the saved Edge-IIoTset scores using only the retrained V4 model."""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
PROJECT=ROOT.parents[1]/'v4'
DATA=ROOT/'data'/'derived'


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


def counts(y,p):
    return dict(tn=int(((~y)&(~p)).sum()),fp=int(((~y)&p).sum()),
                fn=int((y&(~p)).sum()),tp=int((y&p).sum()))


report=json.loads((ROOT/'evidence'/'metrics.json').read_text())
assert digest(DATA/'features.csv.gz')==report['feature_file_sha256']
assert digest(DATA/'predictions.csv.gz')==report['prediction_file_sha256']
assert digest(ROOT/'evaluation_plan.original.json')==report['plan_sha256']
assert digest(ROOT/'data'/'source_manifest.json')==report['source_manifest_sha256']
base=PROJECT/'models_live'
expected=json.loads((base/'training_report.json').read_text())['frozen_artifact_sha256']
for name,sha in expected.items(): assert digest(base/name)==sha,name
info=report['models']['retrained_v4']
for name,sha in info['model_sha256'].items(): assert digest(base/name)==sha,name

features=pd.read_csv(DATA/'features.csv.gz');predictions=pd.read_csv(DATA/'predictions.csv.gz')
assert len(features)==len(predictions)==report['records']
assert features.flow_id.equals(predictions.flow_id)
columns=(base/'paml_v4_features.txt').read_text().splitlines()
x=features[columns].to_numpy(dtype=float); y=features.category.eq('attack').to_numpy()
rf=joblib.load(base/'paml_v4_binary_rf.joblib');rf.set_params(n_jobs=1)
scaler=joblib.load(base/'paml_v4_scaler.joblib')
probability=rf.predict_proba(scaler.transform(x))[:,list(rf.classes_).index(1)]
np.testing.assert_allclose(probability,predictions.retrained_v4_probability,rtol=1e-12,atol=1e-12)
decision=probability>=info['threshold']
assert np.array_equal(decision,predictions.retrained_v4_attack.to_numpy(dtype=bool))
actual=counts(y,decision)
assert actual=={k:info['overall'][k] for k in actual}
for capture,expected_metrics in info['by_capture'].items():
    mask=features.capture.eq(capture).to_numpy()
    actual_group=counts(y[mask],decision[mask])
    assert actual_group=={k:expected_metrics[k] for k in actual_group}
single=features.packet_count.eq(1)
assert int(single.sum())==report['singletons']
assert features.loc[single,'flow_packets_per_sec'].eq(1000000).all()
assert features.loc[features.category.eq('attack'),'packet_count'].eq(1).all()
print(json.dumps(dict(model='retrained_v4',records=len(features),frozen_hashes_match=True,
    predictions_recomputed=True,confusion_matrix=actual,
    accuracy=info['overall']['accuracy'],balanced_accuracy=info['overall']['balanced_accuracy'],
    false_positive_rate=info['overall']['false_positive_rate'],
    singleton_records=int(single.sum()),singleton_pps_all_1000000=True),indent=2))
