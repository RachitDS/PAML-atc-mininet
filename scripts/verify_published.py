"""Reproduce published paired detector scores without privileged network access."""
import hashlib
import json
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'v4'))
from train_live import score
from src.v4_schema import ALL_FEATURES_V4

training=json.loads((ROOT/'v4/models_live/training_report.json').read_text())
for name,digest in training['frozen_artifact_sha256'].items():
    assert hashlib.sha256((ROOT/'v4/models_live'/name).read_bytes()).hexdigest()==digest,name
data=pd.read_csv(ROOT/'validation-MONITOR/raw/live_paml_features.csv')
data=data[data.category.isin(['benign','attack'])]
assert len(data)==19431 and not data.flow_id.duplicated().any()
x=data[ALL_FEATURES_V4].to_numpy();y=(data.category=='attack').astype(int)
actual={}
for name,directory in [('previous_v4','models'),('retrained_v4','models_live')]:
    model_dir=ROOT/'v4'/directory
    rf=joblib.load(model_dir/'paml_v4_binary_rf.joblib');rf.set_params(n_jobs=1)
    scaler=joblib.load(model_dir/'paml_v4_scaler.joblib')
    threshold=json.loads((model_dir/'paml_v4_threshold.json').read_text())['threshold']
    probabilities=rf.predict_proba(scaler.transform(x))[:,list(rf.classes_).index(1)]
    prediction=probabilities>=threshold
    if name=='retrained_v4':
        np.testing.assert_allclose(probabilities,data.attack_probability.to_numpy(),rtol=1e-9,atol=1e-10)
        assert np.array_equal(prediction,(data.state=='ATTACK').to_numpy())
    actual[name]=score(y,prediction)
actual['fixed_200pps']=score(y,(data.flow_packets_per_sec>=200).astype(int))
expected=json.loads((ROOT/'RESULTS.json').read_text())['paired_fresh_detectors']
for name,result in actual.items():
    for key,value in result.items():
        assert np.isclose(value,expected[name][key],rtol=1e-12,atol=1e-12),(name,key)
print(json.dumps(dict(model_hashes_match=True,records=len(data),paired_detectors=actual),indent=2))
