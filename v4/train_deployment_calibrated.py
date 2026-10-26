"""Train the v3 deployment-calibrated PAML model.

The generated dataset is synthetic and is calibrated to the short flow/rate
range used by the Phase-7 Mininet laboratory experiment. It is a deployment
calibration benchmark, not a substitute for original CIC-DDoS2019.
"""
from pathlib import Path
import json, sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
import joblib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from src.temporal_features import add_temporal_features, TEMPORAL_FEATURES
from src.dataset import BASE_FEATURES, CLASSES

ALL_FEATURES = BASE_FEATURES + TEMPORAL_FEATURES
PROTO = {"ICMP_Flood": 2, "SYN_Flood": 0, "UDP_Flood": 1, "HTTP_Flood": 0, "Slowloris": 0}


def make_flow(rng, label, pps, n=20):
    pps = float(max(2.0, pps * rng.lognormal(0, 0.06)))
    duration = max((n - 1) / pps, 1e-4)
    if label == "Benign":
        fl, bl, var = max(40,rng.normal(220,70)), max(40,rng.normal(180,60)), max(100,rng.normal(3500,1800))
        bf = np.clip(rng.normal(.35,.12), .05,.8); syn=max(0,rng.normal(1,.7)); fin=max(0,rng.normal(.5,.5)); rst=max(0,rng.normal(.1,.2))
    elif label == "ICMP_Flood":
        fl, bl, var = max(56,rng.normal(64,5)), max(0,rng.normal(1,1)), max(5,rng.normal(35,15)); bf=np.clip(rng.normal(.01,.01),0,.08); syn=fin=rst=0
    elif label == "SYN_Flood":
        fl, bl, var = max(40,rng.normal(60,8)), max(0,rng.normal(1,1)), max(10,rng.normal(60,25)); bf=np.clip(rng.normal(.01,.01),0,.08); syn=max(1,rng.normal(18,4)); fin=max(0,rng.normal(.05,.08)); rst=max(0,rng.normal(.2,.3))
    elif label == "UDP_Flood":
        fl, bl, var = max(100,rng.normal(900,180)), max(0,rng.normal(2,2)), max(50,rng.normal(1200,500)); bf=np.clip(rng.normal(.01,.01),0,.08); syn=fin=rst=0
    elif label == "HTTP_Flood":
        fl, bl, var = max(100,rng.normal(500,130)), max(60,rng.normal(420,110)), max(1000,rng.normal(30000,12000)); bf=np.clip(rng.normal(.45,.12),.15,.8); syn=max(0,rng.normal(1.2,.8)); fin=max(0,rng.normal(.8,.7)); rst=max(0,rng.normal(.2,.3))
    else:
        fl, bl, var = max(50,rng.normal(200,60)), max(30,rng.normal(150,50)), max(500,rng.normal(8000,3500)); bf=np.clip(rng.normal(.45,.15),.1,.8); syn=max(0,rng.normal(.8,.5)); fin=max(0,rng.normal(.05,.1)); rst=max(0,rng.normal(.05,.1))
    fwd=pps*(1-bf); bwd=pps*bf
    return {
        "flow_duration": duration*1e6, "fwd_packet_length_mean": fl, "bwd_packet_length_mean": bl,
        "flow_bytes_per_sec": pps*(fl*(1-bf)+bl*bf), "flow_packets_per_sec": pps,
        "fwd_iat_mean": 1e6/max(fwd,.1), "bwd_iat_mean": 1e6/max(bwd,.1),
        "active_mean": duration*1e6, "idle_mean": 0.0, "fwd_packets_per_sec": fwd, "bwd_packets_per_sec": bwd,
        "packet_length_variance": var, "fin_flag_count": fin, "syn_flag_count": syn, "rst_flag_count": rst,
        "protocol_encoded": PROTO.get(label, int(rng.choice([0,1,2]))), "down_up_ratio": bf/max(1-bf,.01),
    }


def generate(seed=2026, seq_per_class=180, flows_per_sequence=30):
    rng=np.random.default_rng(seed); rows=[]; sid=0
    for label in CLASSES:
        for _ in range(seq_per_class):
            hard=rng.random()<.18
            if label == "Benign": base=float(rng.uniform(8,180))
            elif label in {"ICMP_Flood","SYN_Flood","UDP_Flood"}: base=float(rng.uniform(260,2200))
            elif label == "HTTP_Flood": base=float(rng.uniform(180,1000))
            else: base=float(rng.uniform(4,40))
            for i in range(flows_per_sequence):
                trend=1+rng.normal(0,.035)+rng.normal(0,.02)*(i/max(1,flows_per_sequence-1))
                effective=label
                if hard and label=="Benign" and flows_per_sequence//3 <= i < 2*flows_per_sequence//3:
                    effective=str(rng.choice(["ICMP_Flood","SYN_Flood","UDP_Flood","HTTP_Flood"]))
                if hard and label!="Benign" and flows_per_sequence//3 <= i < 2*flows_per_sequence//3:
                    effective="Benign"
                row=make_flow(rng,effective,base*trend)
                row.update(sequence_id=sid,flow_index=i,label=int(label!="Benign"),attack_type=label,hard_case=int(hard))
                rows.append(row)
            sid+=1
    return pd.DataFrame(rows)


def main():
    df=add_temporal_features(generate())
    splitter=GroupShuffleSplit(n_splits=1,test_size=.20,random_state=2026)
    ti,vi=next(splitter.split(df,df.label,groups=df.sequence_id))
    tr,te=df.iloc[ti],df.iloc[vi]
    scaler=StandardScaler(); Xtr=scaler.fit_transform(tr[ALL_FEATURES]); Xte=scaler.transform(te[ALL_FEATURES])
    rf=RandomForestClassifier(n_estimators=180,max_depth=18,min_samples_leaf=2,max_features="sqrt",class_weight="balanced_subsample",random_state=2026,n_jobs=-1)
    rf.fit(Xtr,tr.label)
    probs=rf.predict_proba(Xte)[:,list(rf.classes_).index(1)]
    pred=(probs>=.60).astype(int)
    cm=confusion_matrix(te.label,pred,labels=[0,1]); tn,fp,fn,tp=cm.ravel()
    metrics={"accuracy":accuracy_score(te.label,pred),"precision":precision_score(te.label,pred),"recall":recall_score(te.label,pred),"f1":f1_score(te.label,pred),"fpr":fp/(fp+tn),"fnr":fn/(fn+tp),"confusion_matrix":cm.tolist()}
    mapping={c:i for i,c in enumerate(CLASSES)}
    multi=RandomForestClassifier(n_estimators=180,max_depth=18,min_samples_leaf=2,max_features="sqrt",class_weight="balanced_subsample",random_state=2027,n_jobs=-1)
    multi.fit(Xtr,tr.attack_type.map(mapping)); mp=multi.predict(Xte)
    multi_metrics={"accuracy":accuracy_score(te.attack_type.map(mapping),mp),"macro_f1":f1_score(te.attack_type.map(mapping),mp,average="macro")}
    (ROOT/"data/processed").mkdir(parents=True,exist_ok=True); (ROOT/"results/processed").mkdir(parents=True,exist_ok=True)
    df.to_csv(ROOT/"data/processed/paml_deployment_calibration_v3.csv",index=False)
    joblib.dump(rf,ROOT/"models/paml_binary_rf_phase1b.joblib"); joblib.dump(multi,ROOT/"models/paml_multiclass_rf_phase1b.joblib"); joblib.dump(scaler,ROOT/"models/paml_scaler_phase1b.joblib")
    (ROOT/"models/paml_features_phase1b.txt").write_text("\n".join(ALL_FEATURES)+"\n")
    (ROOT/"models/paml_class_mapping.json").write_text(json.dumps(mapping,indent=2))
    out={"phase":"7.1-FINAL-v3","data_type":"synthetic deployment calibration","warning":"Not original CIC-DDoS2019 and not a real-testbed score","threshold":.60,"window_size":5,"persistence":2,"binary":metrics,"multiclass":multi_metrics}
    (ROOT/"results/processed/training_metrics_phase1b_v3.json").write_text(json.dumps(out,indent=2))
    print(json.dumps(out,indent=2))

if __name__=="__main__": main()
