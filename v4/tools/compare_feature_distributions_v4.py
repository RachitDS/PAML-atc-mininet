"""Compare V4 training and live PAML feature distributions.

Reports mean/std standardized mean difference and a two-sample KS statistic for
all 20 model inputs.  It is diagnostic evidence, not a model-performance
metric.  The live CSV may contain a ``category`` column; otherwise all live
rows are compared as an unlabeled deployment sample.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from src.v4_schema import ALL_FEATURES_V4
ROOT=Path(__file__).resolve().parents[1]

def one(a,b):
    a=np.asarray(a,dtype=float); b=np.asarray(b,dtype=float)
    a=a[np.isfinite(a)]; b=b[np.isfinite(b)]
    if len(a)<2 or len(b)<2: return {"n_train":len(a),"n_live":len(b),"smd":None,"ks":None,"p":None}
    smd=(a.mean()-b.mean())/max(1e-12,np.sqrt((a.var()+b.var())/2))
    ks,p=ks_2samp(a,b)
    return {"n_train":len(a),"n_live":len(b),"smd":float(smd),"ks":float(ks),"p":float(p)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--live",default="results/raw/live_paml_features.csv"); ap.add_argument("--out",default="results/statistics/v4_feature_drift.json"); args=ap.parse_args()
    live=Path(args.live); train=ROOT/"data/processed/paml_v4_deployment_calibration.csv"
    if not live.exists(): raise SystemExit(f"Missing {live}; run a V4 live experiment first.")
    tr=pd.read_csv(train); lv=pd.read_csv(live)
    out={"schema":ALL_FEATURES_V4,"rows":{"training":len(tr),"live":len(lv)},"overall":{},"by_category":{}}
    for f in ALL_FEATURES_V4: out["overall"][f]=one(tr[f],lv[f])
    if "category" in lv:
        tr_parts={"benign":tr[tr.label==0],"attack":tr[tr.label==1]}
        for cat,part in [("benign",lv[lv.category.str.lower()=="benign"]),("attack",lv[lv.category.str.lower()=="attack"])]:
            out["by_category"][cat]={f:one(tr_parts[cat][f],part[f]) for f in ALL_FEATURES_V4}
    out["flags"]={f:abs(v["smd"])>=1.0 if v["smd"] is not None else False for f,v in out["overall"].items()}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True); Path(args.out).write_text(json.dumps(out,indent=2));
    print(json.dumps(out,indent=2))
if __name__=="__main__": main()
