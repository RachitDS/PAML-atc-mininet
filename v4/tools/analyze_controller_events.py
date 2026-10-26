"""Summarize real Ryu controller events captured in controller_events.csv."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--input', default=str(ROOT/'results/raw/controller_events.csv'))
parser.add_argument('--output', default=str(ROOT/'results/statistics/controller_event_summary.csv'))
args=parser.parse_args()
df=pd.read_csv(args.input)
if df.empty:
    raise SystemExit('No controller events found.')
for c in ['detected','false_positive']:
    df[c]=pd.to_numeric(df[c], errors='coerce').fillna(0)
for c in ['feature_ms','inference_ms','flow_mod_ms','total_handler_ms']:
    df[c]=pd.to_numeric(df[c], errors='coerce')
summary=[]
for category, g in df.groupby('category'):
    row={'category':category,'events':len(g),'detected':int(g.detected.sum()),'false_positive':int(g.false_positive.sum())}
    for c in ['feature_ms','inference_ms','flow_mod_ms','total_handler_ms']:
        vals=g[c].dropna()
        row[c+'_mean']=float(vals.mean()) if len(vals) else 0.0
        row[c+'_p95']=float(vals.quantile(.95)) if len(vals) else 0.0
    summary.append(row)
out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
pd.DataFrame(summary).to_csv(out,index=False)
print(out)
