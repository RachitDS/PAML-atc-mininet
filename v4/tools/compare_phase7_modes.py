"""Compare saved real Phase-7 PAML and Fixed-ATC CSVs under matched scenarios."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

p=argparse.ArgumentParser()
p.add_argument('--paml', required=True)
p.add_argument('--fixed', required=True)
p.add_argument('--output', default='results/statistics/phase7_mode_comparison.csv')
a=p.parse_args()
paml=pd.read_csv(a.paml); fixed=pd.read_csv(a.fixed)
keys=['protocol','bot_ratio','per_attacker_pps','seed']
left=paml.groupby(keys,as_index=False)[['benign_pdr','benign_rtt_ms','attack_pdr','attack_block_rate']].mean()
right=fixed.groupby(keys,as_index=False)[['benign_pdr','benign_rtt_ms','attack_pdr','attack_block_rate']].mean()
out=left.merge(right,on=keys,suffixes=('_paml','_fixed'))
out['attack_block_rate_gain']=out['attack_block_rate_paml']-out['attack_block_rate_fixed']
out['benign_pdr_change']=out['benign_pdr_paml']-out['benign_pdr_fixed']
out['rtt_change_ms']=out['benign_rtt_ms_paml']-out['benign_rtt_ms_fixed']
path=Path(a.output); path.parent.mkdir(parents=True,exist_ok=True); out.to_csv(path,index=False)
print(path)
