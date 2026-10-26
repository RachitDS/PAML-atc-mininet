from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
summary=pd.read_csv(ROOT/'results/processed/phase6b3_mean_sd.csv')
PLOT=ROOT/'plots'; PLOT.mkdir(exist_ok=True)
order=['A1_StaticThreshold','A2_PAML','A3_PAML_ATC','A4_FULL']
summary['ord']=summary.configuration.map({x:i for i,x in enumerate(order)})
summary=summary.sort_values('ord')

def bar(metric,label,filename):
    y=summary[metric].to_numpy(float); e=summary.get(metric.replace('_mean','_std'),pd.Series(np.zeros(len(summary)))).fillna(0).to_numpy(float)
    fig,ax=plt.subplots(figsize=(9,5)); x=np.arange(len(summary)); ax.bar(x,y,yerr=e,capsize=4)
    ax.set_xticks(x,summary.configuration,rotation=15,ha='right'); ax.set_ylabel(label); ax.set_title(f'Phase 6B.3 — {label}: Mean ± SD (10 seeds)'); ax.grid(axis='y',alpha=.25); fig.tight_layout(); fig.savefig(PLOT/filename,dpi=300); plt.close(fig)

for m,l,f in [('f1_mean','F1 Score','phase6b3_f1.png'),('fpr_mean','FPR','phase6b3_fpr.png'),('benign_pdr_mean','Benign PDR','phase6b3_benign_pdr.png'),('attack_pdr_mean','Attack PDR','phase6b3_attack_pdr.png'),('overall_pdr_mean','Overall PDR','phase6b3_overall_pdr.png'),('attack_block_rate_mean','Attack Block Rate','phase6b3_attack_block_rate.png'),('cpu_percent_mean','CPU (%)','phase6b3_cpu.png'),('rtt_ms_mean','RTT (ms)','phase6b3_rtt.png')]: bar(m,l,f)
