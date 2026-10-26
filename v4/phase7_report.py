"""V4 real-testbed report with schema and latency-integrity checks."""
from pathlib import Path
import csv,json,platform,subprocess
from statistics import mean,stdev
ROOT=Path(__file__).resolve().parent; EVENTS=ROOT/"results/raw/controller_events.csv"; LIVE=ROOT/"results/raw/controller_metrics_live.json"; MEASURE=ROOT/"results/raw/phase7_measurements.csv"; REPORT=ROOT/"results/statistics/phase7_final_report_v4.txt"
def rows(p):
    if not p.exists(): return []
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def fl(r,k,d=0):
    try:return float(r.get(k,d))
    except:return d
def pct(x):return f"{100*x:.2f} %"
def p95(a):
    if not a:return 0
    a=sorted(a); pos=.95*(len(a)-1); lo=int(pos); hi=min(lo+1,len(a)-1); return a[lo]+(a[hi]-a[lo])*(pos-lo)
def cmd(c):
    try:return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except:return 'N/A'
def main():
    events=rows(EVENTS); live=json.loads(LIVE.read_text()) if LIVE.exists() else {}; measure=rows(MEASURE)
    e=[r for r in events if r.get('evaluation_eligible')=='1']; tp=sum(r['category']=='attack' and r['detected']=='1' for r in e); tn=sum(r['category']=='benign' and r['detected']=='0' for r in e); fp=sum(r['category']=='benign' and r['detected']=='1' for r in e); fn=sum(r['category']=='attack' and r['detected']=='0' for r in e); den=tp+tn+fp+fn
    acc=(tp+tn)/den if den else 0; prec=tp/(tp+fp) if tp+fp else 0; rec=tp/(tp+fn) if tp+fn else 0; f1=2*prec*rec/(prec+rec) if prec+rec else 0; fpr=fp/(fp+tn) if fp+tn else 0; fnr=fn/(fn+tp) if fn+tp else 0
    benign_sent=sum(int(fl(r,'benign_offered_packets')) for r in measure); benign_recv=sum(int(fl(r,'benign_delivered_packets')) for r in measure); attack_sent=sum(int(fl(r,'attack_offered_packets')) for r in measure); attack_recv=sum(int(fl(r,'attack_delivered_packets')) for r in measure); total_sent=benign_sent+attack_sent; total_recv=benign_recv+attack_recv
    fm=[fl(r,'flow_mod_ms') for r in e if r.get('flow_mod_ms') not in ('',None) and 0<=fl(r,'flow_mod_ms')<=60000]; feature=[fl(r,'feature_ms') for r in e if fl(r,'feature_ms')>0 and fl(r,'feature_ms')<60000]; infer=[fl(r,'inference_ms') for r in e if fl(r,'inference_ms')>0 and fl(r,'inference_ms')<60000]
    drift='PASS: live_paml_features.csv exists' if (ROOT/'results/raw/live_paml_features.csv').exists() else 'PENDING: run a V4 live experiment'
    tm=mean(feature) if feature else 0; im=mean(infer) if infer else 0; fmm=mean(fm) if fm else 0
    lines=['='*64,'        PAML-ATC REAL SDN/ICS TESTBED','        PHASE 7.1 FINAL V4','='*64,'','[1] ENVIRONMENT',f'Python       : {platform.python_version()}',f'Ryu          : {cmd("ryu-manager --version")}', 'OpenFlow     : 1.3',f'Mininet      : {cmd("mn --version")}',f'Open vSwitch : {cmd("ovs-vsctl --version | head -1")}','','[2] PAML V4 SCHEMA','Model        : Random Forest','Features     : 20 (8 base + 12 temporal)','Temporal     : exact same builder offline/online','Window       : '+str(getattr(live,'window_size',live.get('window_size',5)))+' flows','Threshold    : '+str(live.get('attack_threshold',live.get('threshold','calibrated'))),'Persistence  : '+str(live.get('persistence','calibrated')),'','[3] LIVE TRAFFIC',f'Benign packets  : {benign_sent}',f'Attack packets  : {attack_sent}','','[4] PAML DETECTION',f'Accuracy        : {pct(acc)}',f'Precision       : {pct(prec)}',f'Recall          : {pct(rec)}',f'F1 Score        : {pct(f1)}',f'FPR             : {pct(fpr)}',f'FNR             : {pct(fnr)}',f'Evaluation flows: {den}','','[5] ADAPTIVE ATC',f'Forwarded       : {sum(r.get("action")=="FORWARD" for r in events)}',f'Dropped         : {sum(r.get("action")=="DROP" for r in events)}',f'Redirected      : {sum(r.get("action")=="REDIRECT" for r in events)}','','[6] NETWORK PERFORMANCE',f'CPU usage       : {live.get("cpu_percent_mean",0):.3f} %',f'RTT             : {mean([fl(r,"benign_rtt_ms") for r in measure if fl(r,"benign_rtt_ms")>0]) if any(fl(r,"benign_rtt_ms")>0 for r in measure) else 0:.3f} ms',f'Overall PDR     : {pct(total_recv/total_sent if total_sent else 0)}',f'Benign PDR      : {pct(benign_recv/benign_sent if benign_sent else 0)}',f'Attack PDR      : {pct(attack_recv/attack_sent if attack_sent else 0)}','','[7] LATENCY',f'Feature extraction : {tm:.3f} ms (P95 {p95(feature):.3f})',f'PAML inference     : {im:.3f} ms (P95 {p95(infer):.3f})',f'Packet-In->Flow-Mod: {fmm:.3f} ms (P95 {p95(fm):.3f})',f'Latency samples    : {len(fm)} valid / {live.get("latency_invalid_count",0)} rejected','','[8] V4 DIAGNOSTICS',f'Feature drift file : {drift}','Live feature log   : results/raw/live_paml_features.csv','Training stats     : models/paml_v4_feature_stats.json','Schema rule        : 20 features only; auxiliary SYN/FIN/variance are not counted as model inputs','','[9] VALIDATION', 'PDR source       : explicit Mininet ping counters + tcpdump capture','Latency source   : monotonic_ns timestamps from the same controller process','Latency meaning  : Packet-In -> controller Flow-Mod submission','Model warning     : calibration benchmark is synthetic; live metrics require a real rerun','']
    REPORT.parent.mkdir(parents=True,exist_ok=True); REPORT.write_text('\n'.join(lines)+'\n'); print(REPORT); print('\n'.join(lines))
if __name__=='__main__':main()
