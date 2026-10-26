"""V4 controller evidence collection with auditable monotonic latency."""
from __future__ import annotations
import csv,json,os,threading,time
from dataclasses import dataclass,asdict
from pathlib import Path
import psutil
from src.v4_schema import ALL_FEATURES_V4

@dataclass
class PacketCounters:
    packet_in_events:int=0; benign_packet_in:int=0; attack_packet_in:int=0
    forwarded:int=0; rate_limited:int=0; dropped:int=0; redirected:int=0
    detected_attacks:int=0; false_positive:int=0; true_positive:int=0
    true_negative:int=0; false_negative:int=0; paml_decisions:int=0
    suspicious_decisions:int=0; attack_decisions:int=0; ntl_bypass_events:int=0
    ntl_learned_flows:int=0
    unknown_packet_in:int=0

class ControllerMetrics:
    HEADER=["timestamp","dpid","src_ip","dst_ip","protocol","category","ground_truth","state","attack_probability","attack_type","action","evaluation_eligible","detected","feature_ms","inference_ms","flow_mod_ms","total_handler_ms","ntl_bypass","packet_in_ns","flow_mod_ns"]
    FLOW_FIELDS = ["flow_id", "run_id", "src_port", "dst_port", "packet_count", "byte_count", "first_ts", "last_ts", "end_reason", "observation_id"]
    def __init__(self,reset=True,lock=None):
        self.start=time.monotonic(); self.counters=PacketCounters(); self.latency=[]; self.cpu_samples=[]; self.latency_invalid_count=0
        self.mtd_rotations=0; self.decoy_redirects=0; self.attack_captured=0; self._lock=lock or threading.RLock()
        self.root=Path(__file__).resolve().parents[1]; raw=Path(os.getenv("PAML_RAW_DIR", str(self.root/"results/raw"))); raw.mkdir(parents=True,exist_ok=True)
        self.events_path=raw/"controller_events.csv"; self.live_path=raw/"controller_metrics_live.json"; self.feature_log_path=raw/"live_paml_features.csv"
        self.ntl_period=float(os.getenv("PAML_NTL_PERIOD","30"))
        self.buffer_logs = os.getenv("PAML_BUFFER_LOGS") == "1"
        self._streams = {}
        if reset or not self.events_path.exists():
            with self.events_path.open("w",newline="",encoding="utf-8") as f: csv.writer(f).writerow(self.HEADER + self.FLOW_FIELDS)
        self.process=psutil.Process(os.getpid()); self._last_cpu_wall=time.monotonic(); self._last_cpu_time=sum(self.process.cpu_times()[:2])
    def packet_in(self,category):
        with self._lock:
            self.counters.packet_in_events+=1
            field = {"attack":"attack_packet_in", "benign":"benign_packet_in"}.get(category, "unknown_packet_in")
            setattr(self.counters,field,getattr(self.counters,field)+1)
    def action(self,action):
        action=str(action).upper()
        with self._lock:
            if action=="DROP": self.counters.dropped+=1
            elif action=="RATE_LIMIT": self.counters.rate_limited+=1
            elif action=="REDIRECT": self.counters.redirected+=1
            else: self.counters.forwarded+=1
    def ntl_learned(self,count=1): self.counters.ntl_learned_flows+=int(count)
    def ntl_bypass(self): self.counters.ntl_bypass_events+=1
    def _write_event(self,row):
        row = row + [""] * (len(self.HEADER) + len(self.FLOW_FIELDS) - len(row))
        if self.buffer_logs:
            csv.writer(self._stream(self.events_path)).writerow(row)
            return
        with self.events_path.open("a",newline="",encoding="utf-8") as f: csv.writer(f).writerow(row)
    def _stream(self, path):
        if path not in self._streams:
            self._streams[path] = path.open("a", newline="", encoding="utf-8", buffering=1024*1024)
        return self._streams[path]
    def flush(self):
        with self._lock:
            for stream in self._streams.values(): stream.flush()
    def decision(self,*,dpid,src_ip,dst_ip,protocol,category,state,attack_probability,attack_type,action,feature_ms,inference_ms,flow_mod_ms,total_handler_ms,ntl_bypass=False,packet_in_ns=None,flow_mod_ns=None,feature_row=None,flow_metadata=None):
        detected=state=="ATTACK"; eligible=not ntl_bypass and category in {"attack", "benign"}
        flow_metadata = flow_metadata or {}
        with self._lock:
            if eligible:
                self.counters.paml_decisions+=1
                if state=="SUSPICIOUS": self.counters.suspicious_decisions+=1
                if state=="ATTACK": self.counters.attack_decisions+=1
                if category=="attack" and detected: self.counters.true_positive+=1; self.counters.detected_attacks+=1
                elif category=="attack": self.counters.false_negative+=1
                elif category=="benign" and detected: self.counters.false_positive+=1
                else: self.counters.true_negative+=1
            self._write_event([f"{time.time():.6f}",dpid,src_ip,dst_ip,protocol,category,category,state,f"{float(attack_probability):.6f}",attack_type,action,int(eligible),int(detected),f"{float(feature_ms):.6f}",f"{float(inference_ms):.6f}","" if flow_mod_ms is None else f"{float(flow_mod_ms):.6f}",f"{float(total_handler_ms):.6f}",int(ntl_bypass),"" if packet_in_ns is None else int(packet_in_ns),"" if flow_mod_ns is None else int(flow_mod_ns)] + [flow_metadata.get(k, "") for k in self.FLOW_FIELDS])
            if feature_row is not None:
                f = self._stream(self.feature_log_path) if self.buffer_logs else self.feature_log_path.open("a",newline="",encoding="utf-8")
                if f.tell()==0: csv.writer(f).writerow(["timestamp_ns","src_ip","dst_ip","protocol","category","state","attack_probability",*ALL_FEATURES_V4,*self.FLOW_FIELDS])
                csv.writer(f).writerow([time.monotonic_ns(),src_ip,dst_ip,protocol,category,state,float(attack_probability),*[float(feature_row[k]) for k in ALL_FEATURES_V4],*[flow_metadata.get(k, "") for k in self.FLOW_FIELDS]])
                if not self.buffer_logs: f.close()
    def record_event(self,*,dpid,src_ip,dst_ip,protocol,category,state="NO_DECISION",action="FORWARD",feature_ms=0.0,inference_ms=0.0,flow_mod_ms=None,total_handler_ms=0.0,ntl_bypass=False,packet_in_ns=None,flow_mod_ns=None):
        with self._lock:
            self._write_event([f"{time.time():.6f}",dpid,src_ip,dst_ip,protocol,category,category,state,"","",action,0,0,f"{float(feature_ms):.6f}",f"{float(inference_ms):.6f}","" if flow_mod_ms is None else f"{float(flow_mod_ms):.6f}",f"{float(total_handler_ms):.6f}",int(ntl_bypass),"" if packet_in_ns is None else int(packet_in_ns),"" if flow_mod_ns is None else int(flow_mod_ns)])
    def add_latency(self,packet_in_ns,flow_mod_ns=None):
        now= time.monotonic_ns(); packet=int(packet_in_ns); fm=None if flow_mod_ns is None else int(flow_mod_ns)
        total=(now-packet)/1e6; flow=None if fm is None else (fm-packet)/1e6
        # Controller-local submission latency should be milliseconds, not seconds.
        valid=0.0<=total<=60000.0 and (flow is None or 0.0<=flow<=total+100.0)
        with self._lock:
            if valid: self.latency.append((total,flow))
            else: self.latency_invalid_count+=1
        return total,flow
    def sample_cpu(self):
        now=time.monotonic(); cpu=sum(self.process.cpu_times()[:2]); wall=max(now-self._last_cpu_wall,1e-6); pct=100*(cpu-self._last_cpu_time)/wall/max(psutil.cpu_count() or 1,1)
        with self._lock: self.cpu_samples.append(max(0.0,pct))
        self._last_cpu_wall,self._last_cpu_time=now,cpu
    def add_mtd_rotation(self): self.mtd_rotations+=1
    def add_decoy_redirect(self,captured=True): self.decoy_redirects+=1; self.attack_captured+=int(captured)
    @staticmethod
    def mp(values):
        if not values:return (0.0,0.0)
        a=sorted(float(x) for x in values); pos=.95*(len(a)-1); lo=int(pos); hi=min(lo+1,len(a)-1); frac=pos-lo; return sum(a)/len(a),a[lo]+frac*(a[hi]-a[lo])
    def summary(self):
        with self._lock:
            c=asdict(self.counters); den=c["true_positive"]+c["true_negative"]+c["false_positive"]+c["false_negative"]; tp=c["true_positive"]; fp=c["false_positive"]; fn=c["false_negative"]; tn=c["true_negative"]
            acc=(tp+tn)/den if den else 0; prec=tp/(tp+fp) if tp+fp else 0; rec=tp/(tp+fn) if tp+fn else 0; f1=2*prec*rec/(prec+rec) if prec+rec else 0; fpr=fp/(fp+tn) if fp+tn else 0; fnr=fn/(fn+tp) if fn+tp else 0
            totals=[x[0] for x in self.latency]; flows=[x[1] for x in self.latency if x[1] is not None]; tm,tp95=self.mp(totals); fm,fp95=self.mp(flows); cm,cp95=self.mp(self.cpu_samples)
            return {**c,"accuracy":acc,"precision":prec,"recall":rec,"f1":f1,"fpr":fpr,"fnr":fnr,"cpu_percent_mean":cm,"cpu_percent_p95":cp95,"packet_in_to_flow_mod_ms_mean":fm,"packet_in_to_flow_mod_ms_p95":fp95,"handler_latency_ms_mean":tm,"handler_latency_ms_p95":tp95,"latency_samples":len(self.latency),"latency_invalid_count":self.latency_invalid_count,"mtd_rotations":self.mtd_rotations,"decoy_redirects":self.decoy_redirects,"attack_captured":self.attack_captured,"ntl_period":self.ntl_period,"duration_s":time.monotonic()-self.start}
    def write_snapshot(self,extra=None):
        s=self.summary(); s.update(extra or {}); temporary=self.live_path.with_suffix(".tmp"); temporary.write_text(json.dumps(s,indent=2)); temporary.replace(self.live_path); return s
