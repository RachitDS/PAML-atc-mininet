"""Replay a fixed capture sample through the frozen retrained V4 detector."""
import argparse
from collections import Counter, defaultdict, deque
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import sys

import joblib
import numpy as np
import pandas as pd
from scapy.utils import RawPcapReader

ROOT=Path(__file__).resolve().parents[1]
PROJECT=ROOT.parents[1]
SOURCE_ROOT=Path(os.getenv('EDGE_SOURCE_ROOT',str(ROOT)))
OUTPUT_ROOT=Path(os.getenv('EDGE_OUTPUT_ROOT',str(ROOT/'results')))
sys.path.insert(0,str(PROJECT/'v4'))
from src.temporal_features_v4 import build_temporal_row
from src.v4_schema import ALL_FEATURES_V4
from fast_flow_table import FastFlowTable
from inspect_captures import parse_packet
from inventory_captures import NAMES, eligible

SEGMENTS=5
LIMIT=5000
PROTOCOL={1:'ICMP',6:'TCP',17:'UDP'}


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()


def sample_capture(name,total):
    buckets=[[] for _ in range(SEGMENTS)]
    skipped_truncated=0
    with RawPcapReader(str(SOURCE_ROOT/'data'/'pcap'/(name+'.pcap'))) as reader:
        scale=1_000_000_000 if reader.nano else 1_000_000
        if reader.linktype != 1: raise ValueError('Ethernet capture required')
        for index,(packet,meta) in enumerate(reader):
            segment=min(SEGMENTS-1,index*SEGMENTS//total)
            if len(buckets[segment]) >= LIMIT:
                continue
            if meta.caplen < meta.wirelen:
                skipped_truncated+=1; continue
            item=parse_packet(packet)
            if not eligible(name,item):
                continue
            ticks=int(meta.sec)*scale+int(meta.usec)
            buckets[segment].append((ticks,index,item,len(packet)))
    for bucket in buckets:
        bucket.sort(key=lambda row:(row[0],row[1]))
    return buckets,scale,skipped_truncated


def emit_records(name,segment,bucket,scale,writer):
    if not bucket: return dict(selected_packets=0,records=0,singletons=0)
    origin=bucket[0][0]
    run_id=f'{name}-segment-{segment+1}'
    category='benign' if name=='modbus-normal' else 'attack'
    table=FastFlowTable(idle_timeout=.75,max_packets=20)
    histories=defaultdict(lambda:deque(maxlen=5))
    totals=Counter()
    def write(flows):
        for flow in flows:
            key=tuple(flow[k] for k in ('run_id','observation_id','src_ip','dst_ip','protocol','src_port','dst_port'))
            hist=histories[key]; row=build_temporal_row(flow,hist)
            totals['records']+=1; totals['singletons']+=int(flow['packet_count']==1)
            info=dict(capture=name,segment=segment+1,category=category,flow_id=flow['flow_id'],
                src_ip=flow['src_ip'],dst_ip=flow['dst_ip'],protocol=flow['protocol'],
                src_port=flow['src_port'],dst_port=flow['dst_port'],packet_count=flow['packet_count'],
                end_reason=flow['end_reason'],history_length=len(hist))
            info.update({key:row[key] for key in ALL_FEATURES_V4}); writer.writerow(info)
    for ticks,_,item,size in bucket:
        _,src,dst,proto,sport,dport,flags=item
        syn=proto==6 and bool(flags&2); fin=proto==6 and bool(flags&1); rst=proto==6 and bool(flags&4)
        now=(ticks-origin)/scale
        write(table.observe(src,dst,PROTOCOL[proto],size,syn,fin,rst,now,
             src_port=sport,dst_port=dport,ground_truth=category,run_id=run_id))
    write(table.expire(force=True))
    return dict(selected_packets=len(bucket),records=totals['records'],singletons=totals['singletons'],
                capture_duration_seconds=(bucket[-1][0]-origin)/scale)


def score(truth,pred):
    truth=np.asarray(truth,dtype=bool); pred=np.asarray(pred,dtype=bool)
    tp=int(np.sum(truth&pred)); fn=int(np.sum(truth&~pred)); fp=int(np.sum(~truth&pred)); tn=int(np.sum(~truth&~pred))
    divide=lambda a,b:float(a/b) if b else None
    recall=divide(tp,tp+fn); specificity=divide(tn,tn+fp)
    return dict(records=len(truth),tn=tn,fp=fp,fn=fn,tp=tp,
        accuracy=divide(tp+tn,len(truth)),precision=divide(tp,tp+fp),recall=recall,
        false_positive_rate=divide(fp,fp+tn),f1=divide(2*tp,2*tp+fp+fn),
        balanced_accuracy=(recall+specificity)/2 if recall is not None and specificity is not None else None)


def models():
    saved={}
    for name,folder in [('retrained_v4','models_live')]:
        base=PROJECT/'v4'/folder
        files=['paml_v4_binary_rf.joblib','paml_v4_scaler.joblib','paml_v4_threshold.json','paml_v4_features.txt']
        hashes={f:sha256(base/f) for f in files}
        if name=='retrained_v4':
            expected=json.loads((base/'training_report.json').read_text())['frozen_artifact_sha256']
            assert all(hashes[f]==expected[f] for f in files),'Retrained model hash mismatch'
        config=json.loads((base/'paml_v4_threshold.json').read_text())
        if config['persistence']!=1 or config['window_size']!=5:
            raise ValueError('Frozen configuration differs from the registered replay')
        if (base/'paml_v4_features.txt').read_text().splitlines()!=ALL_FEATURES_V4:
            raise ValueError('Model feature order mismatch')
        forest=joblib.load(base/files[0]); forest.set_params(n_jobs=1)
        saved[name]=dict(forest=forest,scaler=joblib.load(base/files[1]),threshold=config['threshold'],hashes=hashes)
    return saved


def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',default='replay-v1'); args=p.parse_args()
    if Path(args.output).name!=args.output: raise ValueError('Output must be a directory name')
    out=OUTPUT_ROOT/args.output
    out.mkdir(parents=True,exist_ok=False)
    source=json.loads((ROOT/'data'/'source_manifest.json').read_text())
    for item in source['files']:
        capture_path=SOURCE_ROOT.joinpath(*PureWindowsPath(item['local_capture']).parts)
        if sha256(capture_path)!=item['capture_sha256']:
            raise ValueError('Downloaded capture hash mismatch: '+item['name'])
    inventory={r['name']:r for r in json.loads((ROOT/'evidence'/'capture_inventory.json').read_text())}
    model_data=models()
    cols=['capture','segment','category','flow_id','src_ip','dst_ip','protocol','src_port','dst_port',
          'packet_count','end_reason','history_length']+ALL_FEATURES_V4
    selection={}
    feature_path=out/'features.csv.gz'
    with gzip.open(feature_path,'wt',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=cols);writer.writeheader()
        for name in NAMES:
            print('Selecting and replaying',name,flush=True)
            buckets,scale,truncated=sample_capture(name,inventory[name]['counts']['packets_total'])
            segment_reports=[]
            for i,bucket in enumerate(buckets):
                segment_reports.append(emit_records(name,i,bucket,scale,writer))
                print(name,'segment',i+1,segment_reports[-1],flush=True)
            selection[name]=dict(segments=segment_reports,truncated_skipped=truncated)
    data=pd.read_csv(feature_path)
    if data.flow_id.duplicated().any(): raise ValueError('Duplicate record id')
    if set(data.category)!={'benign','attack'}: raise ValueError('Both labels required')
    x=data[ALL_FEATURES_V4].to_numpy(dtype=float)
    if not np.isfinite(x).all(): raise ValueError('Non-finite model feature')
    truth=data.category.eq('attack').to_numpy()
    output=dict(dataset='Edge-IIoTset',scope='fixed sample, offline PCAP replay; label policy is provisional',
        plan_sha256=sha256(ROOT/'evaluation_plan.original.json'),selected=selection,
        records=int(len(data)),singletons=int(data.packet_count.eq(1).sum()),models={})
    pred_output=data[['capture','segment','category','flow_id','packet_count']].copy()
    for name,m in model_data.items():
        print('Scoring',name,len(data),'records',flush=True)
        probs=m['forest'].predict_proba(m['scaler'].transform(x))[:,list(m['forest'].classes_).index(1)]
        pred=probs>=m['threshold']; pred_output[name+'_probability']=probs;pred_output[name+'_attack']=pred
        groups={}
        for capture in NAMES:
            mask=data.capture.eq(capture).to_numpy()
            groups[capture]=score(truth[mask],pred[mask])
        strata={}
        for label,mask in [('singleton',data.packet_count.eq(1).to_numpy()),('multiple_packets',data.packet_count.gt(1).to_numpy())]:
            strata[label]=score(truth[mask],pred[mask])
        output['models'][name]=dict(threshold=m['threshold'],model_sha256=m['hashes'],
             overall=score(truth,pred),by_capture=groups,by_flow_size=strata)
    pred_output.to_csv(out/'predictions.csv.gz',index=False,compression='gzip')
    output['source_manifest_sha256']=sha256(ROOT/'data'/'source_manifest.json')
    output['feature_file_sha256']=sha256(feature_path)
    output['prediction_file_sha256']=sha256(out/'predictions.csv.gz')
    (out/'metrics.json').write_text(json.dumps(output,indent=2),encoding='utf-8')
    print(json.dumps(output,indent=2),flush=True)


if __name__=='__main__':main()
