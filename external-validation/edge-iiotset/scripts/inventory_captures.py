"""Count capture records and replay-eligible packets before model evaluation."""
from collections import Counter
import json
from pathlib import Path
from scapy.utils import RawPcapReader
from inspect_captures import parse_packet

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('modbus-normal', 'icmp-flood', 'tcp-syn-flood', 'udp-flood')
NORMAL_PAIRS = {('192.168.7.62','192.168.7.55'), ('192.168.0.101','192.168.0.128')}
EDGE = '192.168.0.128'


def eligible(name, item):
    if not item or item[0] != 'ok':
        return False
    _, src, dst, proto, _, _, flags = item
    if name == 'modbus-normal':
        return (src,dst) in NORMAL_PAIRS
    if dst != EDGE or src == EDGE:
        return False
    if name == 'icmp-flood':
        return proto == 1 and flags == 8
    if name == 'tcp-syn-flood':
        return proto == 6 and bool(flags & 2) and not bool(flags & 16)
    if name == 'udp-flood':
        return proto == 17
    return False


def timestamp(meta, nano):
    return float(meta.sec) + float(meta.usec)/(1e9 if nano else 1e6)


def inventory(name):
    counts=Counter(); last=None; smallest=None; largest=None
    file=ROOT/'data'/'pcap'/(name+'.pcap')
    with RawPcapReader(str(file)) as reader:
        if reader.linktype != 1:
            raise ValueError(f'Expected Ethernet linktype for {name}; got {reader.linktype}')
        for pkt, meta in reader:
            counts['packets_total'] += 1
            now=timestamp(meta,reader.nano)
            if last is not None and now < last:
                counts['timestamp_regressions'] += 1
            last=now; smallest=now if smallest is None else min(smallest,now); largest=now if largest is None else max(largest,now)
            if meta.caplen < meta.wirelen:
                counts['truncated_packets'] += 1
                continue
            item=parse_packet(pkt)
            if item is None:
                counts['non_ipv4_or_other_protocol'] += 1
            elif item[0] != 'ok':
                counts[item[0]] += 1
            else:
                counts['eligible' if eligible(name,item) else 'excluded'] += 1
    return dict(name=name,counts=dict(counts),first_timestamp=smallest,last_timestamp=largest)


if __name__ == '__main__':
    (ROOT/'results').mkdir(parents=True,exist_ok=True)
    results=[]
    for name in NAMES:
        print('Inventory:',name,flush=True)
        row=inventory(name); results.append(row)
        print(json.dumps(row),flush=True)
    (ROOT/'results'/'capture_inventory.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
