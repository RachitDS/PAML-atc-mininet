"""Inspect packet headers before deciding which flows can be labelled."""
import argparse
from collections import Counter
import json
from pathlib import Path
import socket
import struct
from scapy.utils import RawPcapReader

ROOT = Path(__file__).resolve().parents[1]


def parse_packet(packet):
    if len(packet) < 14:
        return None
    offset = 14
    ether = struct.unpack_from('!H', packet, 12)[0]
    while ether in (0x8100, 0x88a8):
        if len(packet) < offset + 4:
            return None
        ether = struct.unpack_from('!H', packet, offset + 2)[0]
        offset += 4
    if ether != 0x0800 or len(packet) < offset + 20:
        return None
    version_ihl = packet[offset]
    if version_ihl >> 4 != 4:
        return None
    header_len = (version_ihl & 15) * 4
    if header_len < 20 or len(packet) < offset + header_len:
        return None
    proto = packet[offset + 9]
    if proto not in (1, 6, 17):
        return None
    fragment = struct.unpack_from('!H', packet, offset + 6)[0] & 0x1fff
    src = socket.inet_ntoa(packet[offset + 12:offset + 16])
    dst = socket.inet_ntoa(packet[offset + 16:offset + 20])
    l4 = offset + header_len
    if fragment:
        return ('fragment', src, dst, proto, None, None, None)
    if proto in (6, 17):
        if len(packet) < l4 + (20 if proto == 6 else 8):
            return ('truncated', src, dst, proto, None, None, None)
        sport, dport = struct.unpack_from('!HH', packet, l4)
        flags = packet[l4 + 13] if proto == 6 else None
    else:
        sport = dport = 0
        flags = packet[l4] if len(packet) > l4 else None
    return ('ok', src, dst, proto, sport, dport, flags)


def inspect(path, limit):
    counts = Counter(); pairs = Counter(); sources = Counter(); destinations = Counter(); flags = Counter()
    timestamps = []; actual = 0
    with RawPcapReader(str(path)) as reader:
        for packet, metadata in reader:
            actual += 1
            if actual > limit:
                break
            if hasattr(metadata, 'sec'):
                timestamps.append(float(metadata.sec) + float(metadata.usec) / 1e6)
            item = parse_packet(packet)
            if item is None:
                counts['non_matching'] += 1
                continue
            status, src, dst, proto, sport, dport, fl = item
            counts[status] += 1
            counts['proto_' + str(proto)] += 1
            sources[src] += 1; destinations[dst] += 1
            pairs[(src, dst, proto)] += 1
            flags[(proto, fl)] += 1
    return dict(file=path.name, sampled_packets=min(actual,limit), sample_limit=limit,
        time_start=min(timestamps) if timestamps else None,
        time_end=max(timestamps) if timestamps else None,
        counts=dict(counts), top_sources=sources.most_common(15),
        top_destinations=destinations.most_common(15),
        top_pairs=[{'source': k[0], 'destination': k[1], 'protocol': k[2], 'count': v} for k,v in pairs.most_common(20)],
        top_flags=[{'protocol': k[0], 'flags_or_icmp_type': k[1], 'count': v} for k,v in flags.most_common(12)])


if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('names', nargs='+'); p.add_argument('--limit',type=int,default=200000)
    args=p.parse_args(); out=ROOT/'results'/'inspection'; out.mkdir(parents=True,exist_ok=True)
    for name in args.names:
        report=inspect(ROOT/'data'/'pcap'/(name+'.pcap'),args.limit)
        (out/(name+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2),flush=True)
