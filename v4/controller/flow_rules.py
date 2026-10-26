"""OpenFlow 1.3 rule helpers."""
from __future__ import annotations


def ipv4_match(datapath, src_ip=None, dst_ip=None, ip_proto=None):
    parser = datapath.ofproto_parser
    fields = {"eth_type": 0x0800}
    if src_ip: fields["ipv4_src"] = src_ip
    if dst_ip: fields["ipv4_dst"] = dst_ip
    if ip_proto is not None: fields["ip_proto"] = ip_proto
    return parser.OFPMatch(**fields)
