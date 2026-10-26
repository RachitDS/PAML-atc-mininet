"""Read actual Open vSwitch port/flow counters from a Mininet host OS."""
from __future__ import annotations

import re
import subprocess


def dump_ports(switch: str):
    p = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports", switch],
                       text=True, capture_output=True, check=False)
    return p.stdout


def parse_port_packets(text: str):
    rows = []
    current = None
    for line in text.splitlines():
        m = re.search(r"port (\d+):", line)
        if m:
            current = int(m.group(1))
        m = re.search(r"rx pkts=(\d+), bytes=(\d+), errors=(\d+), dropped=(\d+)", line)
        if m and current is not None:
            rows.append({"port": current, "rx_packets": int(m.group(1)), "rx_bytes": int(m.group(2)),
                         "rx_errors": int(m.group(3)), "rx_dropped": int(m.group(4))})
        m = re.search(r"tx pkts=(\d+), bytes=(\d+), errors=(\d+), dropped=(\d+)", line)
        if m and current is not None:
            rows[-1].update({"tx_packets": int(m.group(1)), "tx_bytes": int(m.group(2)),
                             "tx_errors": int(m.group(3)), "tx_dropped": int(m.group(4))})
    return rows
