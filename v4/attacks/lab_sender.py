"""Seeded private-testbed traffic used for both labeled legitimate and attack runs."""
import argparse
import errno
import json
import random
import socket
import struct
import time
from run_attack import validate_target, _checksum


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--protocol", choices=["ICMP", "UDP", "TCP"], required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--pps", type=float, required=True)
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--jitter", type=float, default=.1)
    p.add_argument("--port", type=int, default=10001)
    a = p.parse_args()
    validate_target(a.target)
    rng = random.Random(a.seed)
    proto = {"ICMP": 1, "TCP": 6, "UDP": 17}[a.protocol]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == 17 else socket.SOCK_RAW, proto)
    if proto == 17:
        sock.bind((a.source, a.port))
    start = time.monotonic()
    deadline, sent, send_errors = start, 0, 0
    while time.monotonic() - start < a.duration:
        # Identical payload distribution for both classes avoids a size shortcut.
        payload = bytes(rng.randrange(256) for _ in range(rng.choice([48, 80, 128])))
        if proto == 1:
            header = struct.pack("!BBHHH", 8, 0, 0, a.port, sent % 65536)
            data = struct.pack("!BBHHH", 8, 0, _checksum(header + payload), a.port, sent % 65536) + payload
        elif proto == 6:
            header = struct.pack("!HHIIBBHHH", a.port, 9000, sent, 0, 5 << 4, 2, 8192, 0, 0)
            pseudo = socket.inet_aton(a.source) + socket.inet_aton(a.target) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
            checksum = _checksum(pseudo + header + payload)
            data = struct.pack("!HHIIBBHHH", a.port, 9000, sent, 0, 5 << 4, 2, 8192, checksum, 0) + payload
        else:
            data = payload
        try:
            sock.sendto(data, (a.target, 9000 if proto == 17 else 0))
            sent += 1
        except OSError as exc:
            if exc.errno not in {errno.ENOBUFS, errno.EAGAIN}:
                raise
            send_errors += 1
        deadline += rng.uniform(1-a.jitter, 1+a.jitter) / a.pps
        time.sleep(max(0, deadline - time.monotonic()))
    print(json.dumps(dict(sent=sent, send_errors=send_errors, elapsed=time.monotonic()-start, protocol=a.protocol,
                          source=a.source, src_port=a.port, target=a.target)))


if __name__ == "__main__":
    main()
