"""Mininet traffic measurement helpers used by Phase 7.7."""
from __future__ import annotations

import re
import os
import shutil
import struct
import subprocess
import time
from pathlib import Path


def ping(host, target_ip: str, count: int = 10):
    start = time.perf_counter()
    out = host.cmd(f"ping -c {count} -W 1 {target_ip}")
    elapsed = time.perf_counter() - start
    sent = received = 0
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if m:
        sent, received = map(int, m.groups())
    rtt = None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    if m:
        rtt = float(m.group(1))
    return {"sent": sent, "received": received, "pdr": received / sent if sent else 0.0,
            "rtt_ms": rtt if rtt is not None else 0.0, "elapsed_s": elapsed, "raw": out}


def start_capture(host, interface: str, packet_filter: str = "ip"):
    """Capture to disk so an unread stdout pipe cannot stall tcpdump."""
    artifact_folder = Path(__file__).resolve().parents[1] / 'results/pcaps'
    folder = Path(os.getenv('PAML_CAPTURE_DIR', str(artifact_folder)))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f'{host.name}-{time.monotonic_ns()}.pcap'
    proc = host.popen(
        ['tcpdump', '-nn', '-U', '--immediate-mode', '-B', '4096', '-i', interface, '-Q', 'in', '-w', str(path), packet_filter],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    proc.capture_path = path
    proc.artifact_path = artifact_folder / path.name
    time.sleep(0.25)
    if proc.poll() is not None:
        raise RuntimeError(f'tcpdump failed: {proc.communicate()[1]}')
    return proc


def pcap_packet_count(path):
    """Count complete PCAP records and reject truncated evidence."""
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError('Missing PCAP global header')
        magic = header[:4]
        if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
            endian = '<'
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
            endian = '>'
        else:
            raise ValueError('Unsupported PCAP format')
        count = 0
        while True:
            record = stream.read(16)
            if not record:
                return count
            if len(record) != 16:
                raise ValueError('Truncated PCAP record header')
            _, _, size, _ = struct.unpack(endian + 'IIII', record)
            if len(stream.read(size)) != size:
                raise ValueError('Truncated PCAP packet')
            count += 1


def stop_capture(proc):
    proc.terminate()
    try:
        stdout, stderr = proc.communicate(timeout=2)
    except Exception:
        proc.kill()
        stdout, stderr = proc.communicate()
    drops = re.search(r'(\d+) packets dropped by kernel', stderr)
    if not drops:
        raise RuntimeError(f'Capture statistics missing: {stderr}')
    count = pcap_packet_count(proc.capture_path)
    destination = getattr(proc, 'artifact_path', proc.capture_path)
    if destination != proc.capture_path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(proc.capture_path, destination)
        proc.capture_path.unlink()
    return {'packets_seen': count,
            'kernel_drops': int(drops.group(1)), 'capture_path': str(destination),
            'raw_lines': [], 'stderr': stderr}
