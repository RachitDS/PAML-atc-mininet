"""Download four original Edge-IIoTset captures, preserving source provenance."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://www.kaggle.com/api/v1/datasets/download/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot/'
FILES = [
    ('modbus-normal', 'Edge-IIoTset dataset/Normal traffic/Modbus/Modbus.pcap', 21040950),
    ('icmp-flood', 'Edge-IIoTset dataset/Attack traffic/DDoS ICMP Flood Attacks.pcap', 212434878),
    ('tcp-syn-flood', 'Edge-IIoTset dataset/Attack traffic/DDoS TCP SYN Flood Attacks.pcap', 282613890),
    ('udp-flood', 'Edge-IIoTset dataset/Attack traffic/DDoS UDP Flood Attacks.pcap', 247560012),
]


def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()


def get_capture(spec):
    slug, remote, expected = spec
    archive = ROOT / 'data' / 'archives' / (slug + '.zip')
    capture = ROOT / 'data' / 'pcap' / (slug + '.pcap')
    temp = archive.with_suffix('.part')
    if not archive.exists():
        if temp.exists():
            raise RuntimeError(f'Partial file exists: {temp}; inspect it before retrying')
        url = BASE + urllib.parse.quote(remote, safe='')
        start = time.monotonic()
        with urllib.request.urlopen(url, timeout=120) as response, temp.open('xb') as out:
            if response.headers.get_content_type() != 'application/zip':
                raise RuntimeError(f'Unexpected download format for {slug}')
            size = 0
            previous = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                out.write(block)
                size += len(block)
                if size - previous >= 50 * 1024 * 1024:
                    print(f'{slug}: downloaded {size // (1024 * 1024)} MiB', flush=True)
                    previous = size
        os.replace(temp, archive)
        print(f'{slug}: archive downloaded in {time.monotonic()-start:.1f}s', flush=True)
    with zipfile.ZipFile(archive) as z:
        files = [item for item in z.infolist() if not item.is_dir()]
        if len(files) != 1 or Path(files[0].filename).name != Path(remote).name:
            raise RuntimeError(f'Unexpected archive entries for {slug}')
        if files[0].file_size != expected:
            raise RuntimeError(f'Unexpected capture size for {slug}: {files[0].file_size} != {expected}')
        if not capture.exists():
            partial_capture = capture.with_suffix('.part')
            with z.open(files[0]) as source, partial_capture.open('xb') as dest:
                shutil.copyfileobj(source, dest, 1024 * 1024)
            os.replace(partial_capture, capture)
    if capture.stat().st_size != expected:
        raise RuntimeError(f'Existing capture size mismatch for {slug}')
    print(f'{slug}: ready ({expected / 1e6:.1f} MB)', flush=True)
    return dict(name=slug, source_file=remote, capture_bytes=expected,
                archive_sha256=digest(archive), capture_sha256=digest(capture),
                local_capture=str(capture.relative_to(ROOT)))


if __name__ == '__main__':
    for directory in ('archives','pcap'):
        (ROOT/'data'/directory).mkdir(parents=True,exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        records = list(executor.map(get_capture, FILES))
    manifest = dict(dataset='Edge-IIoTset', version='Kaggle version 5',
        owner='Mohamed Amine Ferrag', source='https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot',
        research_paper='https://doi.org/10.1109/ACCESS.2022.3165809',
        dataset_listing_license='CC BY-NC-SA 4.0', files=records)
    (ROOT / 'data' / 'download_manifest.local.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('Local download manifest written. The recorded source manifest remains unchanged.', flush=True)
