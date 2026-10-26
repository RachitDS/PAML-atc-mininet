import struct
import pytest
from tools.traffic_probe import pcap_packet_count


@pytest.mark.parametrize('endian', ['<', '>'])
def test_complete_and_empty_captures(tmp_path, endian):
    path = tmp_path / 'evidence.pcap'
    header = struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header)
    assert pcap_packet_count(path) == 0
    packet = b'network packet'
    record = struct.pack(endian + 'IIII', 1, 0, len(packet), len(packet)) + packet
    path.write_bytes(header + record * 2000)
    assert pcap_packet_count(path) == 2000


def test_truncated_capture_is_rejected(tmp_path):
    path = tmp_path / 'broken.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                     + struct.pack('<IIII', 1, 0, 100, 100) + b'partial')
    with pytest.raises(ValueError, match='Truncated PCAP packet'):
        pcap_packet_count(path)
