"""Heap-backed expiry for V4 flow table, preserving its feature definitions."""
import heapq
from controller.flow_features import OnlineFlowTable


class FastFlowTable(OnlineFlowTable):
    def __init__(self, idle_timeout=.75, max_packets=20):
        super().__init__(idle_timeout, max_packets)
        self.expiry_heap = []
        self.heap_serial = 0

    def observe(self, src_ip, dst_ip, protocol, size, syn=False, fin=False, rst=False,
                now=None, *, observation_id=1, src_port=0, dst_port=0,
                ground_truth='unknown', run_id='unspecified'):
        if now is None:
            raise ValueError('Capture timestamp is required')
        result = super().observe(src_ip, dst_ip, protocol, size, syn, fin, rst, now,
            observation_id=observation_id, src_port=src_port, dst_port=dst_port,
            ground_truth=ground_truth, run_id=run_id)
        key = (observation_id,src_ip,dst_ip,protocol.upper(),int(src_port),int(dst_port),ground_truth,run_id)
        if key in self.flows:
            self.heap_serial += 1
            heapq.heappush(self.expiry_heap,(float(now),self.heap_serial,key))
        return result

    def expire(self, now=None, force=False):
        if force:
            result=super().expire(now=now,force=True)
            self.expiry_heap.clear()
            return result
        if now is None:
            from time import monotonic
            now=monotonic()
        emitted=[]
        while self.expiry_heap and now - self.expiry_heap[0][0] >= self.idle_timeout:
            last, _, key = heapq.heappop(self.expiry_heap)
            if key in self.flows and self.last_seen[key] == last:
                emitted.append(self._finalize(key,'idle'))
        return emitted
