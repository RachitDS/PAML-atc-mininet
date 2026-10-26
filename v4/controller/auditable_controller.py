"""Single-switch IPv4 observation with independent dataplane forwarding.

The observation switch outputs packets to NORMAL and copies them to Ryu.
There is no PacketOut dependency. NONE never loads or invokes ML. MONITOR
classifies without enforcement; FIXED uses only PPS; PAML may install drops.
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controller.flow_features import OnlineFlowTable
from controller.ground_truth import GroundTruth
from controller.metrics import ControllerMetrics
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4, tcp, udp

LOG = logging.getLogger(__name__)


def select_model_directory(root):
    explicit = os.getenv("PAML_MODEL_DIR")
    if explicit:
        return Path(explicit)
    retrained = Path(root)/"models_live"
    return retrained if (retrained/"training_report.json").is_file() else Path(root)/"models"


class AuditableController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = os.getenv("PAML_MODE", "MONITOR").upper()
        if self.mode not in {"NONE", "FIXED", "MONITOR", "PAML"}:
            raise ValueError(self.mode)
        self.observation_id = int(os.getenv("PAML_OBSERVATION_DPID", "1"))
        self.protected_ips = set(os.getenv("PAML_PROTECTED_IPS", "10.0.0.10,10.0.0.11,10.0.0.12").split(','))
        self.detector = None
        if self.mode in {"MONITOR", "PAML"}:
            from src.paml_detector_v4 import PAMLDetectorV4
            model_dir = select_model_directory(ROOT)
            calibration = json.loads((model_dir / "paml_v4_threshold.json").read_text())
            self.detector = PAMLDetectorV4(model_dir,
                attack_threshold=calibration["threshold"],
                persistence=calibration.get("persistence", 1),
                window_size=calibration.get("window_size", 5))
        self.flows = OnlineFlowTable(float(os.getenv("PAML_FLOW_IDLE", "0.75")),
                                     int(os.getenv("PAML_FLOW_PACKETS", "20")))
        self.truth = GroundTruth(os.getenv("PAML_TRUTH_MANIFEST"))
        self.metrics = ControllerMetrics(lock=hub.Semaphore(1))
        self.datapaths = {}
        self.current_run = None
        self.pending = []
        self.inference_errors = 0
        self.observed_packets = 0
        self.packet_log = None
        if os.getenv("PAML_PACKET_LOG"):
            import csv
            self.packet_log = open(os.environ["PAML_PACKET_LOG"], "w", buffering=1024*1024)
            self.packet_writer = csv.writer(self.packet_log)
            self.packet_writer.writerow(["run_id", "timestamp", "src_ip", "dst_ip", "protocol",
                                        "src_port", "dst_port", "size", "syn", "fin", "rst", "ground_truth"])
        self.worker = hub.spawn(self._monitor)

    def add_rule(self, dp, priority, match, actions, hard_timeout=0):
        p, o = dp.ofproto_parser, dp.ofproto
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=priority, match=match,
            instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)],
            hard_timeout=hard_timeout))
        return time.monotonic_ns()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        p, o = dp.ofproto_parser, dp.ofproto
        self.add_rule(dp, 0, p.OFPMatch(), [p.OFPActionOutput(o.OFPP_NORMAL)])
        if dp.id == self.observation_id and self.mode != "NONE":
            self.add_rule(dp, 10, p.OFPMatch(eth_type=0x0800),
                [p.OFPActionOutput(o.OFPP_NORMAL),
                 p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])

    @staticmethod
    def stream_key(flow):
        return tuple(flow[k] for k in ("run_id", "observation_id", "src_ip", "dst_ip",
                                       "protocol", "src_port", "dst_port"))

    def process_flows(self, flows):
        if not flows or self.mode == "NONE":
            return
        batch_started = time.monotonic_ns()
        predictions = None
        if self.mode in {"MONITOR", "PAML"}:
            try:
                predictions = self.detector.predict_flows_timed(flows,
                    [self.stream_key(flow) for flow in flows])
            except Exception:
                self.inference_errors += len(flows)
                LOG.exception("Batch prediction failed")
                return
        for index, flow in enumerate(flows):
            started = batch_started
            state, probability, attack_type = "BENIGN", 0.0, "Unknown"
            feature_ms = inference_ms = 0.0
            row = None
            if self.mode == "NONE":
                continue
            if self.mode == "FIXED":
                probability = float(flow["flow_packets_per_sec"] >= float(os.getenv("FIXED_THRESHOLD_PPS", "200")))
                state = "ATTACK" if probability else "BENIGN"
            else:
                decision, feature_ms, inference_ms, row = predictions[index]
                state, probability, attack_type = decision.state, decision.attack_probability, decision.attack_type
            action, mod_ns = "FORWARD", None
            dp = self.datapaths.get(flow["observation_id"])
            if self.mode in {"PAML", "FIXED"} and state == "ATTACK" and dp is not None:
                fields = dict(eth_type=0x0800, ipv4_src=flow["src_ip"], ipv4_dst=flow["dst_ip"],
                              ip_proto={"TCP": 6, "UDP": 17, "ICMP": 1}[flow["protocol"]])
                if flow["protocol"] in {"TCP", "UDP"}:
                    prefix = flow["protocol"].lower()
                    fields.update({prefix + "_src": flow["src_port"], prefix + "_dst": flow["dst_port"]})
                mod_ns = self.add_rule(dp, 100, dp.ofproto_parser.OFPMatch(**fields), [], hard_timeout=1)
                action = "DROP"
            elapsed, mod_ms = self.metrics.add_latency(started, mod_ns)
            self.metrics.action(action)
            self.metrics.decision(dpid=flow["observation_id"], src_ip=flow["src_ip"],
                dst_ip=flow["dst_ip"], protocol=flow["protocol"], category=flow["ground_truth"],
                state=state, attack_probability=probability, attack_type=attack_type, action=action,
                feature_ms=feature_ms, inference_ms=inference_ms, flow_mod_ms=mod_ms,
                total_handler_ms=elapsed, packet_in_ns=started, flow_mod_ns=mod_ns,
                feature_row=row, flow_metadata=flow)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        if msg.datapath.id != self.observation_id or self.mode == "NONE":
            return
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if not ip or ip.proto not in {1, 6, 17}:
            return
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}[ip.proto]
        transport = pkt.get_protocol(tcp.tcp if ip.proto == 6 else udp.udp) if ip.proto in {6, 17} else None
        src_port, dst_port = (transport.src_port, transport.dst_port) if transport else (0, 0)
        bits = transport.bits if ip.proto == 6 and transport else 0
        truth, run_id = self.truth.lookup(ip.src, ip.dst, proto)
        if run_id != self.current_run:
            self.process_flows(self.pending + self.flows.expire(force=True))
            self.pending = []
            if self.detector:
                self.detector.reset()
            self.current_run = run_id
        self.observed_packets += 1
        self.metrics.packet_in(truth)
        # The experiment defines request-direction detection. Responses and
        # unrelated traffic remain unscored, rather than acquiring an IP-role label.
        if ip.dst not in self.protected_ips:
            return
        now = time.monotonic()
        if self.packet_log:
            self.packet_writer.writerow([run_id, now, ip.src, ip.dst, proto, src_port,
                dst_port, len(msg.data), int(bool(bits & 2)), int(bool(bits & 1)), int(bool(bits & 4)), truth])
        emitted = self.flows.observe(ip.src, ip.dst, proto, len(msg.data),
            bool(bits & 2), bool(bits & 1), bool(bits & 4),
            now=now,
            observation_id=msg.datapath.id, src_port=src_port, dst_port=dst_port,
            ground_truth=truth, run_id=run_id)
        self.pending.extend(emitted)

    def _monitor(self):
        while True:
            try:
                self.truth.refresh()
                pending = self.pending + self.flows.expire()
                self.pending = []
                self.process_flows(pending)
                self.metrics.sample_cpu()
                self.metrics.flush()
                if self.packet_log:
                    self.packet_log.flush()
                self.metrics.write_snapshot(dict(mode=self.mode, observation_id=self.observation_id,
                    observed_packets=self.observed_packets, inference_errors=self.inference_errors,
                    manifest_run_id=self.truth.run_id,
                    ml_loaded=self.detector is not None,
                    timestamp_semantics="controller_observation_time; decision-local latency"))
            except Exception:
                LOG.exception("Monitor failure")
            hub.sleep(0.1)
