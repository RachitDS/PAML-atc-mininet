"""50-node-inspired compact ICS topology for Phase 7.

The reference work describes three SDN switches, critical PLC/MTU/RTU nodes,
benign industrial hosts, redundant/deception resources, and 2 Mbps links. This
implementation keeps the first real testbed small enough for a laptop while
preserving those roles. Increase host counts only after the basic pipeline
passes.
"""
from __future__ import annotations

import argparse

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class ICSTopo(Topo):
    def build(self, bandwidth_mbps=2):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")

        self.addLink(s1, s2, cls=TCLink, bw=bandwidth_mbps)
        self.addLink(s2, s3, cls=TCLink, bw=bandwidth_mbps)

        # Critical ICS-style hosts.
        for i, ip in enumerate(["10.0.0.10/24", "10.0.0.11/24", "10.0.0.12/24"], 1):
            h = self.addHost(f"plc{i}", ip=ip, mac=f"00:00:00:00:00:{i:02x}")
            self.addLink(h, s1 if i < 3 else s2, cls=TCLink, bw=bandwidth_mbps)

        for name, ip, mac in [
            ("mtu1", "10.0.0.20/24", "00:00:00:00:00:20"),
            ("rtu1", "10.0.0.21/24", "00:00:00:00:00:21"),
            ("server1", "10.0.0.22/24", "00:00:00:00:00:22"),
            ("benign1", "10.0.0.30/24", "00:00:00:00:00:30"),
            ("benign2", "10.0.0.31/24", "00:00:00:00:00:31"),
            ("benign3", "10.0.0.32/24", "00:00:00:00:00:32"),
            ("attacker1", "10.0.0.40/24", "00:00:00:00:00:40"),
            ("attacker2", "10.0.0.41/24", "00:00:00:00:00:41"),
            ("attacker3", "10.0.0.42/24", "00:00:00:00:00:42"),
            ("attacker4", "10.0.0.43/24", "00:00:00:00:00:43"),
            ("attacker5", "10.0.0.44/24", "00:00:00:00:00:44"),
            ("attacker6", "10.0.0.45/24", "00:00:00:00:00:45"),
            ("attacker7", "10.0.0.46/24", "00:00:00:00:00:46"),
            ("attacker8", "10.0.0.47/24", "00:00:00:00:00:47"),
            ("attacker9", "10.0.0.48/24", "00:00:00:00:00:48"),
            ("attacker10", "10.0.0.49/24", "00:00:00:00:00:49"),
            ("honey", "10.0.0.50/24", "00:00:00:00:00:50"),
        ]:
            h = self.addHost(name, ip=ip, mac=mac)
            sw = s3 if name.startswith(("attacker", "honey")) else s2
            self.addLink(h, sw, cls=TCLink, bw=bandwidth_mbps)


def start(controller_ip="127.0.0.1", controller_port=6653, cli=True):
    topo = ICSTopo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=False, autoStaticArp=True)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    net.start()
    for sw in net.switches:
        sw.cmd(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13")
    info("*** ICS topology started\n")
    if cli:
        CLI(net)
        net.stop()
    return net


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6653)
    args = parser.parse_args()
    setLogLevel("info")
    start(args.controller, args.port, cli=True)
