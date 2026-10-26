#!/usr/bin/env python3
from ics_topology import start
import argparse

p = argparse.ArgumentParser()
p.add_argument('--controller', default='127.0.0.1')
p.add_argument('--port', type=int, default=6653)
args = p.parse_args()
start(args.controller, args.port, cli=True)
