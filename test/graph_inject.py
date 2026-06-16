#!/usr/bin/env python3
"""Inject N known IPv4 packets for the graph-plugin functional test.

Sends synthetic Ether/IP/UDP (or TCP) packets out the given interface. On the
loopback rig these leave CMAC port0, return on CMAC port1 RX, and the plugin
extracts a 5-tuple from each. Run as root (raw L2 send).

  sudo ./graph_inject.py -i ens4f0 -n 200
"""

import argparse
import sys

from scapy.all import sendp

import graph_common as gc


def main():
    ap = argparse.ArgumentParser(description="Inject graph-plugin test packets")
    ap.add_argument("-i", "--iface", required=True, help="egress interface")
    ap.add_argument("-n", "--count", type=int, default=200,
                    help="number of packets (default 200)")
    ap.add_argument("--l4", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--interval", type=float, default=0.0,
                    help="inter-packet gap in seconds (default 0)")
    args = ap.parse_args()

    pkts = [gc.make_packet(i, args.l4) for i in range(args.count)]
    print("Injecting %d %s packets on %s ..." % (args.count, args.l4, args.iface))
    sendp(pkts, iface=args.iface, inter=args.interval, verbose=False)
    full = args.count // gc.MAX_RECORDS
    tail = args.count % gc.MAX_RECORDS
    print("Done. Expect %d full frame(s) of %d records + a %d-record timeout tail."
          % (full, gc.MAX_RECORDS, tail))


if __name__ == "__main__":
    sys.exit(main())
