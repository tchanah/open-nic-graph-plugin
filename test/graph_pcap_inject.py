#!/usr/bin/env python3
"""Replay an Ethernet-encapsulated pcap for the graph-plugin functional test.

Unlike graph_inject.py (which generates synthetic packets), this replays a real
trace previously prepared by pcap_prep.py. On the loopback rig the packets leave
CMAC port0, return on CMAC port1 RX, and the plugin extracts one record per IPv4
packet. Run as root (raw L2 send).

  sudo ./graph_pcap_inject.py -i ens4f0 -f slice.pcap
"""

import argparse
import sys

from scapy.all import rdpcap, sendp


def main():
    ap = argparse.ArgumentParser(description="Replay an encapsulated pcap")
    ap.add_argument("-i", "--iface", required=True, help="egress interface")
    ap.add_argument("-f", "--pcap", required=True, help="encapsulated Ethernet pcap")
    ap.add_argument("--interval", type=float, default=0.0,
                    help="inter-packet gap in seconds (default 0)")
    args = ap.parse_args()

    pkts = rdpcap(args.pcap)        # slice is small (prepared by pcap_prep.py)
    print("Replaying %d packets from %s on %s ..."
          % (len(pkts), args.pcap, args.iface))
    sendp(pkts, iface=args.iface, inter=args.interval, verbose=False)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
