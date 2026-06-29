#!/usr/bin/env python3
"""Slice + Ethernet-encapsulate a raw-IP pcap for graph-plugin replay.

Real anonymized-network-sensing traces (e.g. the CAIDA-style scan datasets)
are captured as DLT_RAW: each record is a bare IPv4 datagram with no Ethernet
header. The graph plugin reads the EtherType at byte 12 and the IP header at
byte 14, and any NIC transmit needs L2 framing, so each datagram must be wrapped
in a 14-byte Ethernet header (EtherType 0x0800) before replay.

The input may be huge (tens of GB), so this reads incrementally with
RawPcapReader and stops after N packets -- it never loads the whole file. The
raw bytes are parsed as IP and wrapped, producing a normal Ethernet (DLT_EN10MB)
pcap that graph_pcap_inject.py / graph_pcap_verify.py consume.

  ./pcap_prep.py -i /scratch/data/20220102-120000.pcap -o slice.pcap -n 5000
"""

import argparse
import sys

from scapy.all import Ether, IP, RawPcapReader, wrpcap

import graph_common as gc


def main():
    ap = argparse.ArgumentParser(description="Slice + Ethernet-encapsulate a raw-IP pcap")
    ap.add_argument("-i", "--input", required=True, help="source raw-IP pcap")
    ap.add_argument("-o", "--output", required=True, help="encapsulated Ethernet pcap")
    ap.add_argument("-n", "--count", type=int, default=5000,
                    help="number of packets to take from the head (default 5000)")
    args = ap.parse_args()

    frames = []
    skipped = 0
    reader = RawPcapReader(args.input)        # incremental: does not load the file
    try:
        for data, _meta in reader:
            try:
                ip = IP(bytes(data))          # DLT_RAW payload is a bare IP datagram
            except Exception:
                skipped += 1
                continue
            frames.append(Ether(src=gc.INJ_SRC_MAC, dst=gc.INJ_DST_MAC,
                                type=0x0800) / ip)
            if len(frames) >= args.count:
                break
    finally:
        reader.close()

    if not frames:
        print("ERROR: no packets read from %s" % args.input)
        return 1
    wrpcap(args.output, frames)
    print("Wrote %d Ethernet-encapsulated packets to %s%s"
          % (len(frames), args.output,
             "" if not skipped else " (%d unparseable skipped)" % skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
