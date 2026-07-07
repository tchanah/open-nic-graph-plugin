#!/usr/bin/env python3
"""Pretty-print aggregated graph-plugin frames from a pcap (or live capture).

tcpdump shows the raw bytes but can't decode our custom 0x88B5 format; this
renders the descriptor and each 5-tuple record in human-readable form.

  ./graph_dump.py -f /tmp/graph_agg.pcap            # all frames, summary
  ./graph_dump.py -f /tmp/graph_agg.pcap -v         # + every record
  ./graph_dump.py -f /tmp/graph_agg.pcap -c 1 -v    # just the first frame

Live (root): sudo ./graph_dump.py -i ens4f1 -v
"""

import argparse
import socket
import sys

import graph_common as gc

PROTO_CODE = {0x8: "TCP", 0x4: "UDP", 0x2: "ICMP", 0x1: "OTH"}
FLAG_BITS = [(0x8, "A"), (0x4, "R"), (0x2, "S"), (0x1, "F")]  # ACK RST SYN FIN


def fmt_flags(code):
    return "".join(c for bit, c in FLAG_BITS if code & bit) or "-"


def fmt_record(rec):
    d = gc.decode_record(rec)  # v3: FloatingEncoder ports, 4-bit proto/flags codes
    return "%-15s:%-5d -> %-15s:%-5d  %-4s  len=%-5d flags=%s" % (
        d["src"], d["sport"], d["dst"], d["dport"],
        PROTO_CODE.get(d["proto_code"], "0x%x" % d["proto_code"]),
        d["length"], fmt_flags(d["flags_code"]))


def show_frame(idx, raw, verbose):
    f = gc.parse_frame(raw)
    if f is None:
        return False
    partial = "partial" if (f["flags"] & 0x01) else "full"
    drops = " DROPS-SEEN" if (f["flags"] & 0x02) else ""
    bad = next((r[:8].hex() for r in f["records"] if r[:8] != gc.REC_FIXED), None)
    tag = "OK" if bad is None else "MISMATCH(%s)" % bad
    print("Frame #%d  seq=%d  count=%d  drop_count=%d  flags=0x%02x(%s%s)  v%d  tag=%s  (%d bytes)"
          % (idx, f["seq"], f["count"], f["drop"], f["flags"], partial,
             drops, f["version"], tag, len(raw)))
    if verbose:
        for j, rec in enumerate(f["records"]):
            print("    [%3d] %s" % (j, fmt_record(rec)))
    return True


def main():
    ap = argparse.ArgumentParser(description="Decode graph-plugin frames")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--pcap", help="read from pcap file")
    src.add_argument("-i", "--iface", help="live capture from interface (root)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print every record")
    ap.add_argument("-c", "--count", type=int, default=0,
                    help="stop after N aggregated frames (0 = all)")
    args = ap.parse_args()

    shown = 0
    if args.pcap:
        from scapy.all import rdpcap
        for p in rdpcap(args.pcap):
            if show_frame(shown, bytes(p), args.verbose):
                shown += 1
                if args.count and shown >= args.count:
                    break
    else:
        from scapy.all import sniff

        def cb(p):
            nonlocal shown
            if show_frame(shown, bytes(p), args.verbose):
                shown += 1

        sniff(iface=args.iface, filter="ether proto 0x88b5",
              count=args.count or 0, prn=cb, store=False)

    print("\n%d aggregated frame(s) shown." % shown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
