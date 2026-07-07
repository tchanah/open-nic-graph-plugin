#!/usr/bin/env python3
"""Stream-validate a large aggregated (0x88B5) pcap without loading it into RAM.

graph_dump.py / graph_pcap_verify.py use scapy rdpcap, which loads the whole file
-- fine for MB captures, but the graph_replay full-trace recording is tens of GB.
This reads the pcap incrementally with the stdlib struct module (no scapy, no OOM),
tallies each frame's descriptor (version, drop_count, frame_seq, REC_FIXED tag), and
decodes a few sample frames.

  ./graph_agg_check.py -f /scratch/data/graph_agg_out.pcap

Healthy: maxdrop=0, tag mismatches=0, version!=3 count=0. A few frame_seq gaps at the
very start are normal (pre-run kernel chatter). Exit 0 if clean, 1 otherwise.
"""

import argparse
import struct
import sys

import graph_common as gc   # scapy-free at import time; only for constants + decode_record

PROTO_CODE = {0x8: "TCP", 0x4: "UDP", 0x2: "ICMP", 0x1: "OTH"}
FLAG_BITS = [(0x8, "A"), (0x4, "R"), (0x2, "S"), (0x1, "F")]


def fmt_record(rec):
    d = gc.decode_record(rec)
    flags = "".join(c for b, c in FLAG_BITS if d["flags_code"] & b) or "-"
    return "%-15s:%-5d -> %-15s:%-5d %-4s len=%-5d flags=%s" % (
        d["src"], d["sport"], d["dst"], d["dport"],
        PROTO_CODE.get(d["proto_code"], "0x%x" % d["proto_code"]), d["length"], flags)


def main():
    ap = argparse.ArgumentParser(description="Stream-validate a large 0x88B5 pcap")
    ap.add_argument("-f", "--pcap", required=True,
                    help="aggregated 0x88B5 pcap (may be tens of GB)")
    ap.add_argument("--show", type=int, default=5,
                    help="decode this many sample frames (default 5)")
    args = ap.parse_args()

    f = open(args.pcap, "rb")
    gh = f.read(24)
    if len(gh) < 24:
        print("FAIL: short/empty pcap")
        return 1
    magic = struct.unpack("<I", gh[:4])[0]
    if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
        print("FAIL: bad pcap magic 0x%08x" % magic)
        return 1
    end = ">" if magic == 0xd4c3b2a1 else "<"

    frames = records = maxdrop = tagbad = verbad = seqgap = nonagg = 0
    last_seq = None
    shown = 0
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            break
        _, _, incl, _ = struct.unpack(end + "IIII", rh)
        if incl == 0 or incl > 65535:
            print("FAIL: bad record length %d at frame %d" % (incl, frames))
            return 1
        d = f.read(incl)
        if len(d) < incl:
            print("WARN: truncated final record (partial capture) -- stopping")
            break
        if len(d) < gc.PREFIX_LEN or d[12:14] != b"\x88\xb5":
            nonagg += 1
            continue
        count = (d[14] << 8) | d[15]
        drop = int.from_bytes(d[16:20], "big")
        seq = int.from_bytes(d[20:24], "big")
        ver = d[25]
        frames += 1
        records += count
        if drop > maxdrop:
            maxdrop = drop
        if ver != gc.HDR_VERSION:
            verbad += 1
        if len(d) >= gc.PREFIX_LEN + 8 and d[gc.PREFIX_LEN:gc.PREFIX_LEN + 8] != gc.REC_FIXED:
            tagbad += 1
        if last_seq is not None and seq != last_seq + 1:
            seqgap += 1
        last_seq = seq
        if shown < args.show and count >= 1 and len(d) >= gc.PREFIX_LEN + gc.RECORD_LEN:
            print("  seq=%d count=%d drop=%d v%d tag=%s" % (
                seq, count, drop, ver, d[gc.PREFIX_LEN:gc.PREFIX_LEN + 8].hex()))
            print("    [0] %s" % fmt_record(d[gc.PREFIX_LEN:gc.PREFIX_LEN + gc.RECORD_LEN]))
            shown += 1
        if frames % 5000000 == 0:
            print("  ...%d frames, maxdrop=%d" % (frames, maxdrop))

    print()
    print("Frames:            %d" % frames)
    print("Records:           %d" % records)
    print("Max drop_count:    %d" % maxdrop)
    print("Tag mismatches:    %d" % tagbad)
    print("version != 0x%02x:   %d" % (gc.HDR_VERSION, verbad))
    print("frame_seq gaps:    %d" % seqgap)
    if nonagg:
        print("non-0x88B5 frames: %d (skipped)" % nonagg)

    ok = (frames > 0 and maxdrop == 0 and tagbad == 0 and verbad == 0)
    if ok:
        print("PASS: %d frames, all v3, tag OK, drop_count=0." % frames)
        return 0
    print("FAIL: see nonzero drop/tag/version counters above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
