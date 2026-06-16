#!/usr/bin/env python3
"""Verify aggregated frames captured during the graph-plugin functional test.

Reads a pcap of the host-bound side (frames with EtherType 0x88B5), validates
each frame's 32-byte descriptor, and checks that the N injected 5-tuples appear
as an in-order subsequence of the emitted records.

  ./graph_verify.py -f /tmp/agg.pcap -n 200

Exit code 0 on success, 1 on any failure (suitable for run_graph_test.sh).
"""

import argparse
import sys

from scapy.all import rdpcap

import graph_common as gc


def main():
    ap = argparse.ArgumentParser(description="Verify graph-plugin output frames")
    ap.add_argument("-f", "--pcap", required=True, help="captured pcap file")
    ap.add_argument("-n", "--count", type=int, default=200,
                    help="number of packets that were injected")
    ap.add_argument("--l4", choices=["udp", "tcp"], default="udp")
    args = ap.parse_args()

    pkts = rdpcap(args.pcap)

    frames = []
    for p in pkts:
        try:
            f = gc.parse_frame(bytes(p))
        except AssertionError as e:
            print("FAIL: malformed aggregated frame: %s" % e)
            return 1
        if f is not None:
            frames.append(f)

    if not frames:
        print("FAIL: no 0x%04X frames found in %s" % (gc.ETH_TYPE, args.pcap))
        return 1

    # Collect records and check descriptor invariants across frames.
    records = []
    expect_seq = frames[0]["seq"]   # base seq (per-port counter)
    max_drop = 0
    for f in frames:
        if f["seq"] != expect_seq:
            print("FAIL: frame_seq gap: got %d, expected %d"
                  % (f["seq"], expect_seq))
            return 1
        expect_seq += 1
        max_drop = max(max_drop, f["drop"])
        partial = bool(f["flags"] & 0x01)
        if partial != (f["count"] < gc.MAX_RECORDS):
            print("FAIL: partial flag inconsistent (count=%d, flags=0x%02x)"
                  % (f["count"], f["flags"]))
            return 1
        records.extend(f["records"])

    # Functional check: every injected 5-tuple present, in order.
    expected = [gc.expected_record(i, args.l4) for i in range(args.count)]
    matched = gc.ordered_subsequence_matched(expected, records)

    print("Frames: %d (seq %d..%d)" % (len(frames), frames[0]["seq"],
                                       frames[-1]["seq"]))
    print("Records received: %d  (expected %d injected)"
          % (len(records), args.count))
    print("In-order matched: %d / %d" % (matched, args.count))
    print("Max drop_count in descriptor: %d" % max_drop)

    if matched != args.count:
        print("FAIL: only %d/%d injected records matched in order "
              "(garbled records => possible timing/extraction bug)"
              % (matched, args.count))
        return 1
    if max_drop != 0:
        print("WARN: drop_count=%d (records dropped on FIFO-full). "
              "Functional match still OK, but investigate rate/backpressure."
              % max_drop)

    print("PASS: all %d injected 5-tuples extracted and aggregated correctly."
          % args.count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
