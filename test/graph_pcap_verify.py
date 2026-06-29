#!/usr/bin/env python3
"""Verify aggregated frames captured while replaying a real pcap.

Like graph_verify.py, but the expected records are derived from the *sent*
encapsulated pcap (graph_common.record_for_packet) rather than the synthetic
make_packet(i) sequence -- so it works for any replayed trace. Checks descriptor
invariants per frame and that every sent IPv4 packet's record appears as an
in-order subsequence of the emitted records.

  ./graph_pcap_verify.py -f /tmp/agg.pcap -s slice.pcap

Exit code 0 on success, 1 on any failure (suitable for run_pcap_test.sh).
"""

import argparse
import sys

from scapy.all import rdpcap

import graph_common as gc


def main():
    ap = argparse.ArgumentParser(description="Verify graph-plugin output vs a replayed pcap")
    ap.add_argument("-f", "--pcap", required=True, help="captured 0x88B5 pcap")
    ap.add_argument("-s", "--sent", required=True,
                    help="the encapsulated pcap that was replayed (expected source)")
    args = ap.parse_args()

    # Expected records: one per IPv4 packet in the sent slice, in send order.
    expected = []
    for p in rdpcap(args.sent):
        rec = gc.record_for_packet(p)
        if rec is not None:
            expected.append(rec)
    if not expected:
        print("FAIL: sent pcap %s yielded no IPv4 records" % args.sent)
        return 1

    frames = []
    for p in rdpcap(args.pcap):
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

    records = []
    expect_seq = frames[0]["seq"]
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

    matched = gc.ordered_subsequence_matched(expected, records)

    print("Sent IPv4 packets: %d" % len(expected))
    print("Frames: %d (seq %d..%d)" % (len(frames), frames[0]["seq"],
                                       frames[-1]["seq"]))
    print("Records received: %d" % len(records))
    print("In-order matched: %d / %d" % (matched, len(expected)))
    print("Max drop_count in descriptor: %d" % max_drop)

    if matched != len(expected):
        print("FAIL: only %d/%d sent records matched in order "
              "(garbled records => extraction/encapsulation bug)"
              % (matched, len(expected)))
        return 1
    if max_drop != 0:
        print("WARN: drop_count=%d (records dropped on FIFO-full). "
              "Functional match still OK, but investigate rate/backpressure."
              % max_drop)

    print("PASS: all %d replayed IPv4 packets extracted and aggregated correctly."
          % len(expected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
