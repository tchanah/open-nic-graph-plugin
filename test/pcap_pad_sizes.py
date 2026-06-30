#!/usr/bin/env python3
"""Zero-pad an Ethernet pcap slice into fixed-size variants for a throughput sweep.

Follows "Extracting TCPIP Headers at High Speed for the Anonymized Network
Traffic Graph Challenge" (arXiv:2409.07374): the CAIDA Equinix-Chicago traces
carry only TCP/IP headers, so to drive the datapath at a chosen packet size we
zero-pad each frame up to that size (and truncate the rare frame already larger).
One output pcap is written per size, e.g.

  graph_slice.pcap -> graph_slice_64.pcap graph_slice_128.pcap ... _1518.pcap

This reuses the existing small slice (graph_slice.pcap from pcap_prep.py) -- it
never touches the multi-GB source. pktgen loops the replay pcap, so a few
thousand frames per size saturate the link while keeping each file tiny:
throughput depends on packet size and rate, not on file length. IP total-length
and checksum are recomputed so every padded frame is a well-formed packet of
exactly the requested size (this becomes the plugin's totalLen record field).

  ./pcap_pad_sizes.py -i /scratch/data/graph_slice.pcap -o <writable_dir> \
      --sizes 64,128,256,512,1024,1518
"""

import argparse
import os
import sys

from scapy.all import Ether, IP, Raw, rdpcap, wrpcap

DEFAULT_SIZES = [64, 128, 256, 512, 1024, 1518]


def resize(frame, size, fcs):
    """Return a copy of `frame` whose pcap length is exactly `size - fcs` bytes.

    `size` is the nominal Ethernet frame size from the paper's table. Pass
    `--fcs 4` if the NIC/CMAC appends the 4-byte CRC, so the *on-wire* frame
    (pcap bytes + hardware FCS) matches `size`; with the default fcs=0 the pcap
    bytes equal `size` (matching the doc's `Throughput = pps * size * 8`).
    """
    target = size - fcs
    raw = bytes(frame)
    if len(raw) < target:
        frame = frame / Raw(load=b"\x00" * (target - len(raw)))
    elif len(raw) > target:
        frame = Ether(raw[:target])
    if IP in frame:                       # recompute so the frame is a valid size-N packet
        del frame[IP].len
        del frame[IP].chksum
    return Ether(bytes(frame))            # finalize lengths/checksums


def main():
    ap = argparse.ArgumentParser(
        description="Zero-pad a pcap slice into fixed-size variants (arXiv:2409.07374 sweep)")
    ap.add_argument("-i", "--input", required=True,
                    help="sliced Ethernet pcap (e.g. /scratch/data/graph_slice.pcap)")
    ap.add_argument("--sizes", default=",".join(map(str, DEFAULT_SIZES)),
                    help="comma-separated frame sizes (default: %(default)s)")
    ap.add_argument("--fcs", type=int, default=0,
                    help="bytes the NIC appends as FCS, subtracted from each size (default 0)")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output directory (default: alongside the input pcap)")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    pkts = rdpcap(args.input)             # the slice is small -> loading it whole is fine
    if not pkts:
        print("ERROR: no packets in %s" % args.input)
        return 1

    base, ext = os.path.splitext(os.path.basename(args.input))
    outdir = args.outdir or os.path.dirname(os.path.abspath(args.input))
    for size in sizes:
        out = os.path.join(outdir, "%s_%d%s" % (base, size, ext or ".pcap"))
        wrpcap(out, [resize(p, size, args.fcs) for p in pkts])
        print("Wrote %d x %dB frames -> %s" % (len(pkts), size, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
