#!/usr/bin/env python3
"""Latch + read CMAC MAC-level TX/RX packet counters (wire-level proof).

netdev tx/rx counters only prove host<->driver. These CMAC statistics count
packets actually crossing the 100G MAC, so they distinguish "we transmitted on
the wire" from "the switch forwarded to us". Write TICK to snapshot, then read.
Reads are cumulative since link-up; diff two runs (before/after an inject).

  sudo ./cmac_pktcount.py 0000:25:00.0 0000:81:00.0 0000:c1:00.0

Pass each card's master PF (function .0). Register map: onic_register.h.
"""
import ctypes
import mmap
import os
import sys

CMAC_BASE = {0: 0x8000, 1: 0xC000}
TICK = 0x02B0
OFF = dict(TX_PKTS=0x0500, TX_GOOD=0x0508, RX_PKTS=0x0608, RX_GOOD=0x0610)


def mapper(bdf):
    path = "/sys/bus/pci/devices/%s/resource2" % bdf
    f = open(path, "r+b", buffering=0)              # keep alive across mmap()
    m = mmap.mmap(f.fileno(), os.path.getsize(path))

    def rd(o):
        return int(ctypes.c_uint32.from_buffer(m, o).value)

    def wr(o, v):
        ctypes.c_uint32.from_buffer(m, o).value = v & 0xFFFFFFFF

    def rd64(o):
        return rd(o) | (rd(o + 4) << 32)
    return rd, wr, rd64


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for bdf in sys.argv[1:]:
        rd, wr, rd64 = mapper(bdf)
        print("== %s ==" % bdf)
        for port in (0, 1):
            b = CMAC_BASE[port]
            wr(b + TICK, 1)                          # latch a snapshot of all stats
            print("  CMAC%d  TX_pkts=%-10d TX_good=%-10d RX_pkts=%-10d RX_good=%-10d"
                  % (port, rd64(b + OFF["TX_PKTS"]), rd64(b + OFF["TX_GOOD"]),
                     rd64(b + OFF["RX_PKTS"]), rd64(b + OFF["RX_GOOD"])))


if __name__ == "__main__":
    main()
