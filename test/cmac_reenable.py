#!/usr/bin/env python3
"""Re-enable a CMAC port's RX/TX and watch whether the RX PCS actually locks.

The onic driver waits only RX_ALIGN_TIMEOUT_MS (once) for RX alignment at load;
if the 100G/FEC link comes up a moment later it gives up and disables the CMAC
(CONF_RX_1=CONF_TX_1=0). With RX disabled, BLOCK_LOCK reads 0 regardless of the
real link -- so "down" is ambiguous. onic_disable_cmac only clears those two
enables (it does NOT re-hold GT reset), so re-arming RX here is valid and safe;
reload the driver (rmmod/insmod onic) to return to the driver-managed state.

This writes only the same CMAC config regs the driver uses. "Aligned" matches
the driver's own test: RX_STATUS == 0x3.

  sudo ./cmac_reenable.py 0000:25:00.0 0            # port 0, keep RS-FEC on
  sudo ./cmac_reenable.py 0000:25:00.0 0 --nofec   # also disable RS-FEC (non-FEC partner)
  sudo ./cmac_reenable.py 0000:25:00.0 0 --secs=12
"""
import ctypes
import mmap
import os
import sys
import time

CMAC_BASE = {0: 0x8000, 1: 0xC000}
OFF = dict(CONF_TX_1=0x000C, CONF_RX_1=0x0014,
           RX_STATUS=0x0204, RX_BLOCK_LOCK=0x020C, RX_LANE_SYNC=0x0210,
           RSFEC_ENABLE=0x107C, RSFEC_STATUS=0x1004)


def mapper(bdf):
    path = "/sys/bus/pci/devices/%s/resource2" % bdf
    f = open(path, "r+b", buffering=0)   # keep the file object alive across mmap()
    m = mmap.mmap(f.fileno(), os.path.getsize(path))

    def rd(o):
        return int(ctypes.c_uint32.from_buffer(m, o).value)

    def wr(o, v):
        ctypes.c_uint32.from_buffer(m, o).value = v & 0xFFFFFFFF
    return rd, wr


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    bdf = sys.argv[1]
    port = int(sys.argv[2])
    nofec = "--nofec" in sys.argv
    fec_on = "--fec" in sys.argv
    secs = 8
    for a in sys.argv:
        if a.startswith("--secs="):
            secs = int(a.split("=")[1])

    b = CMAC_BASE[port]
    rd, wr = mapper(bdf)
    R = lambda n: rd(b + OFF[n])          # noqa: E731
    W = lambda n, v: wr(b + OFF[n], v)    # noqa: E731

    print("%s port %d BEFORE: RX_ena=0x%x TX_ena=0x%x BLOCK_LOCK=0x%x RSFEC_EN=0x%x RSFEC_STAT=0x%x RX_STATUS=0x%x"
          % (bdf, port, R("CONF_RX_1"), R("CONF_TX_1"), R("RX_BLOCK_LOCK"),
             R("RSFEC_ENABLE"), R("RSFEC_STATUS"), R("RX_STATUS")))

    if nofec:
        print("  --nofec: RSFEC_ENABLE <- 0")
        W("RSFEC_ENABLE", 0x0)
    elif fec_on:
        print("  --fec: RSFEC_ENABLE <- 0x3")
        W("RSFEC_ENABLE", 0x3)

    # re-arm the MAC: enable RX, enable TX (send valid idles so the partner can lock to us)
    W("CONF_RX_1", 0x1)
    W("CONF_TX_1", 0x1)

    locked = False
    t0 = time.time()
    while time.time() - t0 < secs:
        rs = R("RX_STATUS")
        bl = R("RX_BLOCK_LOCK")
        ls = R("RX_LANE_SYNC")
        fs = R("RSFEC_STATUS")
        print("  t=%4.1fs RX_STATUS=0x%08x BLOCK_LOCK=0x%08x LANE_SYNC=0x%08x RSFEC_STATUS=0x%08x"
              % (time.time() - t0, rs, bl, ls, fs))
        # BLOCK_LOCK all-lanes is the authoritative lock; RX_STATUS is sticky/latched.
        if bl == 0x000FFFFF:
            locked = True
            break
        time.sleep(0.5)

    if locked:
        print("RESULT: port %d LOCKED (BLOCK_LOCK=0x%05x, all lanes). Link is good with the "
              "current FEC setting." % (port, 0xFFFFF))
    else:
        print("RESULT: port %d did NOT lock in %ds. Note 100G links can take several seconds "
              "to settle; if RS-FEC is on here, retry with --nofec (this rig's switch is no-FEC)." % (port, secs))


if __name__ == "__main__":
    main()
