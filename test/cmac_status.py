#!/usr/bin/env python3
"""Read CMAC RX link + RS-FEC status from OpenNIC shell BAR2 registers.

Diagnoses "carrier up but zero traffic" cases: shows whether each port's RX
PCS/RS-FEC is actually locked to its link partner (switch), independent of the
netdev. Reads are done by mmap'ing the master PF's BAR2 (resource2) directly —
no pcimem/ethtool needed. Run as root.

  sudo ./cmac_status.py 0000:25:00.0 0000:81:00.0 0000:c1:00.0

Pass the *master PF* (function .0) BDF of each card; both CMAC ports live in
that one shell register space. Register map from open-nic-driver onic_register.h.
"""
import ctypes
import mmap
import os
import sys

SHELL_STATUS = 0x0010                 # SYSCFG + 0x10
CMAC_BASE = {0: 0x8000, 1: 0xC000}    # CMAC_SUBSYSTEM_{0,1}_OFFSET
REG = {                               # offset within a CMAC subsystem
    "CONF_TX_1":     0x000C,
    "CONF_RX_1":     0x0014,
    "GT_LOOPBACK":   0x0090,
    "RX_STATUS":     0x0204,
    "RX_BLOCK_LOCK": 0x020C,
    "RX_LANE_SYNC":  0x0210,
    "RSFEC_ENABLE":  0x107C,
    "RSFEC_STATUS":  0x1004,
}


def reg_reader(bdf):
    path = "/sys/bus/pci/devices/%s/resource2" % bdf
    size = os.path.getsize(path)
    f = open(path, "r+b", buffering=0)
    m = mmap.mmap(f.fileno(), size)

    def rd(off):
        # 32-bit aligned load — OpenNIC AXI-Lite regs reject sub-dword access
        # (byte-wise mmap slicing reads back 0xFFFFFFFF).
        return int(ctypes.c_uint32.from_buffer(m, off).value)
    return rd


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for bdf in sys.argv[1:]:
        try:
            rd = reg_reader(bdf)
        except Exception as e:
            print("%s: cannot map BAR2 (%s) -- run as root?" % (bdf, e))
            continue
        build = rd(0x0)          # SYSCFG BUILD_STATUS — sanity (should be nonzero, not all-ones)
        shell = rd(SHELL_STATUS)
        print("== card %s   BUILD_STATUS=0x%08x  SHELL_STATUS=0x%08x ==" % (bdf, build, shell))
        if build == 0xFFFFFFFF and shell == 0xFFFFFFFF:
            print("   BAR2 still reads 0xFFFFFFFF -> access method/decode problem")
            continue
        for port in (0, 1):
            b = CMAC_BASE[port]
            v = {n: rd(b + o) for n, o in REG.items()}
            rx_ok = v["RX_STATUS"] & 0x1
            fec_lock = v["RSFEC_STATUS"] & 0x1
            print("   CMAC%d  RX_STATUS=0x%08x(%s) BLOCK_LOCK=0x%08x LANE_SYNC=0x%08x"
                  % (port, v["RX_STATUS"], "up" if rx_ok else "DOWN",
                     v["RX_BLOCK_LOCK"], v["RX_LANE_SYNC"]))
            print("          RSFEC_EN=0x%x RSFEC_STATUS=0x%08x(%s) TX_ena=0x%x RX_ena=0x%x GT_LOOPBACK=0x%x"
                  % (v["RSFEC_ENABLE"], v["RSFEC_STATUS"],
                     "locked" if fec_lock else "NOT-LOCKED",
                     v["CONF_TX_1"], v["CONF_RX_1"], v["GT_LOOPBACK"]))


if __name__ == "__main__":
    main()
