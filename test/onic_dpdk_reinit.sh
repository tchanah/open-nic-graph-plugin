#!/bin/bash
# Re-program OpenNIC's QDMA steering + CMAC-enable registers for the DPDK
# (QDMA PMD) loopback setup.
#
# These OpenNIC shell registers live in the QDMA reset domain, so vfio-pci
# WIPES them every time it resets the device -- which happens when a DPDK app
# (pktgen/testpmd) exits. Symptom: the first run after a fresh init works, the
# next run sees no loopback. So run this before EACH pktgen/testpmd launch.
#
# The sequence that actually decodes the BAR: detach both PFs from vfio (so the
# sysfs resource2 mmap reaches the device), enable PCIe memory space, poke the
# registers, then re-bind to vfio. Values mirror Xilinx/open-nic-dpdk:
#   QCONF func0 = qbase 0 / numq 1   ;  QCONF func1 = qbase 1 / numq 1
#   CMAC0 enable (0x8014,0x800c)     ;  CMAC1 enable (0xC014,0xC00c)
#
# Usage: sudo-less (it sudo's internally):  ./onic_dpdk_reinit.sh
set -e

DEVBIND=${DEVBIND:-$HOME/dpdk-stable-20.11.9/usertools/dpdk-devbind.py}
PCIMEM=${PCIMEM:-$HOME/pcimem/pcimem}
PF0=${PF0:-0000:17:00.0}
PF1=${PF1:-0000:17:00.1}
RES=/sys/bus/pci/devices/$PF0/resource2

echo "Detaching $PF0 $PF1 from vfio for register access..."
sudo "$DEVBIND" -u "$PF0" "$PF1" 2>/dev/null || true

echo "Enabling PCIe memory space..."
sudo setpci -s "${PF0#0000:}" COMMAND=0x02
sudo setpci -s "${PF1#0000:}" COMMAND=0x02

echo "Programming OpenNIC QDMA steering + CMAC enables..."
sudo "$PCIMEM" "$RES" 0x1000 w 0x1          # QCONF func0: qbase=0, numq=1
sudo "$PCIMEM" "$RES" 0x2000 w 0x00010001   # QCONF func1: qbase=1, numq=1
sudo "$PCIMEM" "$RES" 0x8014 w 0x1          # CMAC0 enable
sudo "$PCIMEM" "$RES" 0x800c w 0x1          # CMAC0 enable
sudo "$PCIMEM" "$RES" 0xC014 w 0x1          # CMAC1 enable
sudo "$PCIMEM" "$RES" 0xC00c w 0x1          # CMAC1 enable

echo "Re-binding to vfio-pci..."
sudo "$DEVBIND" -b vfio-pci "$PF0" "$PF1"

echo "Done. Registers re-initialized; launch pktgen/testpmd now."
