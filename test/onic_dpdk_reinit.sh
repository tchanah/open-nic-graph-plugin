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
# It also (idempotently) restores the DPDK env that a reboot clears: loads
# vfio-pci, enables no-IOMMU mode, and allocates hugepages -- so it works after
# a fresh boot, not just between DPDK runs.
#
# Usage (sudo's internally):  ./onic_dpdk_reinit.sh
#   NUMQ=N       H2C queues on func0 for the multi-queue ramp (default 1)
#   HUGEPAGES=K  2MB pages to allocate if none exist (default 4096; 0 = skip)
set -e

DEVBIND=${DEVBIND:-$HOME/dpdk-stable-20.11.9/usertools/dpdk-devbind.py}
PCIMEM=${PCIMEM:-$HOME/pcimem/pcimem}
PF0=${PF0:-0000:17:00.0}
PF1=${PF1:-0000:17:00.1}
RES=/sys/bus/pci/devices/$PF0/resource2
# H2C queues on func0 (PF0/TX). 1 = original single-queue; >1 = multi-queue ramp.
# QCONF word = (qbase<<16)|numq  -- func0 gets [0,NUMQ), func1 (C2H) stays 1 queue at qbase NUMQ.
# NOTE: the >1 field layout is inferred from the single-queue values; verify on HW.
NUMQ=${NUMQ:-1}
HUGEPAGES=${HUGEPAGES:-4096}   # 2MB pages to allocate if none are (0 = skip)

# --- ensure the DPDK env (reset by a reboot): vfio-pci, no-IOMMU, hugepages ---
# Idempotent: each check is a no-op once set, so this only does work after a boot.
if ! lsmod | grep -q '^vfio_pci'; then
    echo "Loading vfio-pci..."
    sudo modprobe vfio-pci
fi
if [ "$(cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null)" != "Y" ]; then
    echo "Enabling vfio no-IOMMU mode (IOMMU is off on this host)..."
    echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode >/dev/null
fi
HP=/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
if [ "$HUGEPAGES" != "0" ] && [ "$(cat "$HP" 2>/dev/null || echo 0)" -lt "$HUGEPAGES" ]; then
    echo "Allocating $HUGEPAGES x 2MB hugepages..."
    echo "$HUGEPAGES" | sudo tee "$HP" >/dev/null
fi

echo "Detaching $PF0 $PF1 from vfio for register access..."
sudo "$DEVBIND" -u "$PF0" "$PF1" 2>/dev/null || true

echo "Enabling PCIe memory space..."
sudo setpci -s "${PF0#0000:}" COMMAND=0x02
sudo setpci -s "${PF1#0000:}" COMMAND=0x02

echo "Programming OpenNIC QDMA steering (NUMQ=$NUMQ) + CMAC enables..."
Q0=$(printf '0x%x' "$NUMQ")                  # func0: qbase=0, numq=NUMQ
Q1=$(printf '0x%x' "$(( (NUMQ << 16) | 1 ))") # func1: qbase=NUMQ, numq=1  (C2H single queue)
sudo "$PCIMEM" "$RES" 0x1000 w "$Q0"        # QCONF func0: qbase=0, numq=$NUMQ
sudo "$PCIMEM" "$RES" 0x2000 w "$Q1"        # QCONF func1: qbase=$NUMQ, numq=1
sudo "$PCIMEM" "$RES" 0x8014 w 0x1          # CMAC0 enable
sudo "$PCIMEM" "$RES" 0x800c w 0x1          # CMAC0 enable
sudo "$PCIMEM" "$RES" 0xC014 w 0x1          # CMAC1 enable
sudo "$PCIMEM" "$RES" 0xC00c w 0x1          # CMAC1 enable

echo "Re-binding to vfio-pci..."
sudo "$DEVBIND" -b vfio-pci "$PF0" "$PF1"

echo "Done. Registers re-initialized; launch pktgen/testpmd now."
