#!/bin/bash
# Program one or more Alveo U250 cards with the graph-plugin bitfile via JTAG.
# Vivado must be sourced first (setup-vivado).
#
# octo250 has 8 U250s on one JTAG chain, so you must name which card(s) to
# program by JTAG serial. Use --list first to see the serials.
#
# Usage:
#   ./program_fpga.sh --list                          # list JTAG targets/serials, program nothing
#   ./program_fpga.sh [-b BITFILE] SERIAL [SERIAL...]  # program the named card(s)
#
# SERIAL may be a bare JTAG serial (e.g. 213308367035A) or a full hw_target
# URL (localhost:3121/xilinx_tcf/Xilinx/<serial>). Default bitfile is the
# au250_graph_v3 impl_1 output.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repos (open-nic-shell / open-nic-graph-plugin / ...) are cloned as siblings, so
# locate the shell build relative to this script rather than hardcoding a home dir.
WORKSPACE="$(cd "${SCRIPT_DIR}/../.." && pwd)"   # parent folder holding the open-nic-* repos
BUILD_TAG="au250_graph_v3"
DEFAULT_BIT="${WORKSPACE}/open-nic-shell/build/${BUILD_TAG}/open_nic_shell/open_nic_shell.runs/impl_1/open_nic_shell.bit"
HW_URL="localhost:3121"

BITFILE="$DEFAULT_BIT"
LIST_ONLY=0
SERIALS=()

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--bitfile) BITFILE="$2"; shift 2 ;;
        --list)       LIST_ONLY=1; shift ;;
        -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
        -*)           echo "Unknown option: $1"; exit 1 ;;
        *)            SERIALS+=("$1"); shift ;;
    esac
done

run_vivado() {
    # Run Vivado from a throwaway writable dir so its .Xil scratch never depends
    # on the caller's CWD being writable (avoids "Unable to create directory .Xil").
    local d rc
    d="$(mktemp -d)"
    ( cd "$d" && vivado "$@" ); rc=$?
    rm -rf "$d"
    return $rc
}

start_hw_server() {
    /tools/Xilinx/Vivado/2021.1/bin/hw_server >/dev/null 2>&1 &
    HW_SERVER_PID=$!
    sleep 2
    trap 'kill $HW_SERVER_PID 2>/dev/null' EXIT
}

# --- list mode ---
if [ "$LIST_ONLY" = 1 ]; then
    start_hw_server
    HW_LIST=1 run_vivado -mode batch -source "${SCRIPT_DIR}/program_fpga.tcl"
    exit 0
fi

# --- program mode ---
if [ ${#SERIALS[@]} -eq 0 ]; then
    echo "No card serial(s) given."
    echo "  Run './program_fpga.sh --list' to see the 8 cards, then"
    echo "      './program_fpga.sh SERIAL [SERIAL...]' to program the ones you want."
    exit 1
fi

if [ ! -f "$BITFILE" ]; then
    echo "Bitfile not found: $BITFILE"
    exit 1
fi

# Expand bare serials into full hw_target URLs (leave full URLs untouched)
TARGETS=""
for s in "${SERIALS[@]}"; do
    case "$s" in
        */*) TARGETS+="$s " ;;
        *)   TARGETS+="${HW_URL}/xilinx_tcf/Xilinx/${s} " ;;
    esac
done

echo "Bitfile: $BITFILE"
echo "Programming ${#SERIALS[@]} card(s):"
for t in $TARGETS; do echo "  $t"; done
echo ""

start_hw_server
export BITFILE
export HW_TARGETS="$TARGETS"
run_vivado -mode batch -source "${SCRIPT_DIR}/program_fpga.tcl"

echo ""
echo "Programmed ${#SERIALS[@]} card(s). Next: sudo reboot   (WARM reboot — never PCIe rescan / hard reset)"
echo "After reboot: load_driver.sh, then verify with 'lspci | grep -i xilinx' (expect 2 'Network controller' PFs per card)."
