#!/bin/bash
# Program the Alveo U250 with the graph-plugin bitfile via JTAG.
# Vivado must be sourced first (setup-vivado).
#
# Usage: ./program_fpga.sh [bitfile]
#   default bitfile: au250_graph_v3 impl_1 output
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_BIT="/home/chettige/research/open-nic-shell/build/au250_graph_v3/open_nic_shell/open_nic_shell.runs/impl_1/open_nic_shell.bit"

export BITFILE="${1:-$DEFAULT_BIT}"
if [ ! -f "$BITFILE" ]; then
    echo "Bitfile not found: $BITFILE"
    exit 1
fi
echo "Programming: $BITFILE"

/tools/Xilinx/Vivado/2021.1/bin/hw_server &
HW_SERVER_PID=$!
sleep 2

vivado -mode batch -source "${SCRIPT_DIR}/program_fpga.tcl"

kill $HW_SERVER_PID 2>/dev/null

echo ""
echo "FPGA programmed. Next: sudo reboot   (warm reboot — never PCIe rescan)"
echo "After reboot: load_driver.sh, then run_graph_test.sh"
