#!/bin/bash
# Graph-plugin functional loopback test.
#
# Inject known IPv4 packets on IFACE0 (default ns); they loop over the QSFP
# cable into CMAC port1, where the plugin extracts a 5-tuple per packet and
# emits aggregated 0x88B5 frames to the host on IFACE1. Capture those frames
# and verify every injected 5-tuple was extracted and aggregated in order.
#
# IFACE1 is moved into its own network namespace so the kernel cannot
# short-circuit the two local interfaces internally (it would bypass the FPGA).
#
# Usage: sudo ./run_graph_test.sh [iface0] [iface1] [count]
#   e.g: sudo ./run_graph_test.sh ens4f0 ens4f1 200
#
# Requires: scapy + tcpdump, run as root, NIC programmed with the graph bitfile.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"   # so the python scripts find graph_common

IFACE0=${1:-ens4f0}     # inject side (default namespace)
IFACE1=${2:-ens4f1}     # capture side (isolated namespace)
COUNT=${3:-200}
NS=ns_graph_cap
PCAP=/tmp/graph_agg.pcap

cleanup() {
    echo "Cleaning up..."
    [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null
    ip netns del ${NS} 2>/dev/null
}
trap cleanup EXIT

echo "Inject: ${IFACE0} (default ns)   Capture: ${IFACE1} (${NS})   Count: ${COUNT}"

# Fresh namespace for the capture interface
ip netns del ${NS} 2>/dev/null
ip netns add ${NS}
ip link set "${IFACE1}" netns ${NS}
ip netns exec ${NS} ip link set "${IFACE1}" up
ip netns exec ${NS} ip link set lo up
ip link set "${IFACE0}" up

echo "Waiting for carrier..."
sleep 3

# Start capturing the aggregated frames (EtherType 0x88B5) on the host side
rm -f "$PCAP"
ip netns exec ${NS} tcpdump -i "${IFACE1}" -w "$PCAP" 'ether proto 0x88b5' \
    >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Inject the known packets on the other side
./graph_inject.py -i "${IFACE0}" -n "${COUNT}"

# Let the timeout-flushed tail frame arrive (~1 ms in HW) and capture drain
sleep 2
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
TCPDUMP_PID=""

echo ""
echo "=== Verification ==="
./graph_verify.py -f "$PCAP" -n "${COUNT}"
RC=$?

echo ""
echo "Capture saved to ${PCAP} (rc=${RC})"
exit $RC
