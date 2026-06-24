#!/bin/bash
# Graph-plugin v2 field-extraction test (TCP flags / packet length / TTL).
#
# Injects a small, deliberately varied set of packets on IFACE0 and verifies
# each emitted record carries the right tcpFlags / totalLen / TTL / ports.
# Complements run_graph_test.sh (bulk aggregation, fixed length / UDP).
#
# Usage: sudo ./run_fields_test.sh [iface0] [iface1]
#   e.g: sudo ./run_fields_test.sh ens4f0 ens4f1
#
# Requires: scapy + tcpdump, run as root, NIC programmed with the v2 bitfile.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IFACE0=${1:-ens4f0}     # inject side (default namespace)
IFACE1=${2:-ens4f1}     # capture side (isolated namespace)
NS=ns_graph_cap
PCAP=/tmp/graph_fields.pcap

cleanup() {
    echo "Cleaning up..."
    [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null
    ip netns del ${NS} 2>/dev/null
}
trap cleanup EXIT

echo "Inject: ${IFACE0} (default ns)   Capture: ${IFACE1} (${NS})"

ip netns del ${NS} 2>/dev/null
ip netns add ${NS}
ip link set "${IFACE1}" netns ${NS}
ip netns exec ${NS} ip link set "${IFACE1}" up
ip netns exec ${NS} ip link set lo up
ip link set "${IFACE0}" up

echo "Waiting for carrier..."
sleep 3

rm -f "$PCAP"
ip netns exec ${NS} tcpdump -i "${IFACE1}" -w "$PCAP" 'ether proto 0x88b5' \
    >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

./graph_fields_test.py --inject -i "${IFACE0}"

# Let the timeout-flushed frame arrive (~1 ms in HW) and the capture drain
sleep 2
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
TCPDUMP_PID=""

echo ""
echo "=== Verification ==="
./graph_fields_test.py --verify -f "$PCAP"
RC=$?

echo ""
echo "Capture saved to ${PCAP} (rc=${RC})"
exit $RC
