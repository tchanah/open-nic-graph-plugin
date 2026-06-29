#!/bin/bash
# Graph-plugin functional loopback test using a REAL replayed trace (Phase 0).
#
# Same loopback topology as run_graph_test.sh, but instead of synthetic packets
# it replays a slice of a real (raw-IP) pcap that has been Ethernet-encapsulated
# by pcap_prep.py. Confirms the plugin correctly extracts/aggregates records from
# the actual dataset before investing in a high-rate (DPDK) replay.
#
# Usage: sudo ./run_pcap_test.sh <src_rawip_pcap> [iface0] [iface1] [count]
#   e.g: sudo ./run_pcap_test.sh /scratch/data/20220102-120000.pcap ens4f0 ens4f1 5000
#
# Requires: scapy + tcpdump, run as root, NIC programmed with the graph bitfile.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SRC_PCAP=${1:?usage: run_pcap_test.sh <src_rawip_pcap> [iface0] [iface1] [count]}
IFACE0=${2:-ens4f0}     # inject side (default namespace)
IFACE1=${3:-ens4f1}     # capture side (isolated namespace)
COUNT=${4:-5000}
NS=ns_graph_cap
SRC_DIR="$(cd "$(dirname "${SRC_PCAP}")" && pwd)"   # keep artifacts beside the source
SLICE=${SLICE:-${SRC_DIR}/graph_slice.pcap}
PCAP=${PCAP:-${SRC_DIR}/graph_agg_pcap.pcap}

cleanup() {
    echo "Cleaning up..."
    [ -n "${TCPDUMP_PID:-}" ] && kill "$TCPDUMP_PID" 2>/dev/null
    ip netns del ${NS} 2>/dev/null
}
trap cleanup EXIT

echo "=== Prep: slice ${COUNT} pkts from ${SRC_PCAP} + Ethernet-encapsulate ==="
./pcap_prep.py -i "${SRC_PCAP}" -o "${SLICE}" -n "${COUNT}" || exit 1

echo ""
echo "Inject: ${IFACE0} (default ns)   Capture: ${IFACE1} (${NS})   Slice: ${SLICE}"

# Fresh namespace for the capture interface
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

./graph_pcap_inject.py -i "${IFACE0}" -f "${SLICE}"

sleep 2
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
TCPDUMP_PID=""

echo ""
echo "=== Verification ==="
./graph_pcap_verify.py -f "$PCAP" -s "${SLICE}"
RC=$?

echo ""
echo "Capture saved to ${PCAP} (rc=${RC})"
exit $RC
