"""Shared definitions for the graph-plugin hardware test (inject + verify).

Keeps the synthetic 5-tuple generation and the aggregated-frame parser in one
place so graph_inject.py and graph_verify.py can never drift apart. The frame
format here must match graph_aggregator.sv:

  slot 0 (0..15):   Eth(14) + record count K (BE)
  slot 1 (16..31):  drop_count(4 BE) | frame_seq(4 BE) | flags(1) |
                    version(1) | reserved(6)
  slot 2.. :        K x 16-byte records:
                    srcIP(4) dstIP(4) srcPort(2 BE) dstPort(2 BE) proto(1) pad(3)
"""

import socket

# Must match graph_aggregator.sv parameters / format.
ETH_TYPE = 0x88B5
PREFIX_LEN = 32
RECORD_LEN = 16
MAX_RECORDS = 91
HDR_VERSION = 1

# Fixed L2 addresses for the injected (original) packets. Irrelevant to the
# plugin (it only reads L3/L4), but kept constant for reproducibility.
INJ_SRC_MAC = "aa:bb:cc:dd:ee:ff"
INJ_DST_MAC = "11:22:33:44:55:66"


def _ips(i):
    """Distinctive, index-derived src/dst IPv4 strings (10.1.x.x -> 10.2.x.x)."""
    return ("10.1.%d.%d" % ((i >> 8) & 0xFF, i & 0xFF),
            "10.2.%d.%d" % ((i >> 8) & 0xFF, i & 0xFF))


def _ports(i):
    return 1024 + (i % 60000), 2048 + (i % 60000)


def make_packet(i, l4="udp"):
    """Build the i-th synthetic IPv4 test packet (scapy)."""
    from scapy.all import Ether, IP, UDP, TCP
    src_ip, dst_ip = _ips(i)
    sport, dport = _ports(i)
    l4_hdr = TCP(sport=sport, dport=dport) if l4 == "tcp" \
        else UDP(sport=sport, dport=dport)
    pkt = Ether(src=INJ_SRC_MAC, dst=INJ_DST_MAC) \
        / IP(src=src_ip, dst=dst_ip) / l4_hdr / (b"\xab" * 64)
    return Ether(bytes(pkt))  # finalize lengths/proto


def expected_record(i, l4="udp"):
    """The 16-byte record the aggregator should emit for make_packet(i)."""
    src_ip, dst_ip = _ips(i)
    sport, dport = _ports(i)
    proto = 6 if l4 == "tcp" else 17
    return (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
            + sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + bytes([proto]) + b"\x00" * 3)


def parse_frame(raw):
    """Parse one captured Ethernet frame; return a dict or None if not ours.

    Validates structural invariants and raises AssertionError on a malformed
    aggregated frame (so corruption is loud).
    """
    if len(raw) < PREFIX_LEN:
        return None
    if int.from_bytes(raw[12:14], "big") != ETH_TYPE:
        return None
    count = int.from_bytes(raw[14:16], "big")
    drop = int.from_bytes(raw[16:20], "big")
    seq = int.from_bytes(raw[20:24], "big")
    flags = raw[24]
    version = raw[25]
    assert version == HDR_VERSION, "bad version %d" % version
    assert 1 <= count <= MAX_RECORDS, "count out of range: %d" % count
    assert raw[26:32] == b"\x00" * 6, "reserved bytes nonzero"
    expect_len = PREFIX_LEN + RECORD_LEN * count
    assert len(raw) >= expect_len, \
        "frame too short: %d < %d" % (len(raw), expect_len)
    records = [raw[PREFIX_LEN + RECORD_LEN * j: PREFIX_LEN + RECORD_LEN * (j + 1)]
               for j in range(count)]
    return dict(count=count, drop=drop, seq=seq, flags=flags,
                version=version, records=records)


def ordered_subsequence_matched(expected, received):
    """How many of `expected` appear, in order, within `received`.

    Returns the count matched (== len(expected) means full in-order match).
    Tolerates stray records (e.g. kernel IGMP/mDNS) interleaved between ours.
    """
    ei = 0
    for r in received:
        if ei < len(expected) and r == expected[ei]:
            ei += 1
    return ei
