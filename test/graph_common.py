"""Shared definitions for the graph-plugin hardware test (inject + verify).

Keeps the synthetic 5-tuple generation and the aggregated-frame parser in one
place so graph_inject.py and graph_verify.py can never drift apart. The frame
format here must match graph_aggregator.sv:

  slot 0 (0..15):   Eth(14) + record count K (BE)
  slot 1 (16..31):  drop_count(4 BE) | frame_seq(4 BE) | flags(1) |
                    version(1) | reserved(6)
  slot 2.. :        K x 16-byte records (v2 layout):
                    srcIP(4) dstIP(4) ports(3, FloatingEncoder)
                    proto(1) TTL(1) totalLen(2 BE) tcpFlags(1)
"""

import socket

# Must match graph_aggregator.sv parameters / format.
ETH_TYPE = 0x88B5
PREFIX_LEN = 32
RECORD_LEN = 16
MAX_RECORDS = 91
HDR_VERSION = 2

# Fixed L2 addresses for the injected (original) packets. Irrelevant to the
# plugin (it only reads L3/L4), but kept constant for reproducibility.
INJ_SRC_MAC = "aa:bb:cc:dd:ee:ff"
INJ_DST_MAC = "11:22:33:44:55:66"


def _ips(i):
    """Distinctive, index-derived src/dst IPv4 strings (10.1.x.x -> 10.2.x.x)."""
    return ("10.1.%d.%d" % ((i >> 8) & 0xFF, i & 0xFF),
            "10.2.%d.%d" % ((i >> 8) & 0xFF, i & 0xFF))


def _ports(i):
    # Mix exact (<1024) and quantized (>1023) ports to exercise both paths.
    return i % 2000, 1024 + (i % 4000)


def _ttl(i):
    return 1 + (i % 254)


def _tcp_flags(i):
    return ["S", "SA", "A", "FA", "PA", "R"][i % 6]


def floating_encode(v):
    """16-bit value -> 12-bit FloatingEncoder code (mirrors graph_aggregator.sv)."""
    v &= 0xFFFF
    if v & 0xC000:      # bits [15:14]
        exp, mant = 3, v >> 6
    elif v & 0x3000:    # bits [13:12]
        exp, mant = 2, v >> 4
    elif v & 0x0C00:    # bits [11:10]
        exp, mant = 1, v >> 2
    else:               # 0..1023 exact (v==0 lands here)
        exp, mant = 0, v & 0x3FF
    return (exp << 10) | (mant & 0x3FF)


def floating_decode(code):
    """12-bit FloatingEncoder code -> value."""
    exp = (code >> 10) & 0x3
    return (code & 0x3FF) << (exp * 2)


def pack_ports(sport, dport):
    """Two ports -> the 3 packed record bytes (matches the RTL nibble layout)."""
    s = floating_encode(sport)
    d = floating_encode(dport)
    return bytes([(s >> 4) & 0xFF,
                  ((s & 0xF) << 4) | ((d >> 8) & 0xF),
                  d & 0xFF])


def unpack_ports(b3):
    """The 3 packed record bytes -> (sport, dport) decoded values."""
    s = (b3[0] << 4) | (b3[1] >> 4)
    d = ((b3[1] & 0xF) << 8) | b3[2]
    return floating_decode(s), floating_decode(d)


def make_packet(i, l4="udp"):
    """Build the i-th synthetic IPv4 test packet (scapy)."""
    from scapy.all import Ether, IP, UDP, TCP
    src_ip, dst_ip = _ips(i)
    sport, dport = _ports(i)
    if l4 == "tcp":
        l4_hdr = TCP(sport=sport, dport=dport, flags=_tcp_flags(i))
    else:
        l4_hdr = UDP(sport=sport, dport=dport)
    pkt = Ether(src=INJ_SRC_MAC, dst=INJ_DST_MAC) \
        / IP(src=src_ip, dst=dst_ip, ttl=_ttl(i)) / l4_hdr / (b"\xab" * 64)
    return Ether(bytes(pkt))  # finalize lengths/proto


def expected_record(i, l4="udp"):
    """The 16-byte v2 record the aggregator should emit for make_packet(i).

    Built by parsing make_packet(i) so it can never drift from the injector.
    """
    from scapy.all import IP, TCP, UDP
    pkt = make_packet(i, l4)
    ip = pkt[IP]
    rec = socket.inet_aton(ip.src) + socket.inet_aton(ip.dst)
    ports_ok = ip.proto in (6, 17) and ip.ihl == 5
    if ports_ok:
        l4h = pkt[TCP] if ip.proto == 6 else pkt[UDP]
        rec += pack_ports(int(l4h.sport), int(l4h.dport))
    else:
        rec += b"\x00" * 3
    flags = int(pkt[TCP].flags) & 0xFF if (ip.proto == 6 and ip.ihl == 5) else 0
    rec += bytes([ip.proto, ip.ttl & 0xFF])     # proto(1) TTL(1)
    rec += int(ip.len).to_bytes(2, "big")       # totalLen(2 BE)
    rec += bytes([flags])                        # tcpFlags(1)
    return rec


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
