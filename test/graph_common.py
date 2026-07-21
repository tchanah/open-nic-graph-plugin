"""Shared definitions for the graph-plugin hardware test (inject + verify).

Keeps the synthetic 5-tuple generation and the aggregated-frame parser in one
place so graph_inject.py and graph_verify.py can never drift apart. The frame
format here must match graph_aggregator.sv:

  slot 0 (0..15):   Eth(14) + record count K (BE)
  slot 1 (16..31):  drop_count(4 BE) | frame_seq(4 BE) | flags(1) |
                    version(1) | reserved(6)
  bytes 32.. :      K x 32-byte records (v3 layout, big-endian):
                    REC_FIXED(8) srcIP(8, 64-bit right-aligned)
                    dstIP(8, 64-bit right-aligned)
                    protoCode(4b)|srcPort(12b)  flagsCode(4b)|dstPort(12b)
                    pktLen(4, 32-bit right-aligned)
"""

import socket

# Must match graph_aggregator.sv parameters / format.
ETH_TYPE = 0x88B5
PREFIX_LEN = 32
RECORD_LEN = 32
MAX_RECORDS = 45
HDR_VERSION = 4  # v4 = bump-in-wire (network egress); matches graph_aggregator.sv
REC_FIXED = bytes.fromhex("8100FD0000000001")  # MsgHdr tag, record bytes 0-7 (matches graph_aggregator.sv)

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


def encode_protocol(proto):
    """IP protocol number -> 4-bit one-hot code (mirrors graph_aggregator.sv)."""
    return {6: 0x8, 17: 0x4, 1: 0x2}.get(proto, 0x1)


def encode_tcp_flags(flags):
    """TCP flag byte -> 4-bit {ACK,RST,SYN,FIN} code (mirrors graph_aggregator.sv)."""
    code = 0
    if flags & 0x10:
        code |= 0x8   # ACK
    if flags & 0x04:
        code |= 0x4   # RST
    if flags & 0x02:
        code |= 0x2   # SYN
    if flags & 0x01:
        code |= 0x1   # FIN
    return code


def _build_record(src_ip, dst_ip, proto, ip_len, sport, dport, tcp_flags,
                  ports_ok, flags_ok):
    """Assemble one 32-byte v3 record (matches graph_aggregator.sv byte layout)."""
    proto_code = encode_protocol(proto)
    sfp = floating_encode(sport) if ports_ok else 0
    dfp = floating_encode(dport) if ports_ok else 0
    fcode = encode_tcp_flags(tcp_flags) if flags_ok else 0
    rec = bytearray(REC_FIXED)                                    # 0-7   fixed tag
    rec += b"\x00\x00\x00\x00" + socket.inet_aton(src_ip)         # 8-15  srcIP (BE)
    rec += b"\x00\x00\x00\x00" + socket.inet_aton(dst_ip)         # 16-23 dstIP (BE)
    rec += bytes([(proto_code << 4) | ((sfp >> 8) & 0xF), sfp & 0xFF,   # 24-25 word A
                  (fcode << 4) | ((dfp >> 8) & 0xF), dfp & 0xFF])       # 26-27 word B
    rec += b"\x00\x00" + int(ip_len).to_bytes(2, "big")          # 28-31 pktLen (BE)
    return bytes(rec)


def decode_record(rec):
    """Decode a 32-byte v3 record into a field dict (for dump / field tests)."""
    return dict(
        fixed=bytes(rec[0:8]),
        src=socket.inet_ntoa(rec[12:16]),
        dst=socket.inet_ntoa(rec[20:24]),
        proto_code=rec[24] >> 4,
        sport=floating_decode(((rec[24] & 0xF) << 8) | rec[25]),
        flags_code=rec[26] >> 4,
        dport=floating_decode(((rec[26] & 0xF) << 8) | rec[27]),
        length=int.from_bytes(rec[28:32], "big"),
    )


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
    """The 32-byte v3 record the aggregator should emit for make_packet(i).

    Built by parsing make_packet(i) so it can never drift from the injector.
    """
    from scapy.all import IP, TCP, UDP
    pkt = make_packet(i, l4)
    ip = pkt[IP]
    ports_ok = ip.proto in (6, 17) and ip.ihl == 5
    flags_ok = ip.proto == 6 and ip.ihl == 5
    if ports_ok:
        l4h = pkt[TCP] if ip.proto == 6 else pkt[UDP]
        sport, dport = int(l4h.sport), int(l4h.dport)
    else:
        sport = dport = 0
    tcp_flags = int(pkt[TCP].flags) & 0xFF if flags_ok else 0
    return _build_record(ip.src, ip.dst, ip.proto, ip.len, sport, dport,
                         tcp_flags, ports_ok, flags_ok)


def record_for_packet(pkt):
    """The 32-byte v3 record the aggregator should emit for an arbitrary packet.

    Mirrors the RTL extraction (and the cocotb golden model) for a real captured
    Ether/IP packet rather than a synthetic make_packet(i). Returns None when the
    plugin would emit no record (non-IPv4), so callers can build an expected list
    straight from a replayed pcap.
    """
    from scapy.all import IP, TCP, UDP
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if int(ip.version) != 4:
        return None
    ports_ok = ip.proto in (6, 17) and ip.ihl == 5
    flags_ok = ip.proto == 6 and ip.ihl == 5
    if ports_ok:
        l4h = pkt[TCP] if ip.proto == 6 else pkt[UDP]
        sport, dport = int(l4h.sport), int(l4h.dport)
    else:
        sport = dport = 0
    tcp_flags = int(pkt[TCP].flags) & 0xFF if flags_ok else 0
    return _build_record(ip.src, ip.dst, ip.proto, ip.len, sport, dport,
                         tcp_flags, ports_ok, flags_ok)


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
