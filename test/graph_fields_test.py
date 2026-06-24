#!/usr/bin/env python3
"""Focused field-extraction test for graph plugin v2.

Unlike run_graph_test.sh (bulk 5-tuple aggregation, fixed length / UDP), this
injects a *small, deliberately varied* set of packets to confirm the new v2
record fields are extracted correctly on hardware:

  - tcpFlags : SYN, SYN-ACK, ACK, FIN-ACK, PSH-ACK, RST, FIN-PSH-URG, none,
               and 0 for UDP/ICMP
  - totalLen : sweeps 28..1440 bytes, crossing the 255/256 byte boundary so
               both length bytes are exercised
  - TTL      : 1, 32, 64, 77, 100, 128, 200, 254, 255
  - ports    : FloatingEncoder round-trip (exact <1024, quantized above)

Each packet gets a unique src IP (10.77.0.<i>) so captured records map back to
the injected case regardless of ordering or stray kernel traffic. Per-field
diffs are printed, so a wrong byte points straight at the offending field.

Two modes (driven by run_fields_test.sh across the two namespaces):
  ./graph_fields_test.py --inject -i ens4f0
  ./graph_fields_test.py --verify -f /tmp/graph_fields.pcap
"""

import argparse
import socket
import sys

import graph_common as gc

# (l4, flags, payload_len, ttl, sport, dport)
CASES = [
    ("tcp", "S",   0,    1,   80,    443),    # SYN, min len, well-known ports (exact)
    ("tcp", "SA",  20,   32,  1024,  1025),   # SYN-ACK
    ("tcp", "A",   100,  64,  3306,  5432),   # ACK, quantized ports
    ("tcp", "FA",  200,  77,  8080,  8443),   # FIN-ACK
    ("tcp", "PA",  235,  100, 40000, 50000),  # PSH-ACK, len 275 (>255)
    ("tcp", "R",   600,  128, 12345, 54321),  # RST, len 640
    ("tcp", "FPU", 1400, 200, 22,    33),     # FIN-PSH-URG, len 1440 (MTU-ish)
    ("tcp", "",    50,   254, 1000,  2000),   # no flags set -> 0
    ("udp", None,  0,    64,  53,    123),    # UDP, flags must be 0, len 28
    ("udp", None,  300,  255, 5000,  6000),   # UDP, len 328 (>255)
    ("icmp", None, 64,   211, 0,     0),      # ICMP -> ports zeroed, flags 0
]

SRC = "10.77.0.%d"
DST = "10.88.0.%d"
INJ_SRC_MAC = "aa:bb:cc:dd:ee:ff"
INJ_DST_MAC = "11:22:33:44:55:66"


def make_pkt(i):
    from scapy.all import Ether, IP, UDP, TCP, ICMP
    l4, flags, plen, ttl, sport, dport = CASES[i]
    if l4 == "tcp":
        l4_hdr = TCP(sport=sport, dport=dport, flags=flags)
    elif l4 == "udp":
        l4_hdr = UDP(sport=sport, dport=dport)
    else:
        l4_hdr = ICMP()
    pkt = Ether(src=INJ_SRC_MAC, dst=INJ_DST_MAC) \
        / IP(src=SRC % i, dst=DST % i, ttl=ttl) / l4_hdr / (b"\xab" * plen)
    return Ether(bytes(pkt))  # finalize lengths/proto/checksums


def expected_fields(i):
    """Decoded fields the record for CASES[i] should carry (from the packet)."""
    from scapy.all import IP, TCP, UDP
    pkt = make_pkt(i)
    ip = pkt[IP]
    tcp_or_udp = ip.proto in (6, 17) and ip.ihl == 5
    if tcp_or_udp:
        l4 = pkt[TCP] if ip.proto == 6 else pkt[UDP]
        sport = gc.floating_decode(gc.floating_encode(int(l4.sport)))
        dport = gc.floating_decode(gc.floating_encode(int(l4.dport)))
    else:
        sport = dport = 0
    flags = int(pkt[TCP].flags) & 0xFF if (ip.proto == 6 and ip.ihl == 5) else 0
    return dict(src=ip.src, dst=ip.dst, proto=ip.proto, ttl=ip.ttl & 0xFF,
                length=int(ip.len), flags=flags, sport=sport, dport=dport)


def decode_record(rec):
    """Decode a captured 16-byte v2 record into the same field dict."""
    sport, dport = gc.unpack_ports(rec[8:11])
    return dict(src=socket.inet_ntoa(rec[0:4]), dst=socket.inet_ntoa(rec[4:8]),
                proto=rec[11], ttl=rec[12],
                length=int.from_bytes(rec[13:15], "big"), flags=rec[15],
                sport=sport, dport=dport)


def do_inject(iface):
    from scapy.all import sendp
    pkts = [make_pkt(i) for i in range(len(CASES))]
    print("Injecting %d field-test packets on %s ..." % (len(pkts), iface))
    sendp(pkts, iface=iface, inter=0.002, verbose=False)
    print("Done.")
    return 0


def do_verify(pcap):
    from scapy.all import rdpcap
    # Gather all emitted records, keyed by src IP (unique per injected case).
    by_src = {}
    for p in rdpcap(pcap):
        try:
            f = gc.parse_frame(bytes(p))
        except AssertionError as e:
            print("FAIL: malformed aggregated frame: %s" % e)
            return 1
        if f is None:
            continue
        for rec in f["records"]:
            d = decode_record(rec)
            by_src.setdefault(d["src"], d)  # first occurrence wins

    fields = ("proto", "ttl", "length", "flags", "sport", "dport")
    ok = True
    print("%-11s %-5s %-4s %-6s %-6s %-6s %-6s  result"
          % ("src", "proto", "ttl", "len", "flags", "sport", "dport"))
    for i in range(len(CASES)):
        exp = expected_fields(i)
        got = by_src.get(exp["src"])
        if got is None:
            print("%-11s  -- no record captured --              MISSING" % exp["src"])
            ok = False
            continue
        bad = [f for f in fields if exp[f] != got[f]]
        status = "OK" if not bad else "MISMATCH:%s" % ",".join(bad)
        print("%-11s %-5d %-4d %-6d 0x%02x   %-6d %-6d  %s"
              % (exp["src"], got["proto"], got["ttl"], got["length"],
                 got["flags"], got["sport"], got["dport"], status))
        if bad:
            for f in bad:
                print("      %-7s expected %s, got %s" % (f, exp[f], got[f]))
            ok = False

    print()
    if ok:
        print("PASS: all %d field-test packets extracted correctly." % len(CASES))
        return 0
    print("FAIL: one or more fields mis-extracted (see MISMATCH rows above).")
    return 1


def main():
    ap = argparse.ArgumentParser(description="Graph plugin v2 field-extraction test")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inject", action="store_true", help="send the test packets")
    mode.add_argument("--verify", action="store_true", help="check captured frames")
    ap.add_argument("-i", "--iface", help="interface to inject on")
    ap.add_argument("-f", "--pcap", help="captured pcap to verify")
    args = ap.parse_args()

    if args.inject:
        if not args.iface:
            ap.error("--inject requires -i/--iface")
        return do_inject(args.iface)
    if not args.pcap:
        ap.error("--verify requires -f/--pcap")
    return do_verify(args.pcap)


if __name__ == "__main__":
    sys.exit(main())
