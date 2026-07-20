#!/usr/bin/env python3
"""Reachability sweep across graph-plugin ports through a switch.

Each listed interface is a graph-plugin RX port: any IPv4 packet arriving on it
is extracted into a 0x88B5 aggregation frame delivered to that port's host
interface. TX is pass-through, so we can source packets out any port.

Method: tag every source port with a unique srcIP, broadcast a burst out one
port at a time, and sniff 0x88B5 on all ports. Each captured record's decoded
srcIP tells us which source reached that receiver -> who-reaches-whom matrix.

  sudo ./reachability_sweep.py enp37s0f0 enp37s0f1 enp129s0f0 \
                               enp129s0f1 enp193s0f0 enp193s0f1

Uses one sniffer PER interface (never relies on scapy's sniffed_on), and prints
per-receiver capture counts so a blank matrix is diagnosable. Needs scapy as
root. srcIP is always recorded by the plugin for any IPv4 packet.
"""
import argparse
import logging
import sys
import time
from collections import defaultdict

logging.getLogger("scapy").setLevel(logging.CRITICAL)  # silence optional-layer load noise

import graph_common as gc  # noqa: E402

try:
    from scapy.all import Ether, IP, UDP, sendp, AsyncSniffer  # noqa: E402
except Exception as e:  # pragma: no cover
    sys.exit("scapy import failed (%s). Try: sudo pip3 install scapy" % e)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ifaces", nargs="+", help="graph-plugin host interfaces to sweep")
    ap.add_argument("-c", "--count", type=int, default=60, help="packets per source burst")
    ap.add_argument("-w", "--wait", type=float, default=1.5, help="seconds to wait after each burst")
    ap.add_argument("--subnet", default="10.13.37", help="tag subnet; source i uses <subnet>.(i+1)")
    ap.add_argument("--unicast", action="store_true",
                    help="use learned-unicast dst MACs instead of broadcast (tests switches that "
                         "suppress broadcast but forward unicast)")
    ap.add_argument("--raw", action="store_true",
                    help="default/pass-through NIC (not the graph plugin): match raw injected "
                         "frames by srcIP instead of decoding 0x88B5 aggregation frames")
    args = ap.parse_args()

    ifaces = args.ifaces
    n = len(ifaces)
    tag_ip = {i: "%s.%d" % (args.subnet, i + 1) for i in range(n)}
    ip_to_src = {v: k for k, v in tag_ip.items()}
    dst_ip = "%s.254" % args.subnet

    received = defaultdict(set)   # receiver iface -> set(source idx seen)
    frames = defaultdict(int)     # receiver iface -> count of 0x88B5 frames
    recs = defaultdict(int)       # receiver iface -> count of records
    tagged = defaultdict(int)     # receiver iface -> records matching our tags

    def make_handler(rcv):
        def handle(pkt):
            if args.raw:
                # default/pass-through NIC: the injected frame arrives verbatim.
                if IP in pkt:
                    frames[rcv] += 1
                    src = ip_to_src.get(pkt[IP].src)
                    if src is not None:
                        recs[rcv] += 1
                        tagged[rcv] += 1
                        received[rcv].add(src)
                return
            # graph plugin: decode the 0x88B5 aggregation frame + its records.
            try:
                f = gc.parse_frame(bytes(pkt))
            except AssertionError:
                return
            if not f:
                return
            frames[rcv] += 1
            for rec in f["records"]:
                recs[rcv] += 1
                src = ip_to_src.get(gc.decode_record(rec)["src"])
                if src is not None:
                    tagged[rcv] += 1
                    received[rcv].add(src)
        return handle

    # one sniffer per interface -> the receiver identity is fixed by the closure,
    # not by scapy's (unreliable) sniffed_on attribute.
    sniff_filter = "ip" if args.raw else "ether proto 0x88B5"
    print("Sniffing %s on: %s" % ("raw IPv4" if args.raw else "0x88B5", ", ".join(ifaces)))
    sniffers = []
    for iface in ifaces:
        s = AsyncSniffer(iface=iface, filter=sniff_filter,
                         prn=make_handler(iface), store=False)
        s.start()
        sniffers.append(s)
    time.sleep(1.0)

    if args.unicast:
        # each port's real MAC; used as src (so the switch learns it) and as dst target
        macs = {i: open("/sys/class/net/%s/address" % name).read().strip()
                for i, name in enumerate(ifaces)}
        # learn phase: every port emits a frame with its own src MAC so the switch
        # learns which port each MAC lives on (ingress learning happens even if the
        # frame itself isn't forwarded).
        print("[learn] each port announces its MAC")
        for i, src_if in enumerate(ifaces):
            sendp(Ether(src=macs[i], dst="ff:ff:ff:ff:ff:ff") / IP(src=tag_ip[i], dst=dst_ip)
                  / UDP() / (b"\xab" * 16), iface=src_if, count=3, verbose=False)
        time.sleep(1.0)
        # test phase: S -> each other port's unicast MAC
        for i, src_if in enumerate(ifaces):
            for j in range(n):
                if i == j:
                    continue
                burst = [Ether(src=macs[i], dst=macs[j]) / IP(src=tag_ip[i], dst=dst_ip)
                         / UDP(sport=1000 + i, dport=2000) / (b"\xab" * 64)
                         for _ in range(args.count)]
                sendp(burst, iface=src_if, verbose=False)
            print("[inject-unicast] %-12s srcIP=%-12s -> all others x%d" % (src_if, tag_ip[i], args.count))
            time.sleep(args.wait)
    else:
        for i, src_if in enumerate(ifaces):
            burst = [Ether(src=gc.INJ_SRC_MAC, dst="ff:ff:ff:ff:ff:ff")
                     / IP(src=tag_ip[i], dst=dst_ip)
                     / UDP(sport=1000 + i, dport=2000) / (b"\xab" * 64)
                     for _ in range(args.count)]
            print("[inject] %-12s srcIP=%-12s x%d" % (src_if, tag_ip[i], args.count))
            sendp(burst, iface=src_if, verbose=False)
            time.sleep(args.wait)

    time.sleep(args.wait)
    for s in sniffers:
        s.stop()

    # --- matrix: rows = source, cols = receiver ---
    print("\nLegend:")
    for i, name in enumerate(ifaces):
        print("  %d = %s" % (i, name))
    col = "".join("%4d" % j for j in range(n))
    print("\n  src\\recv  %s" % col)
    for i in range(n):
        cells = ""
        for j in range(n):
            if i == j:
                cells += "   ."
            else:
                cells += "   X" if i in received[ifaces[j]] else "   ·"
        print("  %-8d  %s" % (i, cells))
    print("\n  X = source reached receiver   · = not reached   . = self (n/a)")
    total = n * (n - 1)
    got = sum(1 for i in range(n) for j in range(n) if i != j and i in received[ifaces[j]])
    print("  reached %d/%d ordered port-pairs" % (got, total))

    # --- capture diagnostics ---
    print("\nPer-receiver capture (diagnostic):")
    for j, iface in enumerate(ifaces):
        print("  %d %-12s : 0x88B5 frames=%d  records=%d  tag-matched=%d"
              % (j, iface, frames[iface], recs[iface], tagged[iface]))
    if sum(frames.values()) == 0:
        print("  >> No 0x88B5 frames captured anywhere. Either the switch isn't flooding the\n"
              "     broadcast between these ports, or receivers' RX saw no IPv4. Check link lock\n"
              "     (cmac_status.py) and whether the switch forwards broadcast between these ports.")
    elif got == 0:
        print("  >> Frames captured but none matched our tags -- decode/tag mismatch, not the link.")


if __name__ == "__main__":
    main()
