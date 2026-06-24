"""Cocotb tests for the graph plugin (p2p_250mhz with graph_aggregator).

RX path (network ingress -> host): packets sent into s_axis_adap_rx are
parsed; each IPv4 packet yields one 16-byte record (v2 layout)
    srcIP(4) dstIP(4) ports(3, FloatingEncoder) proto(1) TTL(1) totalLen(2) flags(1)
packed into host-bound frames (32-byte prefix = 2 aligned slots):
    bytes 0..13  Ethernet header (DST_MAC, SRC_MAC, ETH_TYPE=0x88B5)
    bytes 14..15 record count K (big-endian)
    bytes 16..19 drop_count   bytes 20..23 frame_seq
    byte  24     flags (bit0 partial, bit1 drops)   byte 25 version (0x02)
    bytes 26..31 reserved
    bytes 32..   K x 16-byte records
A frame flushes at MAX_RECORDS (91) or after the idle timeout
(AGGR_FLUSH_TIMEOUT=256 cycles in the sim wrapper).

TX path (host -> network) remains pass-through and is checked unchanged.
"""

import itertools
import logging
import socket

import cocotb
from cocotb.clock import Clock
from cocotb.regression import TestFactory
from cocotb.triggers import RisingEdge
from cocotbext.axi import (AxiLiteBus, AxiLiteMaster, AxiStreamBus,
                           AxiStreamFrame, AxiStreamSink, AxiStreamSource)
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether

AGG_ETH_TYPE = 0x88B5
AGG_DST_MAC = bytes.fromhex('021122334455')
AGG_SRC_MAC = bytes.fromhex('02aabbccddee')
PREFIX_LEN = 32
RECORD_LEN = 16
MAX_RECORDS = 91
HDR_VERSION = 2

# UDP packet with 128B payload (TX pass-through check)
PACKET = Ether(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66') \
    / IP(src='1.1.1.1', dst='2.2.2.2') \
    / UDP(sport=11111, dport=22222) / (b'\xaa' * 128)


def floating_encode(v):
    """16-bit value -> 12-bit FloatingEncoder code (mirrors the RTL function)."""
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


def make_ipv4_pkt(idx, l4='udp', payload=64):
    """Synthetic IPv4 packet with a distinctive, index-derived 5-tuple.

    Ports span <1024 (FloatingEncoder-exact) and >1023 (quantized); TTL and
    TCP flags vary per index so the new v2 fields are actually exercised.
    """
    src_ip = '10.1.{}.{}'.format((idx >> 8) & 0xFF, idx & 0xFF)
    dst_ip = '10.2.{}.{}'.format((idx >> 8) & 0xFF, idx & 0xFF)
    sport = idx % 2000             # mixes exact (<1024) and quantized
    dport = 1024 + (idx % 4000)    # quantized bands 1-2
    ttl = 1 + (idx % 254)
    if l4 == 'udp':
        l4_hdr = UDP(sport=sport, dport=dport)
    elif l4 == 'tcp':
        flags = ['S', 'SA', 'A', 'FA', 'PA', 'R'][idx % 6]
        l4_hdr = TCP(sport=sport, dport=dport, flags=flags)
    else:
        l4_hdr = ICMP()
    pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='11:22:33:44:55:66') \
        / IP(src=src_ip, dst=dst_ip, ttl=ttl) / l4_hdr / (b'\xab' * payload)
    # Round-trip through bytes so scapy finalizes lengths/proto fields
    return Ether(bytes(pkt))


def expected_record(pkt):
    """The 16-byte v2 record the aggregator should emit for this packet."""
    ip = pkt[IP]
    rec = socket.inet_aton(ip.src) + socket.inet_aton(ip.dst)
    ports_ok = ip.proto in (6, 17) and ip.ihl == 5
    if ports_ok:
        l4 = pkt[TCP] if ip.proto == 6 else pkt[UDP]
        rec += pack_ports(int(l4.sport), int(l4.dport))
    else:
        rec += b'\x00' * 3  # ports zeroed for non-TCP/UDP or IHL!=5
    flags = int(pkt[TCP].flags) & 0xFF if (ip.proto == 6 and ip.ihl == 5) else 0
    rec += bytes([ip.proto, ip.ttl & 0xFF])     # proto(1) TTL(1)
    rec += int(ip.len).to_bytes(2, 'big')       # totalLen(2 BE)
    rec += bytes([flags])                        # tcpFlags(1)
    return rec


async def collect_records(log, sink, n_expected):
    """Receive aggregated frames until n_expected records are gathered.

    Asserts per-frame integrity (header fields, count vs length) and
    returns the concatenated records in arrival order.
    """
    records = []
    exp_seq = 0
    while len(records) < n_expected:
        frame = await sink.recv()
        data = bytes(frame.tdata)
        assert len(data) >= PREFIX_LEN, 'frame shorter than prefix'
        # slot 0: link header
        assert data[0:6] == AGG_DST_MAC, 'bad aggregator DST MAC'
        assert data[6:12] == AGG_SRC_MAC, 'bad aggregator SRC MAC'
        assert data[12:14] == AGG_ETH_TYPE.to_bytes(2, 'big'), \
            'bad aggregator ethertype'
        count = int.from_bytes(data[14:16], 'big')
        # slot 1: status descriptor
        drop = int.from_bytes(data[16:20], 'big')
        seq = int.from_bytes(data[20:24], 'big')
        flags = data[24]
        version = data[25]
        assert 1 <= count <= MAX_RECORDS, 'record count out of range'
        assert len(data) == PREFIX_LEN + RECORD_LEN * count, \
            'frame length does not match record count'
        assert version == HDR_VERSION, 'bad header version'
        assert drop == 0, 'unexpected dropped records: {}'.format(drop)
        assert data[26:32] == b'\x00' * 6, 'reserved bytes not zero'
        # flags bit0 = partial (timeout-flushed), bit1 = drops seen
        assert (flags & 0x01) == (0x01 if count < MAX_RECORDS else 0x00), \
            'partial flag inconsistent with record count'
        assert (flags & 0x02) == 0x00, 'drop flag set unexpectedly'
        assert seq == exp_seq, \
            'frame_seq gap: got {}, expected {}'.format(seq, exp_seq)
        exp_seq += 1
        log.info('Frame seq=%d: %d records, %d bytes, drop=%d, flags=0x%02x',
                 seq, count, len(data), drop, flags)
        for j in range(count):
            start = PREFIX_LEN + RECORD_LEN * j
            records.append(data[start:start + RECORD_LEN])
    return records


class TB:
    def __init__(self, dut):
        self.dut = dut

        self.log = logging.getLogger('cocotb.tb')
        self.log.setLevel(logging.DEBUG)
        self.log.info('Got DUT: {}'.format(dut))

        cocotb.start_soon(Clock(dut.axis_aclk, 2, units='ns').start())
        cocotb.start_soon(Clock(dut.axil_aclk, 4, units='ns').start())

        # Note, cocotb by default assumes reset signals are active high, while
        # open nic shell has reset signals active low. This is why we pass
        # reset_active_level=False.
        self.source_tx = [AxiStreamSource(
            AxiStreamBus.from_prefix(
                dut, 's_axis_qdma_h2c_port{}'.format(port)),
            dut.axis_aclk, dut.p2p_250mhz_inst.axil_aresetn,
            reset_active_level=False)
            for port in [0, 1]]
        self.source_rx = [AxiStreamSource(
            AxiStreamBus.from_prefix(
                dut, 's_axis_adap_rx_250mhz_port{}'.format(port)),
            dut.axis_aclk, dut.p2p_250mhz_inst.axil_aresetn,
            reset_active_level=False)
            for port in [0, 1]]
        self.sink_tx = [AxiStreamSink(
            AxiStreamBus.from_prefix(
                dut, 'm_axis_adap_tx_250mhz_port{}'.format(port)),
            dut.axis_aclk, dut.p2p_250mhz_inst.axil_aresetn,
            reset_active_level=False)
            for port in [0, 1]]
        self.sink_rx = [AxiStreamSink(
            AxiStreamBus.from_prefix(
                dut, 'm_axis_qdma_c2h_port{}'.format(port)),
            dut.axis_aclk, dut.p2p_250mhz_inst.axil_aresetn,
            reset_active_level=False)
            for port in [0, 1]]
        self.control = AxiLiteMaster(
            AxiLiteBus.from_prefix(dut, 's_axil'),
            dut.axil_aclk, dut.p2p_250mhz_inst.axil_aresetn,
            reset_active_level=False)

    def set_idle_generator(self, generator=None):
        if generator:
            for source in self.source_tx + self.source_rx:
                source.set_pause_generator(generator())

    def set_backpressure_generator(self, generator=None):
        if generator:
            for sink in self.sink_tx + self.sink_rx:
                sink.set_pause_generator(generator())

    async def reset(self):
        self.dut.mod_rstn.setimmediatevalue(1)
        # mod rst signals are synced with the axi_aclk
        await RisingEdge(self.dut.axil_aclk)
        await RisingEdge(self.dut.axil_aclk)
        self.dut.mod_rstn.value = 0
        await RisingEdge(self.dut.axil_aclk)
        await RisingEdge(self.dut.axil_aclk)
        self.dut.mod_rstn.value = 1
        await RisingEdge(self.dut.mod_rst_done)


async def check_passthrough(tb, source, sink, test_packet=PACKET):
    """TX path: packets on source should arrive at sink unmodified."""
    test_frame = AxiStreamFrame(bytes(test_packet), tuser=0)
    await source.send(test_frame)
    tb.log.info('Frame sent')

    rx_frame = await sink.recv()
    assert rx_frame.tdata == test_frame.tdata

    assert sink.empty()


async def run_test(dut, idle_inserter=None, backpressure_inserter=None):

    tb = TB(dut)

    await tb.reset()

    tb.set_idle_generator(idle_inserter)
    tb.set_backpressure_generator(backpressure_inserter)

    # TX path (host -> network) is still pass-through
    await check_passthrough(tb, tb.source_tx[0], tb.sink_tx[0], PACKET)
    await check_passthrough(tb, tb.source_tx[1], tb.sink_tx[1], PACKET)

    # RX path (network -> host) aggregates: 200 packets = two full frames
    # of 91 records plus an 18-record tail flushed by the idle timeout
    n_pkts = 200
    pkts = [make_ipv4_pkt(i) for i in range(n_pkts)]
    expected = [expected_record(p) for p in pkts]

    for pkt in pkts:
        await tb.source_rx[0].send(AxiStreamFrame(bytes(pkt), tuser=0))

    records = await collect_records(tb.log, tb.sink_rx[0], n_pkts)
    assert records == expected, 'aggregated records mismatch'

    # Both interfaces carry an aggregator: same check on port 1
    for pkt in pkts[:8]:
        await tb.source_rx[1].send(AxiStreamFrame(bytes(pkt), tuser=0))
    records = await collect_records(tb.log, tb.sink_rx[1], 8)
    assert records == expected[:8], 'port1 aggregated records mismatch'

    await RisingEdge(dut.axis_aclk)
    await RisingEdge(dut.axis_aclk)


async def run_test_filtering(dut):
    """Non-IPv4 is dropped without a record; non-TCP/UDP zeroes the ports."""
    tb = TB(dut)

    await tb.reset()

    udp0 = make_ipv4_pkt(0, l4='udp')
    udp1 = make_ipv4_pkt(1, l4='udp')
    arp = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ff:ff:ff:ff:ff') \
        / ARP(psrc='10.1.0.0', pdst='10.2.0.0')
    icmp = make_ipv4_pkt(2, l4='icmp')
    tcp0 = make_ipv4_pkt(3, l4='tcp')

    sent = [udp0, udp1, arp, icmp, tcp0]
    # ARP must NOT produce a record; ICMP record has zero ports, proto=1
    expected = [expected_record(p) for p in [udp0, udp1, icmp, tcp0]]

    for pkt in sent:
        await tb.source_rx[0].send(AxiStreamFrame(bytes(pkt), tuser=0))

    records = await collect_records(tb.log, tb.sink_rx[0], len(expected))
    assert records == expected, 'filtering records mismatch'

    icmp_rec = records[2]
    assert icmp_rec[8:11] == b'\x00' * 3, 'ICMP ports not zeroed'
    assert icmp_rec[11] == 1, 'ICMP protocol byte wrong'
    assert icmp_rec[12] == icmp[IP].ttl, 'ICMP TTL wrong'
    assert icmp_rec[13:15] == int(icmp[IP].len).to_bytes(2, 'big'), \
        'ICMP totalLen wrong'
    assert icmp_rec[15] == 0, 'ICMP TCP-flags byte not zero'

    tcp_rec = records[3]
    assert tcp_rec[8:11] != b'\x00' * 3, 'TCP ports unexpectedly zeroed'
    assert tcp_rec[15] == (int(tcp0[TCP].flags) & 0xFF), 'TCP flags wrong'

    await RisingEdge(dut.axis_aclk)
    await RisingEdge(dut.axis_aclk)


def cycle_pause():
    return itertools.cycle([1, 1, 1, 0])


if cocotb.SIM_NAME:
    factory = TestFactory(run_test)
    factory.add_option('idle_inserter', [None, cycle_pause])
    factory.add_option('backpressure_inserter', [None, cycle_pause])
    factory.generate_tests()

    factory = TestFactory(run_test_filtering)
    factory.generate_tests()
