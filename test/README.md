# Graph plugin — hardware test

Functional loopback test for the graph aggregator plugin on the Alveo U250
(QSFP0↔QSFP1 back-to-back cable). It drives the **actual plugin behaviour** —
5-tuple extraction + aggregation — not a plain link loopback.

> Note: the old `open-nic-logs/loopback_test.sh` (ICMP ping) no longer works
> with this bitfile. The plugin consumes every IPv4 packet on the RX path and
> emits aggregated 0x88B5 frames instead, so ping gets no echo reply. Use the
> scripts here.

## Flow

```
graph_inject.py  → known IPv4 packets out ens4f0
       │            ↓ cable → CMAC1 RX
   the plugin     → extract 5-tuple, drop original, pack into 0x88B5 frames
       │            ↓ QDMA C2H → ens4f1
graph_verify.py  → capture 0x88B5 frames, validate the 32-byte descriptor
                    (count, drop_count, frame_seq, flags, version) and confirm
                    every injected 5-tuple appears, in order, as a record
```

## Files

| File | Role |
|------|------|
| `program_fpga.sh` / `.tcl` | JTAG-program the bitfile (default: `au250_graph_v1`) |
| `graph_common.py` | shared 5-tuple generation + frame parser (matches `graph_aggregator.sv`) |
| `graph_inject.py` | send N known IPv4 packets on an interface |
| `graph_verify.py` | parse captured frames, validate descriptor + records (pass/fail) |
| `graph_dump.py` | pretty-print the descriptor + 5-tuple records of captured frames |
| `run_graph_test.sh` | orchestrates ns setup → capture → inject → verify → cleanup |

## Prerequisites

- `pip3 install --user scapy` (already installed for the cocotb sim)
- `tcpdump`, root access
- Vivado sourced (`setup-vivado`) for programming only

## Run

```bash
# 1. Program + warm reboot
setup-vivado
./program_fpga.sh                 # or ./program_fpga.sh /path/to/other.bit
sudo reboot                       # warm reboot — never PCIe rescan

# 2. After reboot: load driver (generic script)
~/research/open-nic-logs/load_driver.sh

# 3. Run the functional test
sudo ./run_graph_test.sh ens4f0 ens4f1 200
```

`PASS` means all injected 5-tuples were extracted and aggregated correctly.
The capture is left at `/tmp/graph_agg.pcap` for inspection (below).

## Inspecting the output frames

The aggregated frames use a custom EtherType (`0x88B5`), so standard tools
show raw bytes only. Three ways to look at them:

```bash
# 1. Decoded, human-readable (descriptor + every 5-tuple record)
sudo ./graph_dump.py -f /tmp/graph_agg.pcap -v | less
sudo ./graph_dump.py -f /tmp/graph_agg.pcap -c 1 -v     # just the first frame
sudo ./graph_dump.py -f /tmp/graph_agg.pcap             # one-line summary per frame

# 2. Live decode while injecting (run in the capture namespace)
sudo ip netns exec ns_graph_cap ./graph_dump.py -i ens4f1 -v

# 3. Raw hex via tcpdump
tcpdump -r /tmp/graph_agg.pcap -nn -e -XX -c 1
```

`graph_dump.py -v` prints, per frame:

```
Frame #0  seq=20  count=91  drop_count=0  flags=0x00(full)  v1  (1488 bytes)
    [  0] 10.1.0.0       :1024  -> 10.2.0.0       :2048   UDP
    [  1] 10.1.0.1       :1025  -> 10.2.0.1       :2049   UDP
    ...
```

### Frame byte layout (for reading raw hex)

```
byte 0..5    dst MAC          byte 16..19  drop_count (BE)
byte 6..11   src MAC          byte 20..23  frame_seq  (BE)
byte 12..13  EtherType 0x88B5 byte 24      flags (bit0 partial, bit1 drops)
byte 14..15  record count K   byte 25      version (0x01)
                              byte 26..31  reserved
byte 32..    K x 16-byte records:
             srcIP(4) dstIP(4) srcPort(2 BE) dstPort(2 BE) proto(1) pad(3)
```

## Interpreting failures

| Result | Meaning |
|--------|---------|
| `PASS` | extraction + aggregation correct, `drop_count==0`, seq contiguous |
| `only X/N matched ... garbled records` | record contents wrong → likely the `fifo→frame_buf` setup-timing path (WNS −0.131 ns) biting; needs the FIFO-pipeline RTL fix + rebuild |
| `WARN: drop_count=N` | FIFO overflowed (rate too high / backpressure) — functional match may still pass |
| `frame_seq gap` | a whole frame lost on the C2H/host path, not in the FPGA |
| `no 0x88B5 frames found` | plugin not emitting — check programming, carrier, driver, reboot |

## Later: stress test

A rate-ramp / drop-stress mode (push toward line rate, watch `drop_count` and
the flags climb) and a filtering check (ARP → no record, ICMP → zeroed ports)
will be added on top of these once basic functionality is confirmed.
