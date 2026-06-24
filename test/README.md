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
| `program_fpga.sh` / `.tcl` | JTAG-program the bitfile (default: `au250_graph_v2`) |
| `graph_common.py` | shared 5-tuple generation + frame parser (matches `graph_aggregator.sv`) |
| `graph_inject.py` | send N known IPv4 packets on an interface |
| `graph_verify.py` | parse captured frames, validate descriptor + records (pass/fail) |
| `graph_dump.py` | pretty-print the descriptor + 5-tuple records of captured frames |
| `run_graph_test.sh` | orchestrates ns setup → capture → inject → verify → cleanup |
| `graph_fields_test.py` / `run_fields_test.sh` | focused v2 field check (TCP flags / length / TTL) |

## Build the bitfile

The bitfile is built in the **open-nic-shell** tree (it consumes this plugin via
`-user_plugin`; nothing here builds it). One time, ~4–6 h:

```bash
setup-vivado && cd ~/research/open-nic-shell/script
rm -rf ~/research/open-nic-shell/build/au250_graph_v2
nohup vivado -mode batch -source build.tcl \
  -tclargs -board au250 -num_cmac_port 2 -num_phys_func 2 \
           -tag graph_v2 -impl 1 \
           -user_plugin /home/chettige/research/open-nic-graph-plugin \
  > ~/research/open-nic-logs/build_graph_v2.log 2>&1 &
```

Produces `build/au250_graph_v2/.../impl_1/open_nic_shell.bit` — the default
`program_fpga.sh` programs. (Run the cocotb sim in `../box_250mhz/tb/` first.)

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

### Field-extraction test (flags / length / TTL)

`run_graph_test.sh` uses fixed-length UDP, so it does not exercise the v2
per-packet fields. `run_fields_test.sh` injects a small, deliberately varied
set (TCP flags S/SA/A/FA/PA/R/FPU/none, lengths 28..1440 crossing the 256-byte
boundary, TTL 1..255, UDP/ICMP) and checks each emitted record's
`tcpFlags / totalLen / TTL / ports` field-by-field (records map back by unique
src IP, so mismatches name the offending field):

```bash
sudo ./run_fields_test.sh ens4f0 ens4f1     # capture left at /tmp/graph_fields.pcap
```

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

`graph_dump.py -v` prints, per frame (ports are FloatingEncoder-decoded, so
values above 1023 are quantized):

```
Frame #0  seq=20  count=91  drop_count=0  flags=0x00(full)  v2  (1488 bytes)
    [  0] 10.1.0.0       :0     -> 10.2.0.0       :1024   UDP   ttl=1   len=92    flags=0x00
    [  1] 10.1.0.1       :1     -> 10.2.0.1       :1025   UDP   ttl=2   len=92    flags=0x00
    ...
```

### Frame byte layout (for reading raw hex)

```
byte 0..5    dst MAC          byte 16..19  drop_count (BE)
byte 6..11   src MAC          byte 20..23  frame_seq  (BE)
byte 12..13  EtherType 0x88B5 byte 24      flags (bit0 partial, bit1 drops)
byte 14..15  record count K   byte 25      version (0x02)
                              byte 26..31  reserved
byte 32..    K x 16-byte records (v2 layout):
             srcIP(4) dstIP(4)
             ports(3) = two 12-bit FloatingEncoder codes packed:
               b8 = src[11:4]  b9 = {src[3:0],dst[11:8]}  b10 = dst[7:0]
             proto(1) TTL(1) totalLen(2 BE) tcpFlags(1)
```

FloatingEncoder: `value = mantissa(10b) << (exp(2b) * 2)`. Ports 0–1023 are
exact (well-known); above that they floor to a coarser grid (stride ×4/×16/×64).

## Interpreting failures

| Result | Meaning |
|--------|---------|
| `PASS` | extraction + aggregation correct, `drop_count==0`, seq contiguous |
| `only X/N matched ... garbled records` | record contents wrong → setup-timing path biting (v2 build WNS −0.181 ns, though all violating paths are stock QDMA, not our logic — so unlikely); fix is to pipeline the `fifo→frame_buf` read + rebuild |
| `WARN: drop_count=N` | FIFO overflowed (rate too high / backpressure) — functional match may still pass |
| `frame_seq gap` | a whole frame lost on the C2H/host path, not in the FPGA |
| `no 0x88B5 frames found` | plugin not emitting — check programming, carrier, driver, reboot |

## Later: throughput / drop stress

Filtering (ARP → no record, ICMP → zeroed ports/flags) is already covered by the
cocotb `run_test_filtering` and the hardware `run_fields_test.sh`. Still open: a
sustained-load test that exercises the record FIFO and watches `drop_count` /
flags climb. Note the host TX path alone cannot reach line rate, so this needs a
dedicated approach (to be planned separately).
