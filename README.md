# OpenNIC Graph Plugin

In-network data extraction for the **Anonymized Network Sensing Graph Challenge**
(Jananthan et al., HPEC 2024; FPGA mapping Han et al., arXiv 2409.07374), running on a
Xilinx **Alveo U250** with the [OpenNIC Shell](https://github.com/Xilinx/open-nic-shell).
On the RX/ingress path it extracts each IPv4 packet's fields, drops the original, and
aggregates many compact records into host-bound `0x88B5` frames via QDMA C2H.

**Status — v3 (`version 0x03`, 32 B record):** built (timing **met**, WNS +0.045 ns),
hardware-verified, and throughput-validated on the real datapath:
- multi-queue **≥100 Mpps min-size, drop-free** (host/PCIe-limited; plugin ~163 Mpps in sim);
- the full **57 GB real scan trace — all 1,073,741,824 packets — streamed drop-free**
  (`drop_count=0`, tag OK, `frame_seq` contiguous), in one pass at **15.20 Mpps / 70.7 s** via
  the lz4-in-RAM, multi-queue `graph_replay` streamer (4.4× the raw-HDD baseline), paced by
  the single reader core (~18 Mpps turbo, ~13.4 Mpps sustained after the CPU's power-limit step).

> **Detailed, reproducible step-by-step guides live in the [wiki](../../wiki)** — this README
> is the concise overview + pointers:
> [OpenNIC Shell Setup](../../wiki/OpenNIC-Shell-Setup-Guide) ·
> [Graph Plugin Testing Guide](../../wiki/Graph-Plugin-Testing-Guide) ·
> [DPDK Load-Generation Setup](../../wiki/DPDK-Load-Generation-Setup).

## What it does

```
network → CMAC RX → extract 5-tuple+meta → aggregate → QDMA C2H → host (EtherType 0x88B5)
```
Logic lives entirely in the **`box_250mhz` RX path** — `graph_aggregator.sv` replaces the RX
pipeline in `p2p_250mhz.sv` (single 250 MHz domain, line-rate at 512 b×250 MHz). `box_322mhz`
and the TX path are untouched pass-through. The shell is consumed unmodified via `-user_plugin`.

## v3 record — 32 B per IPv4 packet (all big-endian)

| Bytes | Field | Notes |
|-------|-------|-------|
| 0–7   | `REC_FIXED` | fixed `MsgHdr` tag `0x8100FD00_00000001` |
| 8–15  | `srcIP` | IPv4 right-aligned in a 64-bit field (high bytes 0) for the gmap/GraphBLAS index |
| 16–23 | `dstIP` | IPv4 right-aligned in a 64-bit field |
| 24–25 | `protoCode(4b)` \| `srcPort(12b)` | proto one-hot {TCP,UDP,ICMP,other}; port = FloatingEncoder |
| 26–27 | `flagsCode(4b)` \| `dstPort(12b)` | flags `{ACK,RST,SYN,FIN}` (TCP only) |
| 28–31 | `pktLen` | IP total length, right-aligned in a 32-bit field |

FloatingEncoder: `value = mantissa(10b) << (exp(2b)·2)` — exact ≤1023, floored above. Ports
zeroed unless `IHL==5 & TCP/UDP`; `flagsCode` unless `IHL==5 & TCP`. Non-IPv4 → no record.

**Output frame (`0x88B5`)** = 32 B prefix (Ethernet header + `drop_count`/`frame_seq`/`flags`/
`version` descriptor) then **K × 32 B** records, `K ≤ 45` (full frame = 1472 B); flushes at 45
records or an idle timeout.

## Repo layout

| Path | Role |
|------|------|
| `graph_aggregator.sv` | extractor (5-tuple + proto/flags codes, FloatingEncoder ports) → 512-deep record FIFO → FILL/PREP/DRAIN packetizer |
| `p2p_250mhz.sv` / `p2p_322mhz.sv` | RX-path instantiation / untouched baseline |
| `build_box_250mhz.tcl` | reads `graph_aggregator.sv` then `p2p_250mhz.sv` |
| `box_250mhz/tb/` | cocotb testbench (Icarus, no Vivado) — 10 tests, byte-exact golden model |
| `test/` | hardware + DPDK test suite (below) |

## Quick start

**Simulation** (fast iteration, no Vivado) — see [Testing Guide §1](../../wiki/Graph-Plugin-Testing-Guide):
```bash
cd box_250mhz/tb && make          # expect TESTS=10 PASS=10 (byte-exact golden model)
```

**Build the bitfile** (in open-nic-shell, ~4–6 h) — see [Testing Guide §2](../../wiki/Graph-Plugin-Testing-Guide):
```bash
cd ~/research/open-nic-shell/script && rm -rf ../build/au250_graph_v3
nohup vivado -mode batch -source build.tcl -tclargs -board au250 -num_cmac_port 2 \
  -num_phys_func 2 -tag graph_v3 -impl 1 -user_plugin $(pwd)/../../open-nic-graph-plugin &
```

**Program + hardware functional test** — see [Testing Guide §3–4](../../wiki/Graph-Plugin-Testing-Guide):
```bash
cd test && ./program_fpga.sh && sudo reboot           # WARM reboot only
# after reboot: load driver, then:
sudo ./run_fields_test.sh ens4f0 ens4f1               # v3 field extraction (11/11)
sudo ./run_graph_test.sh  ens4f0 ens4f1 200           # bulk aggregation, version=3, drop_count=0
```

**DPDK high-rate load-gen + full-trace replay** — full procedure in
[DPDK Load-Generation Setup](../../wiki/DPDK-Load-Generation-Setup):
```bash
cd test
NUMQ=8 ./onic_dpdk_reinit.sh                           # multi-queue steering + DPDK env
# real trace at ~100 Mpps: split per queue, pktgen -s 0:mq_0.pcap,mq_1.pcap,...
./pcap_prep.py -i <trace>.pcap --split 8 --prefix /scratch/data/mq_ -n 1600000
# whole 57 GB in one streaming pass at ~15 Mpps (lz4-in-RAM, every frame verified live):
lz4 -1 /scratch/data/<trace>.pcap /scratch/data/trace.lz4   # compress once (kept on /scratch)
cp /scratch/data/trace.lz4 /dev/shm/                        # stage in RAM once per boot
make -f Makefile.graph_replay && NUMQ=4 HUGEPAGES=4096 ./onic_dpdk_reinit.sh
lz4 -dc /dev/shm/trace.lz4 | sudo NQ=4 ./graph_replay -l 4-9 -n 4 \
     -a 0000:17:00.0 -a 0000:17:00.1 -d librte_net_qdma.so -- -
```

## Test tooling (`test/`)

| File | Role |
|------|------|
| `graph_common.py` | shared record gen/parse + FloatingEncoder + proto/flags encoders (matches the RTL) |
| `run_fields_test.sh` · `graph_fields_test.py` | focused v3 field-by-field check (proto/flags codes, len, ports) |
| `run_graph_test.sh` · `graph_inject.py` · `graph_verify.py` | bulk 5-tuple aggregation over a namespace-isolated loopback |
| `run_pcap_test.sh` · `graph_pcap_inject.py` · `graph_pcap_verify.py` | replay a real trace over onic + verify (sampled-capture aware) |
| `graph_dump.py` | pretty-print `0x88B5` frames (decodes records, checks `tag=OK`) |
| `pcap_prep.py` | slice + Ethernet-encapsulate a raw-IP pcap; `--split N` writes per-queue slices |
| `onic_dpdk_reinit.sh` | DPDK per-run: restore vfio/hugepages/steering (`NUMQ=N` for multi-queue) |
| `graph_replay.c` · `Makefile.graph_replay` | DPDK streaming replay of a whole (>RAM) pcap — reads a path or stdin (`-`, e.g. `lz4 -dc … \|`), multi-queue TX (`NQ=N`); verifies every frame live |
| `graph_agg_check.py` | stream-validate a large (tens-of-GB) recorded `0x88B5` pcap (no scapy, no OOM) |

## Notes

- **FloatingEncoder is lossy > 1023** (registered/ephemeral ports quantized); well-known ports
  (0–1023) stay exact. IPv6 deliberately deferred.
- After JTAG programming **always warm reboot** (`sudo reboot`); a PCIe rescan hangs the host, a
  hard reset clears the bitfile.
- `REC_FIXED` is a synthesis parameter — changing the tag needs a rebuild; keep the RTL param and
  the two Python `REC_FIXED` constants in sync.
