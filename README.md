# OpenNIC Graph Plugin

In-network data extraction for the **Anonymized Network Sensing Graph Challenge**
(Jananthan et al., HPEC 2024; FPGA mapping Han et al., arXiv 2409.07374), running on a
Xilinx **Alveo U250** with the [OpenNIC Shell](https://github.com/Xilinx/open-nic-shell).
On the RX/ingress path it extracts each IPv4 packet's fields, drops the original, and
aggregates many compact records into host-bound `0x88B5` frames via QDMA C2H.

**Status — v4 (`version 0x04`, 32 B record) — "bump in the wire":** aggregated frames now
**egress on CMAC port 1** instead of going to the local host via QDMA C2H, so the plugin sits
transparently *in the wire* between a source and a sink. Built (timing **met**, WNS +0.045 ns),
hardware-verified, and throughput-validated on the real datapath:
- multi-queue **≥100 Mpps min-size, drop-free** (host/PCIe-limited; plugin ~163 Mpps in sim);
- **3-card pipeline** (source → plugin → sink over a switch): the full **57 GB real scan trace —
  all 1,073,741,824 packets** — aggregated **exactly 45.00:1**, every frame delivered to the sink,
  **drop-free** (`drop_count=0`, tag OK, `frame_seq` contiguous), in one pass at
  **35.43 Mpps / 30.3 s** (`NQ=2`) — 2.3× the previous 15.20 Mpps best. Paced by the streamer's
  single reader core; the plugin itself runs at ~21 % of its sim datapath.

> **Detailed, reproducible step-by-step guides live in the [wiki](../../wiki)** — this README
> is the concise overview + pointers:
> [OpenNIC Shell Setup](../../wiki/OpenNIC-Shell-Setup-Guide) ·
> [Graph Plugin Testing Guide](../../wiki/Graph-Plugin-Testing-Guide) ·
> [DPDK Load-Generation Setup](../../wiki/DPDK-Load-Generation-Setup) ·
> [OpenNIC on octo250](../../wiki/OpenNIC-on-octo250) (multi-FPGA + switch).

## What it does

```
source → CMAC0 RX → extract 5-tuple+meta → aggregate → CMAC1 TX → sink   (EtherType 0x88B5)
```
Logic lives entirely in the **`box_250mhz` RX path** — `graph_aggregator.sv` replaces the RX
pipeline in `p2p_250mhz.sv` (single 250 MHz domain, line-rate at 512 b×250 MHz). **v4 retargets
its output from QDMA C2H to the port-1 TX stream**: C2H is tied off, port-0 TX stays host
pass-through, port-1 RX is drained. `box_322mhz` is untouched; the shell is consumed unmodified
via `-user_plugin`.

## v4 record — 32 B per IPv4 packet (all big-endian)

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
Layout is unchanged from v3; only `version` moved to `0x04` so a sink can identify a
bump-in-wire frame. `drop_count`/`frame_seq` are cumulative free-running counters, so a single
late frame carries the whole run's totals.

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

**Build the bitfile** (in open-nic-shell; ~1 h 45 m on a 64-core host) — see
[Testing Guide §2](../../wiki/Graph-Plugin-Testing-Guide):
```bash
cd ~/research/open-nic-shell/script && rm -rf ../build/au250_graph_v4
nohup vivado -mode batch -source build.tcl -tclargs -board au250 -num_cmac_port 2 \
  -num_phys_func 2 -tag graph_v4 -impl 1 -user_plugin $(pwd)/../../open-nic-graph-plugin &
```

**Program + hardware functional test** — program **only the plugin card**, inject at the source,
verify at the sink — see [Testing Guide §3–4](../../wiki/Graph-Plugin-Testing-Guide) and
[octo250](../../wiki/OpenNIC-on-octo250):
```bash
cd test && ./program_fpga.sh -b <…au250_graph_v4…/open_nic_shell.bit> <serial> && sudo reboot
# after reboot: insmod onic, links up, pin the sink port to ETH_DST_MAC, then:
sudo tcpdump -i <sink_if> -w /tmp/agg.pcap 'ether proto 0x88b5' &
sudo ./graph_inject.py -i <source_if> -n 200
sudo ./graph_verify.py -f /tmp/agg.pcap -n 200        # 200/200 in-order, version=4, drop_count=0
```

**DPDK full-trace replay** (source card only; the plugin runs autonomously) — full procedure in
[DPDK Load-Generation Setup](../../wiki/DPDK-Load-Generation-Setup):
```bash
cd test && make -f Makefile.graph_replay
numactl --cpunodebind=0 --membind=0 cp <trace>.pcap /dev/shm/    # NUMA-local, uncompressed
PF0=<srcPF0> PF1=<srcPF1> NUMQ=2 HUGEPAGES=4096 ./onic_dpdk_reinit.sh   # before EVERY launch
sudo TXONLY=1 NQ=2 ./graph_replay -l 4-7 -a <srcPF0> -d librte_net_qdma.so -- /dev/shm/<trace>.pcap
sudo ./cmac_pktcount.py <plugin_bdf> <sink_bdf>       # RX in, TX frames, ratio 45.00, delivery
```
Whole-trace scaling (NUMA-local, directed unicast): **24.75 / 35.43 / 34.05 Mpps** at `NQ=1/2/4`.
`NQ=2` is the knee — the single reader lcore saturates (~35 Mpps) and extra TX workers only add
contention; TX/DMA/IOMMU are *not* the limit (confirmed with `STUB=1`).

## Test tooling (`test/`)

| File | Role |
|------|------|
| `graph_common.py` | shared record gen/parse + FloatingEncoder + proto/flags encoders (matches the RTL) |
| `run_fields_test.sh` · `graph_fields_test.py` | focused v3 field-by-field check (proto/flags codes, len, ports) |
| `run_graph_test.sh` · `graph_inject.py` · `graph_verify.py` | bulk 5-tuple aggregation over a namespace-isolated loopback |
| `run_pcap_test.sh` · `graph_pcap_inject.py` · `graph_pcap_verify.py` | replay a real trace over onic + verify (sampled-capture aware) |
| `graph_dump.py` | pretty-print `0x88B5` frames (decodes records, checks `tag=OK`) |
| `pcap_prep.py` | slice + Ethernet-encapsulate a raw-IP pcap; `--split N` writes per-queue slices |
| `onic_dpdk_reinit.sh` | DPDK per-run: restore vfio/hugepages/steering (`NUMQ=N`); auto-detects an IOMMU and only uses no-IOMMU mode when there isn't one |
| `graph_replay.c` · `Makefile.graph_replay` | DPDK streaming replay of a whole (>RAM) pcap — reads a path or stdin (`-`, e.g. `lz4 -dc … \|`), multi-queue TX (`NQ=N`); `TXONLY=1` for the 3-card path (no local RX), `STUB=1` to isolate the reader |
| `graph_agg_check.py` | stream-validate a large (tens-of-GB) recorded `0x88B5` pcap (no scapy, no OOM) |
| `program_fpga.sh` · `.tcl` | JTAG-program by serial (`--list` to enumerate, `-b` to pick the bitfile) |
| `cmac_status.py` · `cmac_pktcount.py` · `cmac_reenable.py` | per-port link/FEC health (`BLOCK_LOCK=0x000fffff`), MAC-level TX/RX counters (**clear on read**), CMAC re-arm |
| `reachability_sweep.py` | any-to-any port reachability matrix (`--raw` for a stock NIC build) |

## Notes

- **FloatingEncoder is lossy > 1023** (registered/ephemeral ports quantized); well-known ports
  (0–1023) stay exact. IPv6 deliberately deferred.
- After JTAG programming **always warm reboot** (`sudo reboot`); a PCIe rescan hangs the host, a
  hard reset clears the bitfile.
- `REC_FIXED` is a synthesis parameter — changing the tag needs a rebuild; keep the RTL param and
  the two Python `REC_FIXED` constants in sync.
- **The injected dst MAC must be real *unicast*** (`graph_replay.c` `DST_MAC` / `graph_common.py`
  `INJ_DST_MAC`). The old `11:22:33:44:55:66` has the I/G bit set, so a switch floods it to every
  port — invisible back-to-back, but it throttles the source once a switch is in the path.
- **Switch FDB entries age out (~5 min):** re-learn both the plugin-ingress and sink MACs before
  each run (a `ping -I <if>` is enough) or traffic reverts to flooding. See the octo250 wiki page.
