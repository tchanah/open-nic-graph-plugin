# cocotb testbench — box_250mhz (graph aggregator)

Fast functional sim for the RX-path graph aggregator (`graph_aggregator.sv` in
`p2p_250mhz.sv`). Runs on Icarus, no Vivado needed — use this as the iteration
loop before any hardware build.

## Prerequisites (one-time)

```bash
sudo apt install iverilog                       # iverilog 11
pip3 install --user 'cocotb<2.0' cocotbext-axi scapy   # cocotb 1.9.2 (TestFactory)
```
`~/.local/bin` must be on `PATH`. Assumes `open-nic-shell` is checked out as a
sibling of this plugin repo (else `make SHELL_SRC=/path/to/open-nic-shell/src`).

## Run

```bash
make            # build + run all tests
make clean      # remove sim_build/, results.xml
```

## What it checks (10 tests)

| Test | Coverage |
|------|----------|
| `run_test` ×4 | TX pass-through, then RX aggregation of 200 pkts (91+91+18 frames) compared **byte-exact** to the v2 golden model, across all idle/backpressure combos |
| `run_test_filtering` | ARP → no record; ICMP → zeroed ports + zero flags, TTL/len present; TCP flags extracted |
| `run_test_overflow` | **Drop-path validation:** 2000 min-size pkts pushed back-to-back (1 record/cycle) while the C2H sink is starved (ready 1-in-16) → the 512-deep record FIFO overflows. Asserts `delivered + drop_count == sent` (exact accounting), `drop_count > 0`, the drops-seen flag tracks it, and delivered records are an in-order, bit-exact subsequence of the golden set (no corruption under overflow). |
| `run_test_sustained` ×4 | **Throughput against an ideal (never-stalled) C2H sink** — isolates the aggregator's own rate from any host-drain limit. Records pop only during `ST_FILL`, so per-frame overhead sets a break-even at the single-beat (min-size) boundary. Cases: real 100GbE min-size + IFG (~0.6 rec/cyc) → **0 drops**; gap-free min-size (1.0 rec/cyc) → drops (intrinsic ceiling); 128 B/2-beat (0.5) and 256 B/4-beat (0.25) → **0 drops, byte-exact**. Confirms payload-bearing traffic drains with large margin. |

The v2 record (16 B): `srcIP(4) dstIP(4) ports(3, FloatingEncoder) proto(1)
TTL(1) totalLen(2 BE) tcpFlags(1)`, descriptor `version=0x02`. The golden model
(`expected_record`) and the `floating_encode`/`pack_ports` helpers mirror the
RTL; test packets vary TTL/flags and use ports both below and above 1023.

## Expect

```
** TESTS=10 PASS=10 FAIL=0 SKIP=0 **
```

## Files

| File | Role |
|------|------|
| `test_graph_250mhz_wrapper.py` | tests + golden model + FloatingEncoder helpers |
| `p2p_250mhz_wrapper.sv` | DUT wrapper (sets `AGGR_FLUSH_TIMEOUT=256` for fast sim) |
| `sim_models.sv` | Icarus stand-ins for `axis_register_slice` IP + `xpm_cdc_single` |
| `Makefile` | sources list + run config |
