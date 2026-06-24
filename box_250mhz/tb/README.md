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

## What it checks (5 tests)

| Test | Coverage |
|------|----------|
| `run_test` ×4 | TX pass-through, then RX aggregation of 200 pkts (91+91+18 frames) compared **byte-exact** to the v2 golden model, across all idle/backpressure combos |
| `run_test_filtering` | ARP → no record; ICMP → zeroed ports + zero flags, TTL/len present; TCP flags extracted |

The v2 record (16 B): `srcIP(4) dstIP(4) ports(3, FloatingEncoder) proto(1)
TTL(1) totalLen(2 BE) tcpFlags(1)`, descriptor `version=0x02`. The golden model
(`expected_record`) and the `floating_encode`/`pack_ports` helpers mirror the
RTL; test packets vary TTL/flags and use ports both below and above 1023.

## Expect

```
** TESTS=5 PASS=5 FAIL=0 SKIP=0 **
```

## Files

| File | Role |
|------|------|
| `test_graph_250mhz_wrapper.py` | tests + golden model + FloatingEncoder helpers |
| `p2p_250mhz_wrapper.sv` | DUT wrapper (sets `AGGR_FLUSH_TIMEOUT=256` for fast sim) |
| `sim_models.sv` | Icarus stand-ins for `axis_register_slice` IP + `xpm_cdc_single` |
| `Makefile` | sources list + run config |
