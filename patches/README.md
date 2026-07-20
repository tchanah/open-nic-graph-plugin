# open-nic-driver patches (octo250)

`open-nic-driver-octo250.patch` — the local changes to Xilinx's
[open-nic-driver](https://github.com/Xilinx/open-nic-driver) needed to run the
graph plugin on the **octo250** host (Ubuntu 20.04, kernel 5.4, SONiC switch).
Generated against the official release tag **`1.0`** (commit `93d1439`).

## Why these changes (see the wiki "OpenNIC on octo250" page for detail)

1. **Kernel 5.4 → use tag `1.0`.** The driver's `main` HEAD requires kernel
   5.15+ (XDP/page_pool APIs) and will not compile on 5.4. Tag `1.0` predates
   that and already knows the `903f/913f` device IDs and 2-PF setup.
2. **RS-FEC off** (`onic_hardware.c`, `onic_enable_cmac`). The SONiC switch runs
   the ports with **no FEC** (`Oper FEC: none`), but the driver force-enabled
   RS-FEC, so the CMAC RX never achieved PCS lock (`BLOCK_LOCK=0`, RX local
   fault) and the driver then disabled the CMAC. Setting `RSFEC_CONF_ENABLE=0`
   lets the link lock (~1 s). Patient align retry (`msleep`, not busy-wait).
3. **Skip factory cards** (`onic_main.c`, `onic_probe`). The driver binds PCI
   id `0x903f`, which is also the factory/golden image on **unprogrammed** cards
   (they enumerate as "Serial controller", class `0x07`). Probing them fails
   MSI-X (`onic_init_capacity` → `-28`) and the half-init corrupts IRQ state,
   causing soft/hard lockups. An early `-ENODEV` for non-network-class devices
   makes the driver attach only to real programmed shells.

## Apply

```bash
cd ~/…/open-nic-driver          # a fresh clone
git checkout 1.0
git apply /path/to/open-nic-graph-plugin/patches/open-nic-driver-octo250.patch
make clean && make
```

> Note: on octo250 the driver **oopses on `rmmod`** (a stock 1.0 teardown bug in
> `netif_napi_del`). Apply driver changes via **warm reboot + single `insmod`**,
> never `rmmod`.
