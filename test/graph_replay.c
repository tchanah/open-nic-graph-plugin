/* graph_replay.c -- stream a raw-IP (DLT_RAW) pcap through the OpenNIC graph
 * plugin and check the aggregated result live.
 *
 * Purpose: run the WHOLE ~57 GB trace through the design in one pass (pktgen can't
 * -- it loads the whole pcap into hugepages). This process streams the file, Ethernet-
 * encapsulates each raw IPv4 datagram, TXes it on PF0, and simultaneously drains the
 * aggregated 0x88B5 frames coming back on PF1, reading the per-frame descriptor
 * (version, drop_count, frame_seq) and checking the fixed REC_FIXED tag.
 *
 * Input: a pcap PATH, or "-" to read from stdin so a decompressor can feed it, e.g.
 *   lz4  -dc  /dev/shm/trace.lz4       | sudo NQ=8 ./graph_replay ... -- -
 *   zstd -dc -T0 /scratch/trace.pcap.zst | sudo      ./graph_replay ... -- -
 * The compressed file is a few x smaller than the 57 GB raw pcap and the decompressor
 * runs in a pipe (RAM) -- the 57 GB decompressed form is never staged back to disk.
 *
 * Throughput: NQ (env, default 1) TX queues. One READER lcore parses the pipe and
 * round-robins packet refs to NQ WORKER lcores that each encapsulate + TX on their own
 * queue (each from its OWN mempool -- no cross-core pool contention); the MAIN lcore
 * drains + verifies the (45x fewer) C2H frames on a single RX queue from its own pool.
 * Single-queue (NQ=1) reproduces the original disk-bound behaviour.
 *
 * Diagnostics: STUB=1 (env) makes workers drop refs without encap/alloc/TX, isolating the
 * reader+dispatch (pipe/parse) throughput from the TX/mempool path. If reader+stub clears
 * the lz4-decode ceiling, the wall is on the TX side; if it caps low, the front-end is it.
 *
 * Topology (same as the pktgen loopback): PF0 TX -> CMAC0 -> QSFP0 ==loop== QSFP1
 *   -> CMAC1 RX -> plugin -> QDMA C2H -> PF1 RX (this app drains + checks).
 *
 * Prereq per run (steering wiped on each DPDK exit): NUMQ=<NQ> ./onic_dpdk_reinit.sh
 *
 * Build:  make -f Makefile.graph_replay
 * Run:    lz4 -dc /dev/shm/trace.lz4 | sudo NQ=8 ./graph_replay -l 4-13 -n 4 \
 *             -a 0000:17:00.0 -a 0000:17:00.1 -d librte_net_qdma.so -- - [out.pcap]
 *         (single queue from a file: sudo ./graph_replay -l 4-6 ... -- trace.pcap)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_ring.h>
#include <rte_launch.h>
#include <rte_lcore.h>

#define PORT_TX        0
#define PORT_RX        1
#define NB_DESC        1024
#define NUM_MBUFS_RX   32768            /* RX/drain pool (main lcore frees here) */
#define NUM_MBUFS_TX   16384            /* per-worker TX pool: own pool => no cross-core contention */
#define MBUF_CACHE     512
#define BURST          64
#define MBUF_DATAROOM  (RTE_PKTMBUF_HEADROOM + 2048)   /* min-size frames; no jumbo */

#define NQ_MAX         16
#define NBLK           32                /* stdin read buffers (power of 2; blk field: 5 bits) */
#define BLKSZ          (8u << 20)        /* 8 MB per block (off field: 23 bits) */
#define RING_SZ        8192              /* per-worker ref ring (power of 2) */

/* Must match graph_aggregator.sv / graph_common.py. */
#define ETH_TYPE_AGG   0x88B5
#define HDR_VERSION    0x03
#define RECORD_LEN     32
#define PREFIX_LEN     32
static const uint8_t REC_FIXED[8] = {0x81,0x00,0xFD,0x00,0x00,0x00,0x00,0x01};
/* Injected L2 addrs (plugin ignores L2; kept consistent with the python tooling). */
static const uint8_t DST_MAC[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
static const uint8_t SRC_MAC[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};

/* classic pcap headers */
struct pcap_ghdr { uint32_t magic; uint16_t vmaj, vmin; int32_t tz;
                   uint32_t sig, snaplen, network; };
struct pcap_rhdr { uint32_t ts_sec, ts_usec, incl_len, orig_len; };

static volatile int force_quit = 0;
static void on_sig(int s) { (void)s; force_quit = 1; }

static FILE *out_f = NULL;                 /* optional: record aggregated frames */

/* ---- shared state between lcores ---- */
static struct rte_mempool *g_mp_rx;          /* RX/drain pool (main lcore frees here) */
static struct rte_mempool *g_mp_tx[NQ_MAX];  /* per-worker TX pools (no cross-core mempool contention) */
static struct rte_ring   *g_ring[NQ_MAX];  /* reader -> worker[q] packet refs */
static uint8_t           *g_blk[NBLK];     /* reader's stdin parse buffers */
static int                g_blk_out[NBLK]; /* outstanding refs per block (atomic) */
static int                g_nq = 1;
static int                g_stub = 0;      /* STUB=1: workers drop refs w/o encap+TX (reader isolation) */
static int                g_swap = 0;
static volatile int       g_reader_done = 0;
static volatile int       g_workers_live = 0;
static uint64_t           g_w_sent[NQ_MAX]; /* per-worker TXed count (progress) */

/* ---- stats gathered from the C2H frames (main/RX lcore only) ---- */
static uint64_t st_frames = 0;        /* 0x88B5 frames RXed */
static uint64_t st_records = 0;       /* records inside them */
static uint32_t st_max_drop = 0;      /* cumulative drop_count high-water */
static uint64_t st_tag_bad = 0;       /* frames whose first record tag != REC_FIXED */
static uint64_t st_ver_bad = 0;       /* frames with version != 0x03 */
static uint64_t st_seq_gaps = 0;      /* frame_seq discontinuities */
static int      seq_init = 0;
static uint32_t seq_next = 0;

static inline uint16_t rd16be(const uint8_t *p){ return (p[0]<<8)|p[1]; }
static inline uint32_t rd32be(const uint8_t *p){ return ((uint32_t)p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]; }

/* Pack a packet ref into a pointer-sized word: blk(bits 40+) | off(16..38) | ilen(0..15). */
static inline uintptr_t ref_enc(unsigned blk, unsigned off, unsigned ilen)
{
    return ((uintptr_t)blk << 40) | ((uintptr_t)off << 16) | (ilen & 0xFFFF);
}

/* Parse one captured Ethernet frame from PF1; update stats (main lcore only). */
static void inspect_frame(const uint8_t *d, uint16_t len)
{
    if (len < PREFIX_LEN) return;
    if (rd16be(d + 12) != ETH_TYPE_AGG) return;      /* not ours */
    uint16_t count = rd16be(d + 14);
    uint32_t drop  = rd32be(d + 16);
    uint32_t seq   = rd32be(d + 20);
    uint8_t  ver   = d[25];

    st_frames++;
    st_records += count;
    if (drop > st_max_drop) st_max_drop = drop;
    if (ver != HDR_VERSION) st_ver_bad++;
    if (count >= 1 && len >= PREFIX_LEN + 8 &&
        memcmp(d + PREFIX_LEN, REC_FIXED, 8) != 0) st_tag_bad++;
    if (!seq_init) { seq_init = 1; seq_next = seq; }
    if (seq != seq_next) st_seq_gaps++;
    seq_next = seq + 1;
}

static void drain_rx(void)
{
    struct rte_mbuf *bufs[BURST];
    uint16_t n = rte_eth_rx_burst(PORT_RX, 0, bufs, BURST);
    for (uint16_t i = 0; i < n; i++) {
        uint8_t *d = rte_pktmbuf_mtod(bufs[i], uint8_t *);
        uint16_t len = rte_pktmbuf_pkt_len(bufs[i]);
        inspect_frame(d, len);
        if (out_f) {                                 /* pcap record: hdr + frame */
            struct pcap_rhdr rh = { (uint32_t)st_frames, 0, len, len };
            fwrite(&rh, sizeof(rh), 1, out_f);
            fwrite(d, 1, len, out_f);
        }
        rte_pktmbuf_free(bufs[i]);
    }
}

static int port_init(uint16_t port, unsigned nrxq, unsigned ntxq, struct rte_mempool *mp)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    uint16_t nrxd = NB_DESC, ntxd = NB_DESC;
    int ret;

    if ((ret = rte_eth_dev_configure(port, nrxq, ntxq, &conf)) < 0) return ret;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nrxd, &ntxd)) < 0) return ret;
    for (unsigned q = 0; q < nrxq; q++)
        if ((ret = rte_eth_rx_queue_setup(port, q, nrxd,
                        rte_eth_dev_socket_id(port), NULL, mp)) < 0) return ret;
    for (unsigned q = 0; q < ntxq; q++)
        if ((ret = rte_eth_tx_queue_setup(port, q, ntxd,
                        rte_eth_dev_socket_id(port), NULL)) < 0) return ret;
    if ((ret = rte_eth_dev_start(port)) < 0) return ret;
    rte_eth_promiscuous_enable(port);
    return 0;
}

/* WORKER lcore: dequeue packet refs, encapsulate, TX on its own queue.
 * Encap pads to the 60 B Ethernet minimum (CMAC drops shorter frames as runts; the MAC
 * appends 4 B FCS -> 64 B on the wire). Two hot-path opts vs the naive version:
 *   - bulk-alloc the whole burst of mbufs in one call (not one alloc per packet);
 *   - zero only the pad tail, not the whole frame we then overwrite. */
static int tx_worker(void *arg)
{
    unsigned qid = (unsigned)(uintptr_t)arg;
    struct rte_ring *r = g_ring[qid];
    struct rte_mempool *mp = g_mp_tx[qid];        /* this worker's own pool */
    void *refs[BURST];
    struct rte_mbuf *tx[BURST];
    uint64_t sent = 0;

    while (1) {
        unsigned n = rte_ring_dequeue_burst(r, refs, BURST, NULL);
        if (n == 0) {
            if (g_reader_done && rte_ring_empty(r)) break;
            rte_pause();
            continue;
        }
        if (g_stub) {                                /* reader-isolation: drop refs, no encap/alloc/TX */
            for (unsigned i = 0; i < n; i++) {
                unsigned blk = ((uintptr_t)refs[i] >> 40) & (NBLK - 1);
                __atomic_fetch_sub(&g_blk_out[blk], 1, __ATOMIC_RELEASE);
            }
            sent += n;
            g_w_sent[qid] = sent;
            continue;
        }
        /* one bulk alloc for the whole burst (own pool >> in-flight, so this rarely waits) */
        while (rte_pktmbuf_alloc_bulk(mp, tx, n) != 0) {
            if (force_quit) { g_w_sent[qid] = sent; goto done; }
            rte_pause();
        }
        for (unsigned i = 0; i < n; i++) {
            uintptr_t v   = (uintptr_t)refs[i];
            unsigned  blk = (v >> 40) & (NBLK - 1);
            unsigned  off = (v >> 16) & 0x7FFFFF;
            unsigned  ilen = v & 0xFFFF;
            const uint8_t *ip = g_blk[blk] + off;
            uint16_t flen = 14 + ilen;
            if (flen < 60) flen = 60;
            uint8_t *p = (uint8_t *)rte_pktmbuf_append(tx[i], flen);
            memcpy(p, DST_MAC, 6);
            memcpy(p + 6, SRC_MAC, 6);
            p[12] = 0x08; p[13] = 0x00;              /* EtherType IPv4 */
            memcpy(p + 14, ip, ilen);
            if (flen > 14 + ilen)                    /* zero only the pad tail */
                memset(p + 14 + ilen, 0, flen - (14 + ilen));
            /* payload copied -> block byte no longer needed: release the ref */
            __atomic_fetch_sub(&g_blk_out[blk], 1, __ATOMIC_RELEASE);
        }
        uint16_t s = 0;
        while (s < n) s += rte_eth_tx_burst(PORT_TX, qid, tx + s, n - s);
        sent += n;
        g_w_sent[qid] = sent;                        /* publish progress */
    }
    g_w_sent[qid] = sent;
done:
    __atomic_fetch_sub(&g_workers_live, 1, __ATOMIC_RELEASE);
    return 0;
}

/* Flush one worker's pending ref batch: account it on the block first (before the refs
 * become visible to the worker), then enqueue -- spin only if the ring is momentarily full. */
static inline void flush_batch(unsigned q, unsigned blk, void **pend, unsigned *pc)
{
    if (!*pc) return;
    __atomic_fetch_add(&g_blk_out[blk], *pc, __ATOMIC_RELAXED);
    unsigned s = 0;
    while (s < *pc && !force_quit)
        s += rte_ring_enqueue_burst(g_ring[q], pend + s, *pc - s, NULL);
    *pc = 0;
}

/* READER lcore: stream the pipe/file, parse pcap records, round-robin refs to workers.
 * No payload memcpy here (that is the workers' job) -- just read + parse + dispatch.
 * Refs are batched per worker (TXBATCH) so the ring op + block atomic amortize ~TXBATCH-fold;
 * per-packet enqueue was the ~260 ns/pkt drag that capped this to ~3.8 Mpps. */
#define TXBATCH 128
static int reader_main(void *arg)
{
    FILE *f = (FILE *)arg;
    static uint8_t carry[16 + 65536];                /* one straddling record max */
    size_t carry_len = 0;
    unsigned b = 0, rr = 0;
    static void *pend[NQ_MAX][TXBATCH];              /* per-worker pending refs (this block) */
    unsigned pc[NQ_MAX];
    for (int q = 0; q < g_nq; q++) pc[q] = 0;

    while (!force_quit) {
        /* wait until block b's previous refs are fully consumed before overwriting it */
        while (__atomic_load_n(&g_blk_out[b], __ATOMIC_ACQUIRE) != 0 && !force_quit)
            rte_pause();
        if (force_quit) break;

        uint8_t *blk = g_blk[b];
        if (carry_len) memcpy(blk, carry, carry_len);
        size_t nread = fread(blk + carry_len, 1, BLKSZ - carry_len, f);
        int eof = (nread < BLKSZ - carry_len);        /* short read == EOF/error reached */
        size_t avail = carry_len + nread;
        carry_len = 0;
        if (avail == 0) break;                        /* clean EOF */

        size_t pos = 0;
        while (pos + 16 <= avail) {
            uint32_t incl;
            memcpy(&incl, blk + pos + 8, 4);          /* incl_len field */
            if (g_swap) incl = rte_bswap32(incl);
            if (incl == 0 || incl > 65535) { force_quit = 2; break; }
            if (pos + 16 + incl > avail) break;       /* record straddles -> carry it */
            pend[rr][pc[rr]++] = (void *)ref_enc(b, pos + 16, incl);
            if (pc[rr] == TXBATCH) flush_batch(rr, b, pend[rr], &pc[rr]);
            rr = (rr + 1 == (unsigned)g_nq) ? 0 : rr + 1;
            pos += 16 + incl;
        }
        if (pos < avail) {                            /* stash the partial tail */
            carry_len = avail - pos;
            memmove(carry, blk + pos, carry_len);
        }
        /* block b's refs must all be dispatched before this block could ever be recycled */
        for (int q = 0; q < g_nq; q++) flush_batch(q, b, pend[q], &pc[q]);
        if (eof && feof(f)) break;
        b = (b + 1 == NBLK) ? 0 : b + 1;
    }

    g_reader_done = 1;                                /* workers drain their rings, then exit */
    return 0;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;
    setvbuf(stdout, NULL, _IOLBF, 0);            /* line-buffered: progress shows live under tee */
    if (argc < 2) rte_exit(EXIT_FAILURE, "usage: ... -- <raw-ip.pcap|-> [out.pcap]\n");
    const char *path = argv[1];

    const char *nqs = getenv("NQ");
    g_nq = nqs ? atoi(nqs) : 1;
    if (g_nq < 1) g_nq = 1;
    if (g_nq > NQ_MAX) g_nq = NQ_MAX;
    g_stub = getenv("STUB") ? atoi(getenv("STUB")) : 0;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    if (rte_eth_dev_count_avail() < 2)
        rte_exit(EXIT_FAILURE, "need 2 ports (PF0 TX, PF1 RX)\n");

    /* need 1 reader + g_nq workers on worker lcores, plus the main lcore for RX */
    unsigned nworker_lc = rte_lcore_count() - 1;
    if (nworker_lc < (unsigned)(1 + g_nq))
        rte_exit(EXIT_FAILURE, "NQ=%d needs %d lcores (reader+%d workers+main); have %u\n",
                 g_nq, g_nq + 2, g_nq, rte_lcore_count());

    g_mp_rx = rte_pktmbuf_pool_create("REPLAY_RX", NUM_MBUFS_RX, MBUF_CACHE, 0,
                                      MBUF_DATAROOM, rte_socket_id());
    if (!g_mp_rx) rte_exit(EXIT_FAILURE, "RX mbuf pool create failed\n");
    for (int q = 0; q < g_nq; q++) {                 /* one TX pool per worker -> no shared-pool contention */
        char nm[32]; snprintf(nm, sizeof(nm), "REPLAY_TX_%d", q);
        g_mp_tx[q] = rte_pktmbuf_pool_create(nm, NUM_MBUFS_TX, MBUF_CACHE, 0,
                                             MBUF_DATAROOM, rte_socket_id());
        if (!g_mp_tx[q]) rte_exit(EXIT_FAILURE, "TX pool %d create failed\n", q);
    }

    if (port_init(PORT_TX, 1, g_nq, g_mp_rx) < 0) rte_exit(EXIT_FAILURE, "port %d init\n", PORT_TX);
    printf("PF0 (TX) up, %d queue(s)\n", g_nq);
    if (port_init(PORT_RX, 1, 1, g_mp_rx) < 0) rte_exit(EXIT_FAILURE, "port %d init\n", PORT_RX);
    printf("PF1 (RX) up\n");

    for (int q = 0; q < g_nq; q++) {
        char nm[32]; snprintf(nm, sizeof(nm), "REF_RING_%d", q);
        g_ring[q] = rte_ring_create(nm, RING_SZ, rte_socket_id(),
                                    RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!g_ring[q]) rte_exit(EXIT_FAILURE, "ring %d create failed\n", q);
    }
    for (int i = 0; i < NBLK; i++) {
        g_blk[i] = malloc(BLKSZ);
        if (!g_blk[i]) rte_exit(EXIT_FAILURE, "block %d alloc failed\n", i);
    }

    FILE *f = (strcmp(path, "-") == 0) ? stdin : fopen(path, "rb");
    if (!f) rte_exit(EXIT_FAILURE, "cannot open %s\n", path);
    /* large read buffer so the pipe/HDD streams sequentially (also applies to stdin);
     * set before the first read -- required by the C standard, and safer on a pipe */
    static char iobuf[1 << 22];
    setvbuf(f, iobuf, _IOFBF, sizeof(iobuf));
    struct pcap_ghdr gh;
    if (fread(&gh, sizeof(gh), 1, f) != 1) rte_exit(EXIT_FAILURE, "short pcap header\n");
    g_swap = (gh.magic == 0xd4c3b2a1);               /* file is opposite-endian */
    if (gh.magic != 0xa1b2c3d4 && !g_swap)
        rte_exit(EXIT_FAILURE, "not a pcap file (magic=%08x)\n", gh.magic);

    /* optional: record the aggregated 0x88B5 frames to a pcap (DLT_EN10MB) */
    if (argc >= 3) {
        out_f = fopen(argv[2], "wb");
        if (!out_f) rte_exit(EXIT_FAILURE, "cannot open output %s\n", argv[2]);
        static char obuf[1 << 22];
        setvbuf(out_f, obuf, _IOFBF, sizeof(obuf));
        struct pcap_ghdr og = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1 };  /* Ethernet */
        fwrite(&og, sizeof(og), 1, out_f);
        printf("Recording aggregated frames -> %s\n", argv[2]);
    }

    if (g_stub)
        printf("STUB MODE: workers drop refs (no encap/TX) -- measuring reader+dispatch only\n");
    printf("Streaming %s (linktype %u) -> PF0 x%d, draining PF1...\n", path,
           g_swap ? rte_bswap32(gh.network) : gh.network, g_nq);

    /* assign lcores: first worker lcore = reader, next g_nq = TX workers */
    unsigned lc, idx = 0, reader_lc = 0, worker_lc[NQ_MAX];
    RTE_LCORE_FOREACH_WORKER(lc) {
        if (idx == 0) reader_lc = lc;
        else if (idx - 1 < (unsigned)g_nq) worker_lc[idx - 1] = lc;
        idx++;
    }

    g_workers_live = g_nq;
    for (int q = 0; q < g_nq; q++)
        rte_eal_remote_launch(tx_worker, (void *)(uintptr_t)q, worker_lc[q]);
    rte_eal_remote_launch(reader_main, f, reader_lc);

    uint64_t hz = rte_get_timer_hz(), t0 = rte_get_timer_cycles(), tlast = t0;
    uint64_t last_sent = 0;

    /* MAIN lcore: drain + verify C2H while the workers TX */
    while (__atomic_load_n(&g_workers_live, __ATOMIC_ACQUIRE) > 0 && !force_quit) {
        drain_rx();
        uint64_t now = rte_get_timer_cycles();
        if (now - tlast > 2 * hz) {
            uint64_t sent = 0;
            for (int q = 0; q < g_nq; q++) sent += g_w_sent[q];
            double mpps = (double)(sent - last_sent) / ((double)(now - tlast) / hz) / 1e6;
            printf("  sent=%" PRIu64 "  frames=%" PRIu64 "  drop=%u  %.2f Mpps\n",
                   sent, st_frames, st_max_drop, mpps);
            tlast = now; last_sent = sent;
        }
    }

    /* flush the tail: drain until the C2H frames stop arriving (idle-timeout flush) */
    uint64_t idle_start = rte_get_timer_cycles(), prev_frames = st_frames;
    while (rte_get_timer_cycles() - idle_start < 2 * hz) {
        drain_rx();
        if (st_frames != prev_frames) { prev_frames = st_frames; idle_start = rte_get_timer_cycles(); }
    }
    rte_eal_mp_wait_lcore();
    if (f != stdin) fclose(f);

    uint64_t st_sent = 0;
    for (int q = 0; q < g_nq; q++) st_sent += g_w_sent[q];
    double secs = (double)(rte_get_timer_cycles() - t0) / hz;
    printf("\n==== graph_replay summary (NQ=%d) ====\n", g_nq);
    printf("packets sent      : %" PRIu64 "\n", st_sent);
    printf("frames received   : %" PRIu64 "\n", st_frames);
    printf("records received  : %" PRIu64 "  (Tx:Rx = %.3f)\n", st_records,
           st_frames ? (double)st_sent / st_frames : 0.0);
    printf("max drop_count    : %u\n", st_max_drop);
    printf("tag mismatches    : %" PRIu64 "\n", st_tag_bad);
    printf("version != 0x03   : %" PRIu64 "\n", st_ver_bad);
    printf("frame_seq gaps    : %" PRIu64 "\n", st_seq_gaps);
    printf("elapsed / rate    : %.1f s  /  %.2f Mpps\n", secs, st_sent / secs / 1e6);
    if (out_f) { fclose(out_f); printf("frames -> pcap    : %s\n", "written"); }
    int ok = (st_max_drop == 0 && st_tag_bad == 0 && st_ver_bad == 0);
    printf("RESULT: %s\n", ok ? "PASS (drop-free, tag OK, v3)" : "CHECK (see nonzero counters)");
    rte_eth_dev_stop(PORT_TX); rte_eth_dev_stop(PORT_RX);
    return ok ? 0 : 1;
}
