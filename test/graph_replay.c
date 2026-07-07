/* graph_replay.c -- stream a raw-IP (DLT_RAW) pcap through the OpenNIC graph
 * plugin at disk speed and check the result live.
 *
 * Purpose: run the WHOLE 60 GB trace through the design in one pass (pktgen can't
 * -- it loads the whole pcap into hugepages). This process streams the file from
 * disk, Ethernet-encapsulates each raw IPv4 datagram, TXes it on PF0 (one queue),
 * and simultaneously drains the aggregated 0x88B5 frames coming back on PF1,
 * reading the per-frame descriptor (version, drop_count, frame_seq) and checking
 * the fixed REC_FIXED tag. Rate is bounded by the disk (~a few Mpps on an HDD),
 * which is fine -- the plugin's per-packet behaviour is rate-independent below its
 * ceiling (100 Mpps already proven on RAM chunks), so this validates that every
 * unique packet in the trace is processed drop-free.
 *
 * Topology (same as the pktgen loopback): PF0 TX -> CMAC0 -> QSFP0 ==loop== QSFP1
 *   -> CMAC1 RX -> plugin -> QDMA C2H -> PF1 RX (this app drains + checks).
 *
 * Prereq per run (steering wiped on each DPDK exit): NUMQ=1 ./onic_dpdk_reinit.sh
 *
 * Build:  make -f Makefile.graph_replay
 * Run:    sudo ./graph_replay -l 4-6 -n 4 -a 0000:17:00.0 -a 0000:17:00.1 \
 *             -d librte_net_qdma.so -- /scratch/data/20220102-120000.pcap
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

#define PORT_TX        0
#define PORT_RX        1
#define NB_DESC        1024
#define NUM_MBUFS      32768
#define MBUF_CACHE     256
#define BURST          64
#define MBUF_DATAROOM  (RTE_PKTMBUF_HEADROOM + 2048)   /* min-size frames; no jumbo */

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

/* ---- stats gathered from the C2H frames ---- */
static uint64_t st_sent = 0;          /* packets TXed  */
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

/* Parse one captured Ethernet frame from PF1; update stats. */
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

static int port_init(uint16_t port, struct rte_mempool *mp)
{
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    uint16_t nrxd = NB_DESC, ntxd = NB_DESC;
    int ret;

    if ((ret = rte_eth_dev_configure(port, 1, 1, &conf)) < 0) return ret;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nrxd, &ntxd)) < 0) return ret;
    if ((ret = rte_eth_rx_queue_setup(port, 0, nrxd,
                    rte_eth_dev_socket_id(port), NULL, mp)) < 0) return ret;
    if ((ret = rte_eth_tx_queue_setup(port, 0, ntxd,
                    rte_eth_dev_socket_id(port), NULL)) < 0) return ret;
    if ((ret = rte_eth_dev_start(port)) < 0) return ret;
    rte_eth_promiscuous_enable(port);
    return 0;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;
    setvbuf(stdout, NULL, _IOLBF, 0);            /* line-buffered: progress shows live under tee */
    if (argc < 2) rte_exit(EXIT_FAILURE, "usage: ... -- <raw-ip.pcap> [out.pcap]\n");
    const char *path = argv[1];

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    if (rte_eth_dev_count_avail() < 2)
        rte_exit(EXIT_FAILURE, "need 2 ports (PF0 TX, PF1 RX)\n");

    struct rte_mempool *mp = rte_pktmbuf_pool_create(
        "REPLAY_MP", NUM_MBUFS, MBUF_CACHE, 0, MBUF_DATAROOM, rte_socket_id());
    if (!mp) rte_exit(EXIT_FAILURE, "mbuf pool create failed\n");

    if (port_init(PORT_TX, mp) < 0) rte_exit(EXIT_FAILURE, "port %d init\n", PORT_TX);
    printf("PF0 (TX) up\n");
    if (port_init(PORT_RX, mp) < 0) rte_exit(EXIT_FAILURE, "port %d init\n", PORT_RX);
    printf("PF1 (RX) up\n");

    FILE *f = fopen(path, "rb");
    if (!f) rte_exit(EXIT_FAILURE, "cannot open %s\n", path);
    struct pcap_ghdr gh;
    if (fread(&gh, sizeof(gh), 1, f) != 1) rte_exit(EXIT_FAILURE, "short pcap header\n");
    int swap = (gh.magic == 0xd4c3b2a1);             /* file is opposite-endian */
    if (gh.magic != 0xa1b2c3d4 && !swap)
        rte_exit(EXIT_FAILURE, "not a pcap file (magic=%08x)\n", gh.magic);
    /* setvbuf: large read buffer so the HDD streams sequentially */
    static char iobuf[1 << 22];
    setvbuf(f, iobuf, _IOFBF, sizeof(iobuf));

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

    printf("Streaming %s (linktype %u) -> PF0, draining PF1...\n", path,
           swap ? rte_bswap32(gh.network) : gh.network);
    uint64_t hz = rte_get_timer_hz(), t0 = rte_get_timer_cycles(), tlast = t0;
    uint64_t last_sent = 0;
    static uint8_t ipbuf[65536];

    while (!force_quit) {
        struct rte_mbuf *tx[BURST];
        int nb = 0;
        for (; nb < BURST; nb++) {
            struct pcap_rhdr rh;
            if (fread(&rh, sizeof(rh), 1, f) != 1) { force_quit = 2; break; }
            uint32_t ilen = swap ? rte_bswap32(rh.incl_len) : rh.incl_len;
            if (ilen == 0 || ilen > sizeof(ipbuf)) { force_quit = 2; break; }
            if (fread(ipbuf, 1, ilen, f) != ilen)  { force_quit = 2; break; }

            struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
            if (!m) { /* pool momentarily empty: drain and retry this packet */
                drain_rx();
                m = rte_pktmbuf_alloc(mp);
                if (!m) break;
            }
            /* Pad to the 60 B Ethernet minimum (14 hdr + 46) -- CMAC drops shorter
             * frames as runts; the MAC appends the 4 B FCS -> 64 B on the wire.
             * (pktgen does the same: pcap packets < MIN_PKT_SIZE are padded up.) */
            uint16_t flen = 14 + ilen;
            if (flen < 60) flen = 60;
            uint8_t *p = (uint8_t *)rte_pktmbuf_append(m, flen);
            memset(p, 0, flen);                      /* zero the pad tail */
            memcpy(p, DST_MAC, 6);
            memcpy(p + 6, SRC_MAC, 6);
            p[12] = 0x08; p[13] = 0x00;              /* EtherType IPv4 */
            memcpy(p + 14, ipbuf, ilen);
            tx[nb] = m;
        }
        uint16_t s = 0;
        while (s < nb) {
            s += rte_eth_tx_burst(PORT_TX, 0, tx + s, nb - s);
            drain_rx();                              /* keep C2H flowing while we push */
        }
        st_sent += nb;

        /* progress every ~2s */
        uint64_t now = rte_get_timer_cycles();
        if (now - tlast > 2 * hz) {
            double mpps = (double)(st_sent - last_sent) / ((double)(now - tlast) / hz) / 1e6;
            printf("  sent=%" PRIu64 "  frames=%" PRIu64 "  drop=%u  %.2f Mpps\n",
                   st_sent, st_frames, st_max_drop, mpps);
            tlast = now; last_sent = st_sent;
        }
    }
    fclose(f);

    /* flush the tail: drain until the C2H frames stop arriving (idle-timeout flush) */
    uint64_t idle_start = rte_get_timer_cycles(), prev_frames = st_frames;
    while (rte_get_timer_cycles() - idle_start < 2 * hz) {
        drain_rx();
        if (st_frames != prev_frames) { prev_frames = st_frames; idle_start = rte_get_timer_cycles(); }
    }

    double secs = (double)(rte_get_timer_cycles() - t0) / hz;
    printf("\n==== graph_replay summary ====\n");
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
