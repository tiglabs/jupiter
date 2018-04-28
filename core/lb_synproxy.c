/* Copyright (c) 2018. TIG developer. */

#include <rte_cycles.h>
#include <rte_random.h>

#include "lb_conn.h"
#include "lb_md5.h"
#include "lb_proto.h"
#include "lb_service.h"
#include "lb_synproxy.h"
#include "lb_tcp_secret_seq.h"
#include "lb_toa.h"

// #define SYNPROXY_DEBUG
#ifdef SYNPROXY_DEBUG
#define SYNPROXY_PRINT(...)                                                    \
    do {                                                                       \
        fprintf(stderr, "SYNPROXY: ");                                         \
        fprintf(stderr, __VA_ARGS__);                                          \
    } while (0)
#else
#define SYNPROXY_PRINT(...)                                                    \
    do {                                                                       \
    } while (0)
#endif

extern uint32_t tcp_timeouts[TCP_CONNTRACK_MAX];

static inline void
tcp_conn_set_state(struct lb_conn *conn, uint32_t state) {
    uint32_t timeout = 0;

    if (state == TCP_CONNTRACK_ESTABLISHED) {
        timeout = conn->real_service->virt_service->est_timeout;
    }
    if (timeout == 0)
        timeout = tcp_timeouts[TCP_CONNTRACK_ESTABLISHED];
    conn->state = state;
    conn->timeout = timeout;
}

static const uint16_t msstab[] = {536, 1300, 1440, 1460};

static uint32_t net_secret[2][MD5_MESSAGE_BYTES / 4] __rte_cache_aligned;

static void
synproxy_net_secret_init(void) {
    int i;
    static uint8_t inited = 0;

    if (likely(inited))
        return;

    for (i = 0; i < MD5_MESSAGE_BYTES / 4; i++) {
        net_secret[0][i] = rte_rand();
        net_secret[1][i] = rte_rand();
    }

    inited = 1;
};

#define COOKIEBITS 24 /* Upper bits store count */
#define COOKIEMASK (((uint32_t)1 << COOKIEBITS) - 1)

#define COUNTER_TRIES 4

static inline uint32_t
tcp_cookie_time(void) {
    /* 64s */
    return (uint32_t)(rte_get_tsc_cycles() / (rte_get_tsc_hz() * 60));
}

static inline uint32_t
cookie_hash(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport,
            uint32_t count, int c) {
    uint32_t hash[4];

    synproxy_net_secret_init();

    hash[0] = saddr;
    hash[1] = daddr;
    hash[2] = (sport << 16) + dport;
    hash[3] = count;

    md5_transform(hash, net_secret[c]);

    return hash[0];
}

static uint32_t
secure_tcp_syn_cookie(uint32_t saddr, uint32_t daddr, uint16_t sport,
                      uint16_t dport, uint32_t sseq, uint32_t count,
                      uint32_t data) {
    return (cookie_hash(saddr, daddr, sport, dport, 0, 0) + sseq +
            (count << COOKIEBITS) +
            ((cookie_hash(saddr, daddr, sport, dport, count, 1) + data) &
             COOKIEMASK));
}

static uint32_t
check_tcp_syn_cookie(uint32_t cookie, uint32_t saddr, uint32_t daddr,
                     uint16_t sport, uint16_t dport, uint32_t sseq,
                     uint32_t count, uint32_t maxdiff) {
    uint32_t diff;

    cookie -= cookie_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

    diff = (count - (cookie >> COOKIEBITS)) & ((uint32_t)-1 >> COOKIEBITS);
    if (diff >= maxdiff)
        return (uint32_t)-1;

    return (cookie - cookie_hash(saddr, daddr, sport, dport, count - diff, 1)) &
           COOKIEMASK;
}

uint32_t
synproxy_cookie_ipv4_init_sequence(struct ipv4_hdr *iph, struct tcp_hdr *th,
                                   struct synproxy_options *opts) {
    int mssid;
    const uint16_t mss = opts->mss_clamp;
    uint32_t data = 0;

    for (mssid = RTE_DIM(msstab) - 1; mssid; mssid--)
        if (mss >= msstab[mssid])
            break;

    data = ((mssid & 0x0f) << LB_SYNPROXY_MSS_BITS);
    data |= opts->sack_ok << LB_SYNPROXY_SACKOK_BIT;
    data |= opts->tstamp_ok << LB_SYNPROXY_TSOK_BIT;
    data |= ((opts->snd_wscale & 0x0f) << LB_SYNPROXY_SND_WSCALE_BITS);

    return secure_tcp_syn_cookie(iph->src_addr, iph->dst_addr, th->src_port,
                                 th->dst_port, rte_be_to_cpu_32(th->sent_seq),
                                 tcp_cookie_time(), data);
}

uint32_t
synproxy_cookie_ipv4_check(struct ipv4_hdr *iph, struct tcp_hdr *th,
                           struct synproxy_options *opts) {
    uint32_t rc;
    uint32_t cookie;
    uint32_t sseq;
    uint32_t mssid;

    cookie = rte_be_to_cpu_32(th->recv_ack) - 1;
    sseq = rte_be_to_cpu_32(th->sent_seq) - 1;
    rc = check_tcp_syn_cookie(cookie, iph->src_addr, iph->dst_addr,
                              th->src_port, th->dst_port, sseq,
                              tcp_cookie_time(), COUNTER_TRIES);
    if (rc == (uint32_t)-1)
        return 0;

    mssid = (rc & LB_SYNPROXY_MSS_MASK) >> LB_SYNPROXY_MSS_BITS;

    memset(opts, 0, sizeof(struct synproxy_options));
    if ((mssid < RTE_DIM(msstab)) && ((rc & LB_SYNPROXY_OTHER_MASK) == 0)) {
        opts->mss_clamp = msstab[mssid];
        opts->sack_ok =
            (rc & LB_SYNPROXY_SACKOK_MASK) >> LB_SYNPROXY_SACKOK_BIT;
        opts->tstamp_ok = (rc & LB_SYNPROXY_TSOK_MASK) >> LB_SYNPROXY_TSOK_BIT;
        opts->snd_wscale =
            (rc & LB_SYNPROXY_SND_WSCALE_MASK) >> LB_SYNPROXY_SND_WSCALE_BITS;
        if (opts->snd_wscale > 0 && opts->snd_wscale <= LB_SYNPROXY_WSCALE_MAX)
            opts->wscale_ok = 1;
        else if (opts->snd_wscale == 0)
            opts->wscale_ok = 0;
        else
            return 0;

        return 1;
    }

    return 0;
}

static void
synproxy_parse_set_options(struct tcp_hdr *th, struct synproxy_options *opts) {
    uint8_t *ptr;
    int len;
    uint32_t *tmp;

    memset(opts, 0, sizeof(*opts));
    opts->mss_clamp = 1460;

    ptr = (uint8_t *)(th + 1);
    len = (th->data_off >> 2) - sizeof(*th);
    while (len > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return;
        case TCPOPT_NOP:
            len--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)
                return;
            if (opsize > len)
                return;

            switch (opcode) {
            case TCPOPT_MSS:
                if (opsize == TCPOLEN_MSS) {
                    opts->mss_clamp = rte_be_to_cpu_16(*((uint16_t *)ptr));
                    if (opts->mss_clamp > 1460)
                        opts->mss_clamp = 1460;
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW) {
                    opts->wscale_ok = 1;
                    opts->snd_wscale = *ptr;
                    if (opts->snd_wscale > 14)
                        opts->snd_wscale = 14;
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {
                    /*opts->tstamp_ok = 1;
                    tmp = (uint32_t *)ptr;
                    *(tmp + 1) = *tmp;
                    *tmp = rte_cpu_to_be_32((uint32_t)rte_get_tsc_cycles());*/
                    *(ptr - 2) = TCPOPT_NOP;
                    *(ptr - 1) = TCPOPT_NOP;
                    tmp = (uint32_t *)ptr;
                    *tmp++ = 0x01010101;
                    *tmp = 0x01010101;
                }
                break;
            case TCPOPT_SACK_PERM:
                if (opsize == TCPOLEN_SACK_PERM) {
                    //                    opts->sack_ok = 1;
                    *(ptr - 2) = TCPOPT_NOP;
                    *(ptr - 1) = TCPOPT_NOP;
                }
                break;
            }
            ptr += opsize - 2;
            len -= opsize;
        }
    }
}

static uint16_t
synproxy_options_size(const struct synproxy_options *opts) {
    return TCPOLEN_MSS + (opts->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0) +
           (opts->wscale_ok ? TCPOLEN_WSCALE_ALIGNED : 0) +
           ((opts->sack_ok && !opts->tstamp_ok) ? TCPOLEN_SACKPERM_ALIGNED : 0);
}

void
synproxy_seq_adjust_client(struct tcp_hdr *th, struct synproxy *proxy) {
    struct lb_conn *conn = container_of(proxy, struct lb_conn, proxy);

    if (!(conn->flags & LB_CONN_F_SYNPROXY))
        return;
    th->recv_ack =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) + proxy->oft);
}

void
synproxy_seq_adjust_backend(struct tcp_hdr *th, struct synproxy *proxy) {
    struct lb_conn *conn = container_of(proxy, struct lb_conn, proxy);

    if (!(conn->flags & LB_CONN_F_SYNPROXY))
        return;
    th->sent_seq =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) - proxy->oft);
}

static void
synproxy_sent_client_synack(struct rte_mbuf *m, struct ipv4_hdr *iph,
                            struct tcp_hdr *th, struct lb_device *dev) {
    struct synproxy_options opts;
    uint32_t isn;
    uint16_t pkt_len;
    uint32_t tmpaddr;
    uint16_t tmpport;

    synproxy_parse_set_options(th, &opts);
    isn = synproxy_cookie_ipv4_init_sequence(iph, th, &opts);

    pkt_len = m->data_len;
    rte_pktmbuf_reset(m);
    m->pkt_len = m->data_len = pkt_len;

    iph->time_to_live = 63;
    iph->type_of_service = 0;
    tmpaddr = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = tmpaddr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    tmpport = th->src_port;
    th->src_port = th->dst_port;
    th->dst_port = tmpport;
    th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
    th->sent_seq = rte_cpu_to_be_32(isn);
    th->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
    th->tcp_urp = 0;
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    lb_device_output(m, iph, dev);
}

int
synproxy_recv_client_syn(struct rte_mbuf *m, struct ipv4_hdr *iph,
                         struct tcp_hdr *th, struct lb_device *dev) {
    struct lb_virt_service *vs = NULL;

    if (SYN(th) && !ACK(th) && !RST(th) && !FIN(th) &&
        (vs = lb_vs_get(iph->dst_addr, th->dst_port, iph->next_proto_id)) &&
        (vs->flags & LB_VS_F_SYNPROXY)) {
        if (lb_vs_check_max_conn(vs))
            /* Reject connect. */
            rte_pktmbuf_free(m);
        else
            synproxy_sent_client_synack(m, iph, th, dev);
        lb_vs_put(vs);
        return 0;
    } else {
        if (vs != NULL)
            lb_vs_put(vs);
        return 1;
    }
}

static void
synproxy_syn_build_options(uint32_t *ptr, struct synproxy_options *opts) {
    *ptr++ = rte_cpu_to_be_32((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) |
                              opts->mss_clamp);
    if (opts->tstamp_ok) {
        if (opts->sack_ok)
            *ptr++ = rte_cpu_to_be_32(
                (TCPOPT_SACK_PERM << 24) | (TCPOLEN_SACK_PERM << 16) |
                (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
        else
            *ptr++ =
                rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                 (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
        *ptr++ = rte_cpu_to_be_32((uint32_t)rte_get_tsc_cycles()); /* TSVAL */
        *ptr++ = 0;                                                /* TSECR */
    } else if (opts->sack_ok)
        *ptr++ = rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                  (TCPOPT_SACK_PERM << 8) | TCPOLEN_SACK_PERM);
    if (opts->wscale_ok)
        *ptr++ = rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_WINDOW << 16) |
                                  (TCPOLEN_WINDOW << 8) | (opts->snd_wscale));
}

static void
synproxy_sent_backend_syn(struct rte_mbuf *m, struct ipv4_hdr *iph,
                          struct tcp_hdr *th, struct lb_conn *conn,
                          struct synproxy_options *opts,
                          struct lb_device *dev) {
    struct tcp_hdr *nth;
    uint16_t win;
    uint16_t tcphdr_size;
    struct rte_mbuf *mcopy;

    /* For tcp seq adjust. */
    tcp_secret_seq_init(conn->lip, conn->rip, conn->lport, conn->rport,
                        rte_be_to_cpu_32(th->sent_seq) - 1, &conn->tseq);
    win = th->rx_win;
    tcphdr_size = sizeof(struct tcp_hdr) + synproxy_options_size(opts);
    rte_pktmbuf_reset(m);
    m->pkt_len = m->data_len =
        ETHER_HDR_LEN + sizeof(struct ipv4_hdr) + tcphdr_size;

    iph->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + tcphdr_size);
    iph->type_of_service = 0;
    iph->time_to_live = 63;
    iph->src_addr = conn->lip;
    iph->dst_addr = conn->rip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    nth = (struct tcp_hdr *)(iph + 1);
    nth->src_port = conn->lport;
    nth->dst_port = conn->rport;
    nth->sent_seq = rte_cpu_to_be_32(conn->tseq.isn);
    nth->recv_ack = 0;
    nth->data_off = tcphdr_size << 2;
    nth->tcp_flags = TCP_SYN_FLAG;
    nth->rx_win = win;
    nth->tcp_urp = 0;

    synproxy_syn_build_options((uint32_t *)(nth + 1), opts);

    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(iph, nth);

    mcopy = rte_pktmbuf_clone(m, m->pool);
    if (mcopy != NULL) {
        mcopy->userdata = dev;
        conn->proxy.syn_mbuf = mcopy;
    }

    lb_device_output(m, iph, dev);
}

int
synproxy_recv_client_ack(struct rte_mbuf *m, struct ipv4_hdr *iph,
                         struct tcp_hdr *th, struct lb_conn_table *ct,
                         struct lb_device *dev) {
    struct synproxy_options opts;
    struct lb_virt_service *vs = NULL;
    struct lb_real_service *rs = NULL;
    struct lb_conn *conn = NULL;

    if (!SYN(th) && ACK(th) && !RST(th) && !FIN(th) &&
        (vs = lb_vs_get(iph->dst_addr, th->dst_port, iph->next_proto_id)) &&
        (vs->flags & LB_VS_F_SYNPROXY)) {
        if (synproxy_cookie_ipv4_check(iph, th, &opts) &&
            (rs = lb_vs_get_rs(vs, iph->src_addr, th->src_port)) &&
            (conn = lb_conn_new(ct, iph->src_addr, th->src_port, rs, 1, dev))) {
            tcp_conn_set_state(conn, TCP_CONNTRACK_SYN_SENT);

            conn->proxy.isn = rte_be_to_cpu_32(th->recv_ack) - 1;

            synproxy_sent_backend_syn(m, iph, th, conn, &opts, dev);
        } else {
            rte_pktmbuf_free(m);
        }

        lb_vs_put(vs);
        if (conn == NULL && rs != NULL)
            lb_vs_put_rs(rs);
        return 0;
    } else {
        if (vs != NULL)
            lb_vs_put(vs);
        return 1;
    }
}

static void
synproxy_sent_ack_to_backend(struct rte_mbuf *m, struct lb_conn *conn,
                             struct lb_device *dev) {
    struct ipv4_hdr *iph;
    struct tcp_hdr *th;

    iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, ETHER_HDR_LEN);
    iph->src_addr = conn->lip;
    iph->dst_addr = conn->rip;

    th = TCP_HDR(iph);
    th->src_port = conn->lport;
    th->dst_port = conn->rport;
    tcp_secret_seq_adjust_client(th, &conn->tseq);
    synproxy_seq_adjust_client(th, &conn->proxy);
    tcp_opt_add_toa(m, iph, th, conn->cip, conn->cport);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    lb_device_output(m, iph, dev);
}

static void
synproxy_fwd_synack_to_client(struct rte_mbuf *m, struct ipv4_hdr *iph,
                              struct tcp_hdr *th, struct lb_conn *conn,
                              struct lb_device *dev) {
    iph->src_addr = conn->vip;
    iph->dst_addr = conn->cip;
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    synproxy_seq_adjust_backend(th, &conn->proxy);
    tcp_secret_seq_adjust_backend(th, &conn->tseq);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    lb_device_output(m, iph, dev);
}

static void
synproxy_fwd_rst_to_client(struct rte_mbuf *m, struct ipv4_hdr *iph,
                           struct tcp_hdr *th, struct lb_conn *conn,
                           struct lb_device *dev) {
    iph->src_addr = conn->vip;
    iph->dst_addr = conn->cip;
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    th->sent_seq = rte_cpu_to_be_32(conn->proxy.isn + 1);
    th->recv_ack = 0;
    th->tcp_flags = TCP_RST_FLAG;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    lb_device_output(m, iph, dev);
}

int
synproxy_recv_backend_synack(struct rte_mbuf *m, struct ipv4_hdr *iph,
                             struct tcp_hdr *th, struct lb_conn *conn,
                             struct lb_device *dev) {
    if (SYN(th) && ACK(th) && !RST(th) && !FIN(th) &&
        (conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT)) {

        conn->proxy.oft = rte_be_to_cpu_32(th->sent_seq) - conn->proxy.isn;

        rte_pktmbuf_free(conn->proxy.syn_mbuf);
        conn->proxy.syn_mbuf = NULL;

        if (conn->proxy.ack_mbuf != NULL) {
            tcp_conn_set_state(conn, TCP_CONNTRACK_ESTABLISHED);

            /* Free SYNACK, and send ACK to backend. */
            rte_pktmbuf_free(m);
            synproxy_sent_ack_to_backend(conn->proxy.ack_mbuf, conn, dev);
            conn->proxy.ack_mbuf = NULL;
        } else {
            tcp_conn_set_state(conn, TCP_CONNTRACK_SYN_RECV);

            /* FWD SYNACK to client. */
            synproxy_fwd_synack_to_client(m, iph, th, conn, dev);
        }
        return 0;
    } else if (RST(th) && (conn->flags & LB_CONN_F_SYNPROXY) &&
               (conn->state == TCP_CONNTRACK_SYN_SENT)) {
        tcp_conn_set_state(conn, TCP_CONNTRACK_CLOSE);

        /* FWD RST to client. */
        synproxy_fwd_rst_to_client(m, iph, th, conn, dev);
        return 0;
    }
    return 1;
}
