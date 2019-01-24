/* Copyright (c) 2018. TIG developer. */

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_random.h>
#include <rte_tcp.h>

#include <cryptohash.h>

#include "lb.h"
#include "lb_connection.h"
#include "lb_device.h"
#include "lb_ip_address.h"
#include "lb_mib.h"
#include "lb_service.h"
#include "lb_tcp.h"
#include "lb_tcp_synproxy.h"

#define COOKIEBITS 24 /* Upper bits store count */
#define COOKIEMASK (((uint32_t)1 << COOKIEBITS) - 1)

/* Syncookies use a monotonic timer which increments every 60 seconds.
 * This counter is used both as a hash input and partially encoded into
 * the cookie value.  A cookie is only validated further if the delta
 * between the current counter value and the encoded one is less than this,
 * i.e. a sent cookie is valid only at most for 2*60 seconds (or less if
 * the counter advances immediately after a cookie is generated).
 */
#define MAX_SYNCOOKIE_AGE 2

static uint32_t syncookie_secret[2][16 - 4 + SHA_DIGEST_WORDS];

/*
 * MSS Values are chosen based on the 2011 paper
 * 'An Analysis of TCP Maximum Segement Sizes' by S. Alcock and R. Nelson.
 * Values ..
 *  .. lower than 536 are rare (< 0.2%)
 *  .. between 537 and 1299 account for less than < 1.5% of observed values
 *  .. in the 1300-1349 range account for about 15 to 20% of observed mss
 * values
 *  .. exceeding 1460 are very rare (< 0.04%)
 *
 *  1460 is the single most frequently announced mss value (30 to 46% depending
 *  on monitor location).  Table must be sorted.
 */
static uint16_t const ipv4_msstab[] = {
    536,
    1300,
    1440, /* 1440, 1452: PPPoE */
    1460,
};

/* RFC 2460, Section 8.3:
 * [ipv6 tcp] MSS must be computed as the maximum packet size minus 60 [..]
 *
 * Due to IPV6_MIN_MTU=1280 the lowest possible MSS is 1220, which allows
 * using higher values than ipv4 tcp syncookies.
 * The other values are chosen based on ethernet (1500 and 9k MTU), plus
 * one that accounts for common encap (PPPoe) overhead. Table must be sorted.
 */
static uint16_t const ipv6_msstab[] = {
    1280 - 60, /* IPV6_MIN_MTU - 60 */
    1480 - 60,
    1500 - 60,
    9000 - 60,
};

static void
syncookie_secret_init_once(void) {
    static int inited = 0;
    int i;

    if (inited)
        return;
    for (i = 0; i < 16 - 4 + SHA_DIGEST_WORDS; i++) {
        syncookie_secret[0][i] = rte_rand();
        syncookie_secret[1][i] = rte_rand();
    }
    inited = !inited;
}

static inline uint32_t
cookie_v4_hash(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport,
               uint32_t count, int c) {
    uint32_t cookie_scratch[16 + 5 + SHA_WORKSPACE_WORDS];
    uint32_t *tmp = cookie_scratch;

    syncookie_secret_init_once();

    memcpy(tmp + 4, syncookie_secret[c], sizeof(syncookie_secret[c]));
    tmp[0] = saddr;
    tmp[1] = daddr;
    tmp[2] = ((uint32_t)sport << 16) + (uint32_t)dport;
    tmp[3] = count;
    sha_transform(tmp + 16, (char *)tmp, tmp + 16 + 5);

    return tmp[17];
}

static inline uint32_t
cookie_v6_hash(const uint32_t *saddr, const uint32_t *daddr, uint16_t sport,
               uint16_t dport, uint32_t count, int c) {
    uint32_t cookie_scratch[16 + 5 + SHA_WORKSPACE_WORDS];
    uint32_t *tmp = cookie_scratch;

    syncookie_secret_init_once();

    /*
     * we have 320 bits of information to hash, copy in the remaining
     * 192 bits required for sha_transform, from the syncookie_secret
     * and overwrite the digest with the secret
     */
    memcpy(tmp + 10, syncookie_secret[c], 44);
    memcpy(tmp, saddr, 16);
    memcpy(tmp + 4, daddr, 16);
    tmp[8] = ((uint32_t)sport << 16) + (uint32_t)dport;
    tmp[9] = count;
    sha_transform(tmp + 16, (char *)tmp, tmp + 16 + 5);

    return tmp[17];
}

static inline uint32_t
tcp_syncookie_time(void) {
    return (uint32_t)(lb_time_now_sec() / 60);
}

static uint32_t
secure_tcp_syn_cookies_v4(uint32_t saddr, uint32_t daddr, uint16_t sport,
                          uint16_t dport, uint32_t sseq, uint32_t data) {
    /*
     * Compute the secure sequence number.
     * The output should be:
     *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
     *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
     * Where sseq is their sequence number and count increases every
     * minute by 1.
     * As an extra hack, we add a small "data" value that encodes the
     * MSS into the second hash value.
     */
    uint32_t count = tcp_syncookie_time();
    return (cookie_v4_hash(saddr, daddr, sport, dport, 0, 0) + sseq +
            (count << COOKIEBITS) +
            ((cookie_v4_hash(saddr, daddr, sport, dport, count, 1) + data) &
             COOKIEMASK));
}

static uint32_t
secure_tcp_syn_cookies_v6(const uint32_t *saddr, const uint32_t *daddr,
                          uint16_t sport, uint16_t dport, uint32_t sseq,
                          uint32_t data) {
    uint32_t count = tcp_syncookie_time();
    return (cookie_v6_hash(saddr, daddr, sport, dport, 0, 0) + sseq +
            (count << COOKIEBITS) +
            ((cookie_v6_hash(saddr, daddr, sport, dport, count, 1) + data) &
             COOKIEMASK));
}

static uint32_t
check_tcp_syn_cookie_v4(uint32_t cookie, uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport, uint32_t sseq) {
    uint32_t diff, count = tcp_syncookie_time();

    cookie -= cookie_v4_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

    diff = (count - (cookie >> COOKIEBITS)) & ((uint32_t)-1 >> COOKIEBITS);
    if (diff >= MAX_SYNCOOKIE_AGE)
        return (uint32_t)-1;

    return (cookie -
            cookie_v4_hash(saddr, daddr, sport, dport, count - diff, 1)) &
           COOKIEMASK;
}

static uint32_t
check_tcp_syn_cookie_v6(uint32_t cookie, const uint32_t *saddr,
                        const uint32_t *daddr, uint16_t sport, uint16_t dport,
                        uint32_t sseq) {
    uint32_t diff, count = tcp_syncookie_time();

    cookie -= cookie_v6_hash(saddr, daddr, sport, dport, 0, 0) + sseq;

    diff = (count - (cookie >> COOKIEBITS)) & ((uint32_t)-1 >> COOKIEBITS);
    if (diff >= MAX_SYNCOOKIE_AGE)
        return (uint32_t)-1;

    return (cookie -
            cookie_v6_hash(saddr, daddr, sport, dport, count - diff, 1)) &
           COOKIEMASK;
}

static uint32_t
tcp_v4_syncookie_init_sequence(const struct ipv4_hdr *ip4,
                               const struct tcp_hdr *th, uint16_t *mssp) {
    int mssind;
    const uint16_t mss = *mssp;

    for (mssind = RTE_DIM(ipv4_msstab) - 1; mssind; mssind--)
        if (mss >= ipv4_msstab[mssind])
            break;
    *mssp = ipv4_msstab[mssind];
    log_debug("%s(): mssind=%u\n", __func__, mssind);
    return secure_tcp_syn_cookies_v4(ip4->src_addr, ip4->dst_addr, th->src_port,
                                     th->dst_port,
                                     rte_be_to_cpu_32(th->sent_seq), mssind);
}

static uint32_t
tcp_v6_syncookie_init_sequence(const struct ipv6_hdr *ip6,
                               const struct tcp_hdr *th, uint16_t *mssp) {
    int mssind;
    const uint16_t mss = *mssp;

    for (mssind = RTE_DIM(ipv6_msstab) - 1; mssind; mssind--)
        if (mss >= ipv6_msstab[mssind])
            break;
    *mssp = ipv6_msstab[mssind];

    return secure_tcp_syn_cookies_v6(
        (const uint32_t *)ip6->src_addr, (const uint32_t *)ip6->dst_addr,
        th->src_port, th->dst_port, rte_be_to_cpu_32(th->sent_seq), mssind);
}

static uint32_t
tcp_v4_syncookie_check(const struct ipv4_hdr *ip4, const struct tcp_hdr *th,
                       uint32_t cookie) {
    uint32_t seq = rte_be_to_cpu_32(th->sent_seq) - 1;
    uint32_t mssind = check_tcp_syn_cookie_v4(
        cookie, ip4->src_addr, ip4->dst_addr, th->src_port, th->dst_port, seq);
    log_debug("%s(): mssind=%u\n", __func__, mssind);
    return mssind < RTE_DIM(ipv4_msstab) ? ipv4_msstab[mssind] : 0;
}

static uint32_t
tcp_v6_syncookie_check(const struct ipv6_hdr *ip6, const struct tcp_hdr *th,
                       uint32_t cookie) {
    uint32_t seq = rte_be_to_cpu_32(th->sent_seq) - 1;
    uint32_t mssind = check_tcp_syn_cookie_v6(
        cookie, (const uint32_t *)ip6->src_addr,
        (const uint32_t *)ip6->dst_addr, th->src_port, th->dst_port, seq);
    return mssind < RTE_DIM(ipv6_msstab) ? ipv6_msstab[mssind] : 0;
}

#define SYNPROXY_OPT_MSS 0x01
#define SYNPROXY_OPT_WSCALE 0x02
#define SYNPROXY_OPT_SACK_PERM 0x04
#define SYNPROXY_OPT_TIMESTAMP 0x08
#define SYNPROXY_OPT_ECN 0x10

struct synproxy_options {
    uint8_t options;
    uint8_t wscale;
    uint16_t mss;
    uint32_t tsval;
    uint32_t tsecr;
};

static void
synproxy_parse_options(struct tcp_hdr *th, struct synproxy_options *opts) {
    uint8_t *ptr;
    int len;

    memset(opts, 0, sizeof(*opts));

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
                    opts->mss = rte_be_to_cpu_16(*((uint16_t *)ptr));
                    opts->options |= SYNPROXY_OPT_MSS;
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW) {
                    opts->wscale = *ptr;
                    if (opts->wscale > 14)
                        opts->wscale = 14;
                    opts->options |= SYNPROXY_OPT_WSCALE;
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {
                    opts->tsval = rte_be_to_cpu_32(*((uint32_t *)ptr));
                    opts->tsecr = rte_be_to_cpu_32(*((uint32_t *)(ptr + 4)));
                    opts->options |= SYNPROXY_OPT_TIMESTAMP;
                }
                break;
            case TCPOPT_SACK_PERM:
                if (opsize == TCPOLEN_SACK_PERM)
                    opts->options |= SYNPROXY_OPT_SACK_PERM;
                break;
            }
            ptr += opsize - 2;
            len -= opsize;
        }
    }
}

static void
synproxy_rebuild_options(struct tcp_hdr *th,
                         const struct synproxy_options *opts) {
    uint8_t *ptr;
    int len;
    uint32_t *tmp;

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
                    if (opts->options & SYNPROXY_OPT_MSS) {
                        *(uint16_t *)ptr = rte_cpu_to_be_16(opts->mss);
                    } else {
                        *(ptr - 2) = TCPOPT_NOP;
                        *(ptr - 1) = TCPOPT_NOP;
                        *ptr = TCPOPT_NOP;
                        *(ptr + 1) = TCPOPT_NOP;
                    }
                }
                break;
            case TCPOPT_WINDOW:
                if (opsize == TCPOLEN_WINDOW) {
                    *(ptr - 2) = TCPOPT_NOP;
                    *(ptr - 1) = TCPOPT_NOP;
                    *ptr = TCPOPT_NOP;
                }
                break;
            case TCPOPT_TIMESTAMP:
                if (opsize == TCPOLEN_TIMESTAMP) {
                    *(ptr - 2) = TCPOPT_NOP;
                    *(ptr - 1) = TCPOPT_NOP;
                    tmp = (uint32_t *)ptr;
                    *tmp++ = 0x01010101;
                    *tmp = 0x01010101;
                }
                break;
            case TCPOPT_SACK_PERM:
                if (opsize == TCPOLEN_SACK_PERM) {
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

static unsigned int
synproxy_options_size(const struct synproxy_options *opts) {
    unsigned int size = 0;

    if (opts->options & SYNPROXY_OPT_MSS)
        size += TCPOLEN_MSS_ALIGNED;
    if (opts->options & SYNPROXY_OPT_TIMESTAMP)
        size += TCPOLEN_TSTAMP_ALIGNED;
    else if (opts->options & SYNPROXY_OPT_SACK_PERM)
        size += TCPOLEN_SACKPERM_ALIGNED;
    if (opts->options & SYNPROXY_OPT_WSCALE)
        size += TCPOLEN_WSCALE_ALIGNED;

    return size;
}

static void
synproxy_build_options(struct tcp_hdr *th,
                       const struct synproxy_options *opts) {
    uint32_t *ptr = (uint32_t *)(th + 1);
    uint8_t options = opts->options;

    if (options & SYNPROXY_OPT_MSS)
        *ptr++ = rte_cpu_to_be_32((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) |
                                  opts->mss);

    if (options & SYNPROXY_OPT_TIMESTAMP) {
        if (options & SYNPROXY_OPT_SACK_PERM)
            *ptr++ = rte_cpu_to_be_32(
                (TCPOPT_SACK_PERM << 24) | (TCPOLEN_SACK_PERM << 16) |
                (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
        else
            *ptr++ =
                rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                 (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);

        *ptr++ = rte_cpu_to_be_32(opts->tsval);
        *ptr++ = rte_cpu_to_be_32(opts->tsecr);
    } else if (options & SYNPROXY_OPT_SACK_PERM)
        *ptr++ = rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                  (TCPOPT_SACK_PERM << 8) | TCPOLEN_SACK_PERM);

    if (options & SYNPROXY_OPT_WSCALE)
        *ptr++ = rte_cpu_to_be_32((TCPOPT_NOP << 24) | (TCPOPT_WINDOW << 16) |
                                  (TCPOLEN_WINDOW << 8) | opts->wscale);
}

static void
synproxy_sent_backend_syn(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                          struct lb_connection *conn,
                          struct synproxy_options *opts, uint8_t is_ip4) {
    struct ipv4_hdr *niph4;
    struct ipv6_hdr *niph6;
    struct tcp_hdr *nth;
    uint16_t win;
    uint16_t tcphdr_size;
    struct ether_hdr *eth;

    (void)iph;
    win = th->rx_win;
    tcphdr_size = sizeof(struct tcp_hdr) + synproxy_options_size(opts);
    rte_pktmbuf_reset(m);

    nth = (struct tcp_hdr *)rte_pktmbuf_append(m, tcphdr_size);
    nth->src_port = conn->lport;
    nth->dst_port = conn->rport;
    nth->sent_seq = rte_cpu_to_be_32(conn->new_isn);
    nth->recv_ack = 0;
    nth->data_off = tcphdr_size << 2;
    nth->tcp_flags = TCP_SYN_FLAG;
    nth->rx_win = win;
    nth->tcp_urp = 0;
    synproxy_build_options(nth, opts);

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->raddr))
            goto sent_ip4;
        else
            goto drop;
    } else {
        if (ip46_address_is_ip4(&conn->raddr))
            goto sent_ip4;
        else
            goto sent_ip6;
    }

sent_ip4:
    niph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv4_hdr));
    niph4->version_ihl = 0x45;
    niph4->type_of_service = 0;
    niph4->total_length = rte_cpu_to_be_16(sizeof(*niph4) + tcphdr_size);
    niph4->packet_id = 0;
    niph4->fragment_offset = 0;
    niph4->time_to_live = 64;
    niph4->next_proto_id = IPPROTO_TCP;
    niph4->src_addr = conn->laddr.ip4.as_u32;
    niph4->dst_addr = conn->raddr.ip4.as_u32;
    niph4->hdr_checksum = 0;
    niph4->hdr_checksum = rte_ipv4_cksum(niph4);
    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(niph4, nth);

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    conn->synproxy_synpkt = rte_pktmbuf_clone(m, m->pool);
    conn->synproxy_rto = TCP_RETRASYN_TIMEOUT_INIT;
    tcp_conn_timer_reset(conn, TCP_TIMER_RETRASYN, conn->synproxy_rto);
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&niph4->dst_addr);
    return;

sent_ip6:
    niph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv6_hdr));
    niph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
    niph6->payload_len = rte_cpu_to_be_16(tcphdr_size);
    niph6->proto = IPPROTO_TCP;
    niph6->hop_limits = 64;
    ip6_address_copy((ip6_address_t *)niph6->src_addr, &conn->laddr.ip6);
    ip6_address_copy((ip6_address_t *)niph6->dst_addr, &conn->raddr.ip6);
    nth->cksum = 0;
    nth->cksum = rte_ipv6_udptcp_cksum(niph6, nth);

    eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
    conn->synproxy_synpkt = rte_pktmbuf_clone(m, m->pool);
    conn->synproxy_rto = TCP_RETRASYN_TIMEOUT_INIT;
    tcp_conn_timer_reset(conn, TCP_TIMER_RETRASYN, conn->synproxy_rto);
    lb_inbound_device_ip6_output(m, (ip6_address_t *)niph6->dst_addr);
    return;

drop:
    rte_pktmbuf_free(m);
}

static void
synproxy_sent_backend_ack(const void *iph, const struct tcp_hdr *th,
                          struct lb_connection *conn, uint8_t is_ip4) {
    struct rte_mbuf *m;
    struct ipv4_hdr *niph4;
    struct ipv6_hdr *niph6;
    struct tcp_hdr *nth;
    uint16_t tcp_hdr_size;

    (void)iph;
    if (!(m = lb_pktmbuf_alloc())) {
        LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
        return;
    }

    tcp_hdr_size = sizeof(*nth);
    if ((conn->flags & LB_CONN_F_TOA))
        tcp_hdr_size +=
            is_ip4 ? sizeof(struct tcp_opt_toa) : sizeof(struct tcp_opt_toa6);

    nth = (struct tcp_hdr *)rte_pktmbuf_prepend(m, tcp_hdr_size);
    nth->src_port = conn->lport;
    nth->dst_port = conn->rport;
    nth->sent_seq = th->recv_ack;
    nth->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
    nth->data_off = tcp_hdr_size << 2;
    nth->tcp_flags = TCP_ACK_FLAG;
    nth->rx_win = th->rx_win;
    nth->tcp_urp = 0;
    if (is_ip4) {
        struct tcp_opt_toa *toa;

        toa = (struct tcp_opt_toa *)(nth + 1);
        toa->optcode = TCPOPT_TOA;
        toa->optsize = TCPOLEN_TOA;
        toa->port = conn->cport;
        toa->addr = conn->caddr.ip4.as_u32;
        goto sent_ip4;
    } else {
        struct tcp_opt_toa6 *toa6;

        toa6 = (struct tcp_opt_toa6 *)(nth + 1);
        toa6->optcode = TCPOPT_TOA6;
        toa6->optsize = TCPOLEN_TOA6;
        toa6->port = conn->cport;
        ip6_address_copy((ip6_address_t *)toa6->addr, &conn->caddr.ip6);
        goto sent_ip6;
    }

sent_ip4:
    niph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph4));
    niph4->version_ihl = 0x45;
    niph4->type_of_service = 0;
    niph4->total_length = rte_cpu_to_be_16(tcp_hdr_size + sizeof(*niph4));
    niph4->packet_id = 0;
    niph4->fragment_offset = 0;
    niph4->time_to_live = 64;
    niph4->next_proto_id = IPPROTO_TCP;
    niph4->src_addr = conn->laddr.ip4.as_u32;
    niph4->dst_addr = conn->raddr.ip4.as_u32;
    niph4->hdr_checksum = 0;
    niph4->hdr_checksum = rte_ipv4_cksum(niph4);
    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(niph4, nth);

    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&niph4->dst_addr);
    return;

sent_ip6:
    niph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph6));
    niph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
    niph6->payload_len = rte_cpu_to_be_16(tcp_hdr_size);
    niph6->proto = IPPROTO_TCP;
    niph6->hop_limits = 64;
    ip6_address_copy((ip6_address_t *)niph6->src_addr, &conn->laddr.ip6);
    ip6_address_copy((ip6_address_t *)niph6->dst_addr, &conn->raddr.ip6);
    nth->cksum = 0;
    nth->cksum = rte_ipv6_udptcp_cksum(niph6, nth);

    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_inbound_device_ip6_output(m, (ip6_address_t *)niph6->dst_addr);
}

static void
synproxy_sent_client_rst(const void *iph, const struct tcp_hdr *th,
                         struct lb_connection *conn, uint8_t is_ip4) {
    struct rte_mbuf *m;
    struct ipv4_hdr *niph4;
    struct ipv6_hdr *niph6;
    struct tcp_hdr *nth;

    (void)iph;
    (void)th;
    if (!(m = lb_pktmbuf_alloc())) {
        LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
        return;
    }

    nth = (struct tcp_hdr *)rte_pktmbuf_prepend(m, sizeof(*nth));
    nth->src_port = conn->vport;
    nth->dst_port = conn->cport;
    nth->recv_ack = 0;
    nth->sent_seq = rte_cpu_to_be_32(conn->synproxy_isn + 1);
    nth->data_off = sizeof(*nth) << 2;
    nth->tcp_flags = TCP_RST_FLAG;
    nth->rx_win = 0;
    nth->tcp_urp = 0;

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->caddr))
            goto sent_ip4;
        else
            goto sent_ip6;
    } else {
        if (ip46_address_is_ip4(&conn->caddr))
            goto drop;
        else
            goto sent_ip6;
    }

sent_ip4:
    niph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph4));
    niph4->version_ihl = 0x45;
    niph4->type_of_service = 0;
    niph4->total_length = rte_cpu_to_be_16(sizeof(*nth) + sizeof(*niph4));
    niph4->packet_id = 0;
    niph4->fragment_offset = 0;
    niph4->time_to_live = 64;
    niph4->next_proto_id = IPPROTO_TCP;
    niph4->src_addr = conn->vaddr.ip4.as_u32;
    niph4->dst_addr = conn->caddr.ip4.as_u32;
    niph4->hdr_checksum = 0;
    niph4->hdr_checksum = rte_ipv4_cksum(niph4);

    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(niph4, nth);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip4_output(m, (ip4_address_t *)&niph4->dst_addr);
    return;

sent_ip6:
    niph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph6));
    niph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
    niph6->payload_len = rte_cpu_to_be_16(sizeof(*nth));
    niph6->proto = IPPROTO_TCP;
    niph6->hop_limits = 64;
    ip6_address_copy((ip6_address_t *)niph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)niph6->dst_addr, &conn->caddr.ip6);

    nth->cksum = 0;
    nth->cksum = rte_ipv6_udptcp_cksum(niph6, nth);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip6_output(m, (ip6_address_t *)niph6->dst_addr);
    return;

drop:
    rte_pktmbuf_free(m);
}

static void
synproxy_sent_client_ack(const void *iph, const struct tcp_hdr *th,
                         struct lb_connection *conn, uint8_t is_ip4) {
    struct rte_mbuf *m;
    struct ipv4_hdr *niph4;
    struct ipv6_hdr *niph6;
    struct tcp_hdr *nth;

    (void)iph;
    if (!(m = lb_pktmbuf_alloc())) {
        LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
        return;
    }

    nth = (struct tcp_hdr *)rte_pktmbuf_prepend(m, sizeof(*nth));
    nth->src_port = conn->vport;
    nth->dst_port = conn->cport;
    nth->sent_seq = rte_cpu_to_be_32(conn->synproxy_isn + 1);
    nth->recv_ack = rte_cpu_to_be_32(conn->new_isn - conn->new_isn_oft + 1);
    nth->data_off = sizeof(*nth) << 2;
    nth->tcp_flags = TCP_ACK_FLAG;
    nth->rx_win = th->rx_win;
    nth->tcp_urp = 0;

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->caddr))
            goto sent_ip4;
        else
            goto sent_ip6;
    } else {
        if (ip46_address_is_ip4(&conn->caddr))
            goto drop;
        else
            goto sent_ip6;
    }

sent_ip4:
    niph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph4));
    niph4->version_ihl = 0x45;
    niph4->type_of_service = 0;
    niph4->total_length = rte_cpu_to_be_16(sizeof(*nth) + sizeof(*niph4));
    niph4->packet_id = 0;
    niph4->fragment_offset = 0;
    niph4->time_to_live = 64;
    niph4->next_proto_id = IPPROTO_TCP;
    niph4->src_addr = conn->vaddr.ip4.as_u32;
    niph4->dst_addr = conn->caddr.ip4.as_u32;
    niph4->hdr_checksum = 0;
    niph4->hdr_checksum = rte_ipv4_cksum(niph4);
    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(niph4, nth);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip4_output(m, (ip4_address_t *)&niph4->dst_addr);
    return;

sent_ip6:
    niph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*niph6));
    niph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
    niph6->payload_len = rte_cpu_to_be_16(sizeof(*nth));
    niph6->proto = IPPROTO_TCP;
    niph6->hop_limits = 64;
    ip6_address_copy((ip6_address_t *)niph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)niph6->dst_addr, &conn->caddr.ip6);
    nth->cksum = 0;
    nth->cksum = rte_ipv6_udptcp_cksum(niph6, nth);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip6_output(m, (ip6_address_t *)niph6->dst_addr);
    return;

drop:
    rte_pktmbuf_free(m);
}

static void
synproxy_sent_client_synack(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                            struct synproxy_options *opts, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iph;
    struct ipv6_hdr *iph6 = iph;
    uint16_t mss = opts->mss;
    uint32_t isn;
    uint32_t tmpaddr;
    uint16_t tmpport;
    ip6_address_t tmpaddr6;

    if (is_ip4) {
        isn = tcp_v4_syncookie_init_sequence(iph4, th, &mss);
        iph4->time_to_live = 64;
        iph4->packet_id = 0;
        tmpaddr = iph4->src_addr;
        iph4->src_addr = iph4->dst_addr;
        iph4->dst_addr = tmpaddr;
        iph4->hdr_checksum = 0;
        iph4->hdr_checksum = rte_ipv4_cksum(iph4);

        tmpport = th->src_port;
        th->src_port = th->dst_port;
        th->dst_port = tmpport;
        th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
        th->sent_seq = rte_cpu_to_be_32(isn);
        th->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
        th->rx_win = 0;
        th->tcp_urp = 0;
        synproxy_rebuild_options(th, opts);
        th->cksum = 0;
        th->cksum = rte_ipv4_udptcp_cksum(iph4, th);

        lb_outbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
    } else {
        isn = tcp_v6_syncookie_init_sequence(iph6, th, &mss);
        iph6->hop_limits = 64;
        ip6_address_copy(&tmpaddr6, (ip6_address_t *)iph6->src_addr);
        ip6_address_copy((ip6_address_t *)iph6->src_addr,
                         (ip6_address_t *)iph6->dst_addr);
        ip6_address_copy((ip6_address_t *)iph6->dst_addr, &tmpaddr6);

        tmpport = th->src_port;
        th->src_port = th->dst_port;
        th->dst_port = tmpport;
        th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
        th->sent_seq = rte_cpu_to_be_32(isn);
        th->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
        th->rx_win = 0;
        th->tcp_urp = 0;
        synproxy_rebuild_options(th, opts);
        th->cksum = 0;
        th->cksum = rte_ipv6_udptcp_cksum(iph6, th);

        lb_outbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
    }
}

int
synproxy_recv_client_syn(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                         uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iph;
    struct ipv6_hdr *iph6 = iph;
    struct lb_virt_service *vs = NULL;
    struct synproxy_options opts;

    if (SYN(th) && !(ACK(th) || RST(th) || FIN(th))) {
        if (is_ip4)
            vs = lb_vs_get(&iph4->dst_addr, th->dst_port, LB_PROTO_TCP, is_ip4);
        else
            vs = lb_vs_get(iph6->dst_addr, th->dst_port, LB_PROTO_TCP, is_ip4);
        if (vs && (vs->flags & LB_VS_F_SYNPROXY)) {
            lb_vs_put(vs);
            synproxy_parse_options(th, &opts);
            opts.options &= ~(SYNPROXY_OPT_WSCALE | SYNPROXY_OPT_SACK_PERM |
                              SYNPROXY_OPT_TIMESTAMP | SYNPROXY_OPT_ECN);
            synproxy_sent_client_synack(m, iph, th, &opts, is_ip4);
            LB_MIB_INC_STATS(SYNPROXY_RECV_SYN);
            return 0;
        }
    }
    lb_vs_put(vs);
    return 1;
}

int
synproxy_recv_client_ack(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                         uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iph;
    struct ipv6_hdr *iph6 = iph;
    struct synproxy_options opts;
    struct lb_connection *conn = NULL;
    uint16_t mss;

    if (SYN(th) || !ACK(th) || RST(th) || FIN(th))
        return 1;
    if (is_ip4) {
        if ((mss = tcp_v4_syncookie_check(
                 iph4, th, rte_be_to_cpu_32(th->recv_ack) - 1)) &&
            (conn = tcp_conn_create(iph4, th, 1, 1))) {
            opts.options = SYNPROXY_OPT_MSS;
            opts.mss = mss;
            synproxy_sent_backend_syn(m, iph4, th, conn, &opts, 1);
            LB_MIB_INC_STATS(SYNPROXY_ACCESS_ACK);
        } else {
            rte_pktmbuf_free(m);
        }
        return 0;
    } else {
        if ((mss = tcp_v6_syncookie_check(
                 iph6, th, rte_be_to_cpu_32(th->recv_ack) - 1)) &&
            (conn = tcp_conn_create(iph6, th, 1, 0))) {
            opts.options = SYNPROXY_OPT_MSS;
            opts.mss = mss;
            synproxy_sent_backend_syn(m, iph6, th, conn, &opts, 0);
            LB_MIB_INC_STATS(SYNPROXY_ACCESS_ACK);
        } else {
            rte_pktmbuf_free(m);
        }
        return 0;
    }
    return 1;
}

int
synproxy_recv_backend_synack(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                             struct lb_connection *conn, uint8_t is_ip4) {
    if (SYN(th) && ACK(th) && !RST(th) && !FIN(th) &&
        (conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT)) {

        conn->synproxy_isn_oft =
            conn->synproxy_isn - rte_be_to_cpu_32(th->sent_seq);

        tcp_conn_timer_stop(conn, TCP_TIMER_RETRASYN);
        rte_pktmbuf_free(conn->synproxy_synpkt);
        conn->synproxy_synpkt = NULL;

        /* TCP_CONNTRACK_SYN_RECV */
        tcp_set_conntrack_state(conn, th, LB_DIR_IN2OUT);
        synproxy_sent_backend_ack(iph, th, conn, is_ip4);
        synproxy_sent_client_ack(iph, th, conn, is_ip4);

        rte_pktmbuf_free(m);
        return 0;
    } else if (RST(th) && (conn->flags & LB_CONN_F_SYNPROXY) &&
               (conn->state == TCP_CONNTRACK_SYN_SENT)) {
        synproxy_sent_client_rst(iph, th, conn, is_ip4);
        tcp_set_conntrack_state(conn, th, LB_DIR_IN2OUT);
        rte_pktmbuf_free(m);
        return 0;
    }
    return 1;
}
