/* Copyright (c) 2017. TIG developer. */

#include <stdint.h>

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

#include "lb_arp.h"
#include "lb_checksum.h"
#include "lb_config.h"
#include "lb_connection.h"
#include "lb_conntrack_tcp.h"
#include "lb_device.h"
#include "lb_proto_tcp.h"
#include "lb_rwlock.h"
#include "lb_service.h"
#include "parser.h"
#include "unixctl_command.h"

#define IPV4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)
#define TCP_HDR(iph) (struct tcp_hdr *)((char *)(iph) + IPV4_HLEN(iph))

struct tcp_err_stats {
    uint64_t err_not_syn;
    uint64_t err_no_vs_match;
    uint64_t err_new_conn;
    uint64_t err_vs_invalid;
    uint64_t err_rs_resched;
    uint64_t err_rs_not_online;
    uint64_t err_build_l2hdr;
    uint64_t err_cql;
};

static struct tcp_err_stats *tcp_stats;
static struct lb_connection_table *tcp_conn_tbl;

struct lb_connection_table *
lb_tcp_connection_table_get(void) {
    return tcp_conn_tbl;
}

#define TCP_STATS_INC(name)                                                    \
    do {                                                                       \
        tcp_stats[rte_lcore_id()].name++;                                      \
    } while (0)

#define COUNT_STATS(name, count)                                               \
    do {                                                                       \
        uint32_t lcore_id;                                                     \
        count = 0;                                                             \
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {                                    \
            count += tcp_stats[lcore_id].name;                                 \
        }                                                                      \
    } while (0)

static void
tcp_stats_count(struct tcp_err_stats *stats) {
    COUNT_STATS(err_not_syn, stats->err_not_syn);
    COUNT_STATS(err_no_vs_match, stats->err_no_vs_match);
    COUNT_STATS(err_new_conn, stats->err_new_conn);
    COUNT_STATS(err_vs_invalid, stats->err_vs_invalid);
    COUNT_STATS(err_rs_resched, stats->err_rs_resched);
    COUNT_STATS(err_rs_not_online, stats->err_rs_not_online);
    COUNT_STATS(err_build_l2hdr, stats->err_build_l2hdr);
    COUNT_STATS(err_cql, stats->err_cql);
}

static void
tcp_conn_show_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}\n"
#define _(K, S) "\"" K "\":%" PRIu64 S
    static const char *output_json_fmt = _JSON_FMT(
        _("tcp-conn-in-use", ",") _("tcp-conn-avail", ",")
            _("tcp-lport-in-use", ",") _("tcp-lport-avail", ",")
                _("err-not-syn-packet", ",") _("err-no-vs-found", ",")
                    _("err-no-new-conn", ",") _("[err-no-valid-vs", ",")
                        _("err-no-rs-avail", ",") _("err-no-rs-online", ",")
                            _("err-no-arp-found", ",")
                                _("err-cql-rule-match", ""));
#undef _
#undef _JSON_FMT

#define _NORM_FMT(O) O
#define _(K, S) K ": %-20" PRIu64 "\n"
    static const char *output_norm_fmt = _NORM_FMT(
        _("tcp-conn-in-use", ",") _("tcp-conn-avail", ",")
            _("tcp-lport-in-use", ",") _("tcp-lport-avail", ",")
                _("err-not-syn-packet", ",") _("err-no-vs-found", ",")
                    _("err-no-new-conn", ",") _("[err-no-valid-vs", ",")
                        _("err-no-rs-avail", ",") _("err-no-rs-online", ",")
                            _("err-no-arp-found", ",")
                                _("err-cql-rule-match", ""));
#undef _
#undef _NORM_FMT

    struct tcp_err_stats stats;
    uint32_t lport_in_used = 0, lport_unused = 0;
    uint32_t lcore_id;
    const char *output_fmt;

    if (argc > 0) {
        if (strcmp(argv[0], "--json") == 0) {
            output_fmt = output_json_fmt;
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[0]);
            return;
        }
    } else {
        output_fmt = output_norm_fmt;
    }

    /* Pktmbuf-pool, local port */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        uint32_t i;
        struct lb_local_ipv4_addr *addr;

        for (i = 0; i < lb_netdev->local_ipaddr_count_percore[lcore_id]; i++) {
            addr = &lb_netdev->local_ipaddrs_percore[lcore_id][i];
            lport_unused += rte_ring_count(addr->ports[LB_PROTO_TCP]);
        }
    }
    lport_in_used = (lb_cfg->netdev.l4_port_max - lb_cfg->netdev.l4_port_min) *
                        lb_cfg->netdev.local_ip_count -
                    lport_unused;
    tcp_stats_count(&stats);
    unixctl_command_reply(
        fd, output_fmt,
        (uint64_t)rte_mempool_in_use_count(tcp_conn_tbl->conn_pool),
        (uint64_t)rte_mempool_avail_count(tcp_conn_tbl->conn_pool),
        (uint64_t)lport_in_used, (uint64_t)lport_unused, stats.err_not_syn,
        stats.err_no_vs_match, stats.err_new_conn, stats.err_vs_invalid,
        stats.err_rs_resched, stats.err_rs_not_online, stats.err_build_l2hdr,
        stats.err_cql);
}

#define TCPOPT_ADDR 200
#define TCPOLEN_ADDR 8 /* |opcode|size|ip+port| = 1 + 1 + 6 */

struct tcp_opt_toa {
    uint8_t optcode;
    uint8_t optsize;
    uint16_t port;
    uint32_t addr;
} __attribute__((__packed__));

static void
tcp_opt_add_toa(struct rte_mbuf *mbuf, struct ipv4_hdr *iph, struct tcp_hdr *th,
                struct lb_connection *conn) {
    struct tcp_opt_toa *toa;
    uint8_t *p, *q;

    /* ack packet */
    if (!(th->tcp_flags & TCP_ACK_FLAG) ||
        (th->tcp_flags & (TCP_FLAG_ALL & (~TCP_ACK_FLAG))))
        return;
    /* tcp header max length */
    if ((60 - (th->data_off >> 2)) < (int)sizeof(struct tcp_opt_toa))
        return;
    /* MTU */
    if (mbuf->pkt_len + sizeof(struct tcp_opt_toa) >= 1460)
        return;
    p = (uint8_t *)rte_pktmbuf_append(mbuf, sizeof(struct tcp_opt_toa));
    q = p + sizeof(struct tcp_opt_toa);
    while (p >= ((uint8_t *)th + (th->data_off >> 2))) {
        *q = *p;
        q--;
        p--;
    }
    toa = (struct tcp_opt_toa *)((uint8_t *)th + (th->data_off >> 2));
    toa->optcode = TCPOPT_ADDR;
    toa->optsize = TCPOLEN_ADDR;
    toa->port = conn->c4tuple.sport;
    toa->addr = conn->c4tuple.sip;
    th->data_off += (sizeof(struct tcp_opt_toa) / 4) << 4;
    iph->total_length = rte_cpu_to_be_16(rte_be_to_cpu_16(iph->total_length) +
                                         sizeof(struct tcp_opt_toa));
}

#if 0
static void
ip_opt_add_netaddr(struct rte_mbuf *mbuf, struct ipv4_hdr **iph, uint32_t ip,
                   uint16_t port) {
    uint8_t *ptr_o, *ptr_n;
    uint8_t *ptr;
    uint16_t opt_len;

    opt_len = IPV4_HLEN(*iph) - 20;
    if (opt_len + 8 > 40)
        return;

    ptr_o = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ptr_n = (uint8_t *)rte_pktmbuf_prepend(mbuf, 8);
    memmove(ptr_n, ptr_o, 34);
    opt_len += 8;
    *iph = (struct ipv4_hdr *)(ptr_n + 14);
    ptr = (uint8_t *)(*iph + 1);
    *ptr++ = 0x1F;
    *ptr++ = 8;
    *((uint16_t *)ptr) = port;
    ptr += 2;
    *((uint32_t *)ptr) = ip;
    (*iph)->version_ihl = 0x40 | ((opt_len + 20) / 4);
    (*iph)->total_length =
        rte_cpu_to_be_16(rte_be_to_cpu_16((*iph)->total_length) + 8);
}
#endif

#define TCPOPT_NOP 1       /* Padding */
#define TCPOPT_EOL 0       /* End of options */
#define TCPOPT_TIMESTAMP 8 /* Better RTT estimations/PAWS */
#define TCPOLEN_TIMESTAMP 10

static void
tcp_opt_reset_timestamp(struct tcp_hdr *th) {
    uint8_t *ptr;
    int len;

    ptr = (uint8_t *)(th + 1);
    len = (th->data_off >> 2) - sizeof(struct tcp_hdr);
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
            if ((opcode == TCPOPT_TIMESTAMP) && (opsize == TCPOLEN_TIMESTAMP)) {
                int i;
                for (i = 0; i < TCPOLEN_TIMESTAMP; i++) {
                    *(ptr - 2 + i) = TCPOPT_NOP;
                }
            }
            ptr += opsize - 2;
            len -= opsize;
        }
    }
}

static uint32_t timestamp_reset = 1;

static void
timestamp_reset_cmd_cb(int fd, char *argv[], int argc) {
    if (argc == 0) {
        unixctl_command_reply(fd, "TCP timestamp reset: %s\n",
                              timestamp_reset ? "enable" : "disable");
        return;
    }
    if (strcasecmp("enable", argv[0]) == 0) {
        timestamp_reset = 1;
    } else if (strcasecmp("disable", argv[0]) == 0) {
        timestamp_reset = 0;
    } else {
        unixctl_command_reply_error(fd, "Unknow options: %s\n", argv[0]);
    }
}

static void
max_expire_num_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t max_expire_num;

    if (argc == 0) {
        unixctl_command_reply(fd, "TCP connection max_expire_num: %u\n",
                              tcp_conn_tbl->max_expire_num);
        return;
    }
    if (parser_read_uint32(&max_expire_num, argv[0]) < 0) {
        unixctl_command_reply_error(fd, "Unknow option %s\n", argv[0]);
        return;
    }
    thread_write_lock();
    tcp_conn_tbl->max_expire_num =
        (max_expire_num == 0 ? UINT32_MAX : max_expire_num);
    thread_write_unlock();
}

void
lb_proto_tcp_init(void) {
    struct tcp_config *cfg = &lb_cfg->tcp;

    tcp_conn_tbl = lb_connection_table_create(
        "tcp_conn", cfg->conn_max_num, cfg->conn_expire_max_num,
        cfg->conn_expire_period, cfg->conn_timer_period);
    if (!tcp_conn_tbl) {
        rte_exit(EXIT_FAILURE, "Create tcp connection table failed.\n");
    }

    tcp_stats =
        rte_calloc(NULL, RTE_MAX_LCORE, sizeof(struct tcp_err_stats), 0);
    if (!tcp_stats) {
        rte_exit(EXIT_FAILURE, "Alloc memory for tcp info stats failed.\n");
    }
    unixctl_command_register(
        "tcp/stats", "[--json].",
        "Show TCP error statistics and TCP resource usage.", 0, 1,
        tcp_conn_show_cmd_cb);
    unixctl_command_register(
        "tcp/max-expire-num", "[VALUE].",
        "Show or set max number of expired TCP connection each times.", 0, 1,
        max_expire_num_cmd_cb);
    unixctl_command_register(
        "tcp/reset-timestamp", "[enable|disable].",
        "Show or set whether to clean TCP timestamp option.", 0, 1,
        timestamp_reset_cmd_cb);
}

static void
tcp_send_rst(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
             uint16_t dst_port, struct tcp_hdr *th0) {
    struct rte_mbuf *mbuf;
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;
    struct tcp_hdr *th;

    if (!(mbuf = rte_pktmbuf_alloc(lb_pktmbuf_pool))) {
        return;
    }
    th = (struct tcp_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct tcp_hdr));
    if (unlikely(!th)) {
        goto drop_pkt;
    }
    th->src_port = src_port;
    th->dst_port = dst_port;
    if (th0->tcp_flags & TCP_ACK_FLAG) {
        th->sent_seq = th0->recv_ack;
        th->recv_ack = 0;
        th->tcp_flags = TCP_RST_FLAG;
    } else {
        th->sent_seq = 0;
        if (!(th0->tcp_flags & TCP_SYN_FLAG))
            th->recv_ack = rte_be_to_cpu_32(th0->sent_seq);
        else
            th->recv_ack =
                rte_cpu_to_be_32(rte_be_to_cpu_32(th0->sent_seq) + 1);
        th->tcp_flags = TCP_RST_FLAG;
        th->tcp_flags |= TCP_ACK_FLAG;
    }
    th->data_off = sizeof(struct tcp_hdr) << 2;
    th->rx_win = 0;
    th->tcp_urp = 0;

    iph = (struct ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct ipv4_hdr));
    if (unlikely(!iph)) {
        goto drop_pkt;
    }
    iph->version_ihl = 0x45;
    iph->type_of_service = 0;
    iph->total_length = rte_cpu_to_be_16(mbuf->data_len);
    iph->packet_id = rte_cpu_to_be_16(1);
    iph->fragment_offset = 0;
    iph->time_to_live = 16;
    iph->next_proto_id = IPPROTO_TCP;
    iph->src_addr = src_ip;
    iph->dst_addr = dst_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    ethh =
        (struct ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));
    if (unlikely(!ethh)) {
        goto drop_pkt;
    }
    if (lb_ether_build_header(mbuf, ethh, iph->dst_addr) < 0) {
        /* Don't call rte_pktmbuf_free().
           mbuf will be released on master lcore. */
        return;
    }
    lb_netdev_xmit(mbuf);
    return;

drop_pkt:
    rte_pktmbuf_free(mbuf);
}

#define is_syn_packet(th)                                                      \
    ((th->tcp_flags & TCP_SYN_FLAG) && !(th->tcp_flags & TCP_ACK_FLAG))
#define is_conn_active(conn) (conn->conntrack_flags & CONNTRACK_F_ACTIVE)

#define is_from_client(conn, tuple)                                            \
    ((conn)->c4tuple.sip == (tuple)->sip &&                                    \
     (conn)->c4tuple.sport == (tuple)->sport)

int
lb_tcp_fullnat_handle(struct rte_mbuf *mbuf, struct ipv4_hdr *iph) {
    struct tcp_hdr *th = TCP_HDR(iph);
    struct lb_conn_4tuple tuple;
    struct lb_connection *conn;
    struct lb_virt_service *virt_srv;
    uint8_t from_client;

    tuple.sip = iph->src_addr;
    tuple.dip = iph->dst_addr;
    tuple.sport = th->src_port;
    tuple.dport = th->dst_port;
    conn = lb_connection_find(tcp_conn_tbl, &tuple);
    if (!conn) {
        if (!is_syn_packet(th)) {
            TCP_STATS_INC(err_not_syn);
            goto drop;
        }
        virt_srv = lb_virt_service_find(tuple.dip, tuple.dport, IPPROTO_TCP);
        if (!virt_srv) {
            TCP_STATS_INC(err_no_vs_match);
            goto drop;
        }
        if (lb_virt_service_cql(virt_srv, tuple.sip, rte_get_tsc_cycles()) <
            0) {
            TCP_STATS_INC(err_cql);
            goto drop;
        }
        conn =
            lb_connection_new(tcp_conn_tbl, virt_srv, tuple.sip, tuple.sport);
        if (!conn) {
            TCP_STATS_INC(err_new_conn);
            goto rst;
        }
    } else {
        virt_srv = conn->real_service->virt_service;
        if (virt_srv->deleted) {
            TCP_STATS_INC(err_vs_invalid);
            lb_connection_expire(conn, tcp_conn_tbl);
            goto rst;
        }
        if (is_syn_packet(th) && !is_conn_active(conn)) {
            if (lb_virt_service_cql(virt_srv, tuple.sip, rte_get_tsc_cycles()) <
                0) {
                TCP_STATS_INC(err_cql);
                goto drop;
            }
            if (lb_connection_update_real_service(tcp_conn_tbl, conn,
                                                  virt_srv) < 0) {
                TCP_STATS_INC(err_rs_resched);
                lb_connection_expire(conn, tcp_conn_tbl);
                goto rst;
            }
        } else {
            /* 如果online为true，则RS一定没被删除 */
            if (!conn->real_service->online) {
                TCP_STATS_INC(err_rs_not_online);
                lb_connection_expire(conn, tcp_conn_tbl);
                goto rst;
            }
        }
    }
    if (timestamp_reset && is_syn_packet(th)) {
        tcp_opt_reset_timestamp(th);
    }
    from_client = is_from_client(conn, &tuple);
    LB_VS_STATS_INC(virt_srv, !from_client, mbuf->pkt_len);
    tcp_set_conntrack_state(conn, th, !from_client);
    if (from_client) {
        iph->src_addr = conn->r4tuple.dip;
        iph->dst_addr = conn->r4tuple.sip;
        th->src_port = conn->r4tuple.dport;
        th->dst_port = conn->r4tuple.sport;
    } else {
        iph->dst_addr = conn->c4tuple.sip;
        iph->src_addr = conn->c4tuple.dip;
        th->dst_port = conn->c4tuple.sport;
        th->src_port = conn->c4tuple.dport;
    }
    if (virt_srv->source_ip_transport && from_client) {
        tcp_opt_add_toa(mbuf, iph, th, conn);
    }
    iph->hdr_checksum = ipv4_cksum(iph, mbuf);
    th->cksum = ipv4_tcp_cksum(iph, th, mbuf);
    if (lb_ether_build_header(mbuf, rte_pktmbuf_mtod(mbuf, struct ether_hdr *),
                              iph->dst_addr) < 0) {
        TCP_STATS_INC(err_build_l2hdr);
        LB_VS_STATS_DROP(virt_srv, !from_client);
        /* Mbuf will be released on the master lcore. */
        return -1;
    }
    LB_RS_STATS_INC(conn->real_service, !from_client, mbuf->pkt_len);
    lb_netdev_xmit(mbuf);
    return 0;

rst:
    tcp_send_rst(tuple.dip, tuple.sip, tuple.dport, tuple.sport, th);

drop:
    rte_pktmbuf_free(mbuf);
    return -1;
}

