/* Copyright (c) 2017. TIG developer. */

#include <stdint.h>
#include <stdio.h>

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "lb_arp.h"
#include "lb_checksum.h"
#include "lb_config.h"
#include "lb_connection.h"
#include "lb_device.h"
#include "lb_proto_udp.h"
#include "lb_rwlock.h"
#include "lb_service.h"
#include "parser.h"
#include "unixctl_command.h"

#define IP_ICMP_DEST_UNREACH 3

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable		*/
#define ICMP_HOST_UNREACH 1 /* Host Unreachable		*/
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH 3 /* Port Unreachable		*/

#define IPV4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)
#define UDP_HDR(iph) (struct udp_hdr *)((char *)iph + IPV4_HLEN(iph))

struct udp_err_stats {
    uint64_t err_frag_pkt;
    uint64_t err_no_vs_match;
    uint64_t err_new_conn;
    uint64_t err_vs_invalid;
    uint64_t err_rs_resched;
    uint64_t err_rs_not_online;
    uint64_t err_build_l2hdr;
    uint64_t err_cql;
};

static struct lb_connection_table *udp_conn_table;
static struct udp_err_stats *udp_stats;

/* UDP连接延迟回收,       默认30s */
static uint64_t udp_conn_delay_recycle;

struct lb_connection_table *
lb_udp_connection_table_get(void) {
    return udp_conn_table;
}

#define UDP_STATS_INC(name)                                                    \
    do {                                                                       \
        udp_stats[rte_lcore_id()].name++;                                      \
    } while (0)

#define COUNT_STATS(name, count)                                               \
    do {                                                                       \
        uint32_t lcore_id;                                                     \
        count = 0;                                                             \
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {                                    \
            count += udp_stats[lcore_id].name;                                 \
        }                                                                      \
    } while (0)

static void
udp_stats_count(struct udp_err_stats *stats) {
    COUNT_STATS(err_frag_pkt, stats->err_frag_pkt);
    COUNT_STATS(err_no_vs_match, stats->err_no_vs_match);
    COUNT_STATS(err_new_conn, stats->err_new_conn);
    COUNT_STATS(err_vs_invalid, stats->err_vs_invalid);
    COUNT_STATS(err_rs_resched, stats->err_rs_resched);
    COUNT_STATS(err_rs_not_online, stats->err_rs_not_online);
    COUNT_STATS(err_build_l2hdr, stats->err_build_l2hdr);
    COUNT_STATS(err_cql, stats->err_cql);
}

static void
udp_stats_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}\n"
#define _(K, S) "\"" K "\":%" PRIu64 S
    static const char *output_json_fmt = _JSON_FMT(
        _("udp-conn-in-use", ",") _("udp-conn-avail", ",")
            _("udp-lport-in-use", ",") _("udp-lport-avail", ",")
                _("err-frag-packet", ",") _("err-no-vs-found", ",")
                    _("err-no-new-conn", ",") _("[err-no-valid-vs", ",")
                        _("err-no-rs-avail", ",") _("err-no-rs-online", ",")
                            _("err-no-arp-found", ",")
                                _("err-cql-rule-match", ""));
#undef _
#undef _JSON_FMT

#define _NORM_FMT(O) O
#define _(K, S) K ": %-20" PRIu64 "\n"
    static const char *output_norm_fmt = _NORM_FMT(
        _("udp-conn-in-use", ",") _("udp-conn-avail", ",")
            _("udp-lport-in-use", ",") _("udp-lport-avail", ",")
                _("err-frag-packet", ",") _("err-no-vs-found", ",")
                    _("err-no-new-conn", ",") _("[err-no-valid-vs", ",")
                        _("err-no-rs-avail", ",") _("err-no-rs-online", ",")
                            _("err-no-arp-found", ",")
                                _("err-cql-rule-match", ""));
#undef _
#undef _NORM_FMT

    struct udp_err_stats stats;
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
            lport_unused += rte_ring_count(addr->ports[LB_PROTO_UDP]);
        }
    }
    lport_in_used = (lb_cfg->netdev.l4_port_max - lb_cfg->netdev.l4_port_min) *
                        lb_cfg->netdev.local_ip_count -
                    lport_unused;
    udp_stats_count(&stats);
    unixctl_command_reply(
        fd, output_fmt,
        (uint64_t)rte_mempool_in_use_count(udp_conn_table->conn_pool),
        (uint64_t)rte_mempool_avail_count(udp_conn_table->conn_pool),
        (uint64_t)lport_in_used, (uint64_t)lport_unused, stats.err_frag_pkt,
        stats.err_no_vs_match, stats.err_new_conn, stats.err_vs_invalid,
        stats.err_rs_resched, stats.err_rs_not_online, stats.err_build_l2hdr,
        stats.err_cql);
}

static void
max_expire_num_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t max_expire_num;

    if (argc == 0) {
        unixctl_command_reply(fd, "UDP connection max_expire_num: %u\n",
                              udp_conn_table->max_expire_num);
        return;
    }
    if (parser_read_uint32(&max_expire_num, argv[0]) < 0) {
        unixctl_command_reply_error(fd, "Unknow option %s\n", argv[0]);
        return;
    }
    thread_write_lock();
    udp_conn_table->max_expire_num =
        (max_expire_num == 0 ? UINT32_MAX : max_expire_num);
    thread_write_unlock();
}

static void
conn_delay_recycle_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t sec;

    if (argc == 0) {
        unixctl_command_reply(fd, "UDP connection delay recycle: %us\n",
                              udp_conn_delay_recycle / rte_get_tsc_hz());
        return;
    }
    if (parser_read_uint32(&sec, argv[0]) < 0) {
        unixctl_command_reply_error(fd, "Unknow option %s\n", argv[0]);
        return;
    }
    thread_write_lock();
    udp_conn_delay_recycle = sec * rte_get_tsc_hz();
    thread_write_unlock();
}

void
lb_proto_udp_init(void) {
    struct udp_config *cfg = &lb_cfg->udp;

    udp_conn_table = lb_connection_table_create(
        "udp_conn", cfg->conn_max_num, cfg->conn_expire_max_num,
        cfg->conn_expire_period, cfg->conn_timer_period);
    if (!udp_conn_table) {
        rte_exit(EXIT_FAILURE, "Create udp connection table failed.\n");
    }

    udp_stats =
        rte_calloc(NULL, RTE_MAX_LCORE, sizeof(struct udp_err_stats), 0);
    if (!udp_stats) {
        rte_exit(EXIT_FAILURE, "Alloc memory for udp error stats failed.\n");
    }

    udp_conn_delay_recycle = 30 * rte_get_tsc_hz();

    unixctl_command_register(
        "udp/stats", "[--json].",
        "Show UDP error statistics and UDP resource usage.", 0, 1,
        udp_stats_cmd_cb);
    unixctl_command_register(
        "udp/max-expire-num", "[VALUE].",
        "Show or set max number of expired UDP connection each times.", 0, 1,
        max_expire_num_cmd_cb);
    unixctl_command_register("udp/conn-delay-recycle", "[VALUE].",
                             "Show or set active time of each UDP "
                             "connection. This can improve performance.",
                             0, 1, conn_delay_recycle_cmd_cb);
}

static void
udp_send_icmp(struct ipv4_hdr *iph_in, int type, int code) {
    struct rte_mbuf *mbuf;
    struct ipv4_hdr *iph;
    struct icmp_hdr *icmph;
    struct ether_hdr *ethh;
    uint32_t icmp_datalen = sizeof(struct ipv4_hdr) + 8;

    if (!(mbuf = rte_pktmbuf_alloc(lb_pktmbuf_pool))) {
        return;
    }
    icmph = (struct icmp_hdr *)rte_pktmbuf_prepend(
        mbuf, sizeof(struct icmp_hdr) + icmp_datalen);
    if (unlikely(!icmph)) {
        goto drop_pkt;
    }
    icmph->icmp_type = type;
    icmph->icmp_code = code;
    icmph->icmp_cksum = 0;
    icmph->icmp_ident = 0;
    icmph->icmp_seq_nb = 0;
    rte_memcpy(icmph + 1, iph_in, icmp_datalen);

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
    iph->next_proto_id = IPPROTO_ICMP;
    iph->src_addr = iph_in->dst_addr;
    iph->dst_addr = iph_in->src_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

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

#ifdef IPOA
static uint32_t ipoa_enable = 0;

static void
ip_opt_add_netaddr(struct rte_mbuf *mbuf, struct ipv4_hdr **iph, uint32_t ip,
                   uint16_t port) {
    uint8_t *ptr_o, *ptr_n;
    uint8_t *ptr;
    uint16_t opt_len;

    opt_len = ipv4_hlen(*iph) - 20;
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

#define is_from_client(conn, tuple)                                            \
    ((conn)->c4tuple.sip == (tuple)->sip &&                                    \
     (conn)->c4tuple.sport == (tuple)->sport)

#define is_new_conn(conn, tuple)                                               \
    (is_from_client(conn, tuple) &&                                            \
     (rte_get_tsc_cycles() - (conn)->create_time >= udp_conn_delay_recycle))

int
lb_udp_fullnat_handle(struct rte_mbuf *mbuf, struct ipv4_hdr *iph) {
    struct udp_hdr *uh = UDP_HDR(iph);
    struct lb_conn_4tuple tuple;
    struct lb_connection *conn;
    struct lb_virt_service *virt_srv;
    uint8_t from_client;

    if (rte_ipv4_frag_pkt_is_fragmented(iph)) {
        UDP_STATS_INC(err_frag_pkt);
        goto drop;
    }
    tuple.sip = iph->src_addr;
    tuple.dip = iph->dst_addr;
    tuple.sport = uh->src_port;
    tuple.dport = uh->dst_port;
    conn = lb_connection_find(udp_conn_table, &tuple);
    if (!conn) {
        virt_srv = lb_virt_service_find(tuple.dip, tuple.dport, IPPROTO_UDP);
        if (!virt_srv) {
            UDP_STATS_INC(err_no_vs_match);
            goto drop;
        }
        if (lb_virt_service_cql(virt_srv, tuple.sip, rte_get_tsc_cycles()) <
            0) {
            UDP_STATS_INC(err_cql);
            goto drop;
        }
        conn =
            lb_connection_new(udp_conn_table, virt_srv, tuple.sip, tuple.sport);
        if (!conn) {
            UDP_STATS_INC(err_new_conn);
            goto rst;
        }
    } else {
        virt_srv = conn->real_service->virt_service;
        if (virt_srv->deleted) {
            UDP_STATS_INC(err_vs_invalid);
            lb_connection_expire(conn, udp_conn_table);
            goto rst;
        }

        if (is_new_conn(conn, &tuple)) {
            if (lb_virt_service_cql(virt_srv, tuple.sip, rte_get_tsc_cycles()) <
                0) {
                UDP_STATS_INC(err_cql);
                goto drop;
            }
            if (lb_connection_update_real_service(udp_conn_table, conn,
                                                  virt_srv) < 0) {
                UDP_STATS_INC(err_rs_resched);
                lb_connection_expire(conn, udp_conn_table);
                goto rst;
            }
        } else {
            if (!conn->real_service->online) {
                UDP_STATS_INC(err_rs_not_online);
                lb_connection_expire(conn, udp_conn_table);
                goto rst;
            }
        }
    }
    from_client = is_from_client(conn, &tuple);
    LB_VS_STATS_INC(virt_srv, !from_client, mbuf->pkt_len);
    if (from_client) {
        iph->src_addr = conn->r4tuple.dip;
        iph->dst_addr = conn->r4tuple.sip;
        uh->src_port = conn->r4tuple.dport;
        uh->dst_port = conn->r4tuple.sport;
    } else {
        iph->dst_addr = conn->c4tuple.sip;
        iph->src_addr = conn->c4tuple.dip;
        uh->dst_port = conn->c4tuple.sport;
        uh->src_port = conn->c4tuple.dport;
    }
    iph->hdr_checksum = ipv4_cksum(iph, mbuf);
    uh->dgram_cksum = ipv4_udp_cksum(iph, uh, mbuf);
    if (lb_ether_build_header(mbuf, rte_pktmbuf_mtod(mbuf, struct ether_hdr *),
                              iph->dst_addr) < 0) {
        UDP_STATS_INC(err_build_l2hdr);
        LB_VS_STATS_DROP(virt_srv, !from_client);
        /* Mbuf will be released on the master lcore. */
        return -1;
    }
    lb_netdev_xmit(mbuf);
    LB_RS_STATS_INC(conn->real_service, !from_client, mbuf->pkt_len);
    return 0;

rst:
    udp_send_icmp(iph, IP_ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);

drop:
    rte_pktmbuf_free(mbuf);
    return -1;
}

