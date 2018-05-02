/* Copyright (c) 2018. TIG developer. */

#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_udp.h>

#include <unixctl_command.h>

#include "lb_clock.h"
#include "lb_conn.h"
#include "lb_format.h"
#include "lb_proto.h"

static struct lb_conn_table lb_conn_tbls[RTE_MAX_LCORE];
static uint32_t udp_timeout = 30 * LB_CLOCK_HZ;

static void
udp_set_conntrack_state(struct lb_conn *conn, __rte_unused struct udp_hdr *uh,
                        int dir) {
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t lcore_id = rte_lcore_id();

    if (dir == LB_DIR_ORIGINAL) {
        if (!(conn->flags & LB_CONN_F_ACTIVE)) {
            conn->flags |= LB_CONN_F_ACTIVE;
            rte_atomic32_add(&rs->active_conns, 1);
            rte_atomic32_add(&vs->active_conns, 1);
            vs->stats[lcore_id].conns += 1;
            rs->stats[lcore_id].conns += 1;
        }
    } else {
        if (conn->flags & LB_CONN_F_ACTIVE) {
            conn->flags &= ~LB_CONN_F_ACTIVE;
            rte_atomic32_add(&rs->active_conns, -1);
            rte_atomic32_add(&vs->active_conns, -1);
        }
    }
}

static void
udp_set_packet_stats(struct lb_conn *conn, struct rte_mbuf *m, uint8_t dir) {
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t cid = rte_lcore_id();

    vs->stats[cid].bytes[dir] += m->pkt_len;
    vs->stats[cid].packets[dir] += 1;
    rs->stats[cid].bytes[dir] += m->pkt_len;
    rs->stats[cid].packets[dir] += 1;
}

static int
udp_conn_timer_expire_cb(struct lb_conn *conn, uint32_t ctime) {
    if (ctime - conn->use_time > conn->timeout)
        return 0;
    else
        return -1;
}

static struct lb_conn *
udp_conn_schedule(struct lb_conn_table *ct, struct ipv4_hdr *iph,
                  struct udp_hdr *uh, struct lb_device *dev) {
    struct lb_virt_service *vs = NULL;
    struct lb_real_service *rs = NULL;
    struct lb_conn *conn = NULL;

    if ((vs = lb_vs_get(iph->dst_addr, uh->dst_port, iph->next_proto_id)) &&
        (rs = lb_vs_get_rs(vs, iph->src_addr, uh->src_port)) &&
        (conn = lb_conn_new(ct, iph->src_addr, uh->src_port, rs, 0, dev))) {
        lb_vs_put(vs);
        return conn;
    }
    if (vs != NULL) {
        lb_vs_put(vs);
    }
    if (rs != NULL) {
        lb_vs_put_rs(rs);
    }

    return NULL;
}

static int
udp_fullnat_recv_client(struct rte_mbuf *m, struct ipv4_hdr *iph,
                        struct udp_hdr *uh, struct lb_conn_table *ct,
                        struct lb_conn *conn, struct lb_device *dev) {
    if (conn != NULL) {
        lb_conn_expire(ct, conn);
        conn = NULL;
    }

    if (conn == NULL) {
        conn = udp_conn_schedule(ct, iph, uh, dev);
        if (conn == NULL) {
            rte_pktmbuf_free(m);
            return 0;
        }
    }

    udp_set_conntrack_state(conn, uh, LB_DIR_ORIGINAL);
    udp_set_packet_stats(conn, m, LB_DIR_ORIGINAL);

    iph->time_to_live = 63;
    iph->src_addr = conn->lip;
    iph->dst_addr = conn->rip;
    uh->src_port = conn->lport;
    uh->dst_port = conn->rport;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph, uh);
    }

    return lb_device_output(m, iph, dev);
}

static int
udp_fullnat_recv_backend(struct rte_mbuf *m, struct ipv4_hdr *iph,
                         struct udp_hdr *uh, struct lb_conn *conn,
                         struct lb_device *dev) {
    udp_set_conntrack_state(conn, uh, LB_DIR_REPLY);
    udp_set_packet_stats(conn, m, LB_DIR_REPLY);

    iph->time_to_live = 63;
    iph->src_addr = conn->vip;
    iph->dst_addr = conn->cip;
    uh->src_port = conn->vport;
    uh->dst_port = conn->cport;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph, uh);
    }

    return lb_device_output(m, iph, dev);
}

static int
udp_fullnat_handle(struct rte_mbuf *m, struct ipv4_hdr *iph,
                   struct lb_device *dev) {
    struct lb_conn_table *ct;
    struct lb_conn *conn;
    struct udp_hdr *uh;
    uint8_t dir;
    int rc;

    ct = &lb_conn_tbls[rte_lcore_id()];
    uh = UDP_HDR(iph);

    conn = lb_conn_find(ct, iph->src_addr, iph->dst_addr, uh->src_port,
                        uh->dst_port, &dir);
    if (dir == LB_DIR_REPLY)
        rc = udp_fullnat_recv_backend(m, iph, uh, conn, dev);
    else
        rc = udp_fullnat_recv_client(m, iph, uh, ct, conn, dev);

    return rc;
}

static int
udp_fullnat_init(void) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    int rc;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        rc = lb_conn_table_init(ct, LB_IPPROTO_UDP, lcore_id, udp_timeout, NULL,
                                udp_conn_timer_expire_cb);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): lb_conn_table_init failed.\n", __func__);
            return rc;
        }
        RTE_LOG(INFO, USER1, "%s(): Create udp connection table on lcore%u.\n",
                __func__, lcore_id);
    }

    return 0;
}

static struct lb_proto proto_udp = {
    .id = IPPROTO_UDP,
    .type = LB_IPPROTO_UDP,
    .init = udp_fullnat_init,
    .fullnat_handle = udp_fullnat_handle,
};

LB_PROTO_REGISTER(proto_udp);

static void
udp_conn_dump_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                     __attribute__((unused)) int argc) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    struct lb_conn *conn;
    void *tmp;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        rte_spinlock_lock(&ct->spinlock);
        for_each_conn_safe(conn, &ct->timeout_list, next, tmp) {
            unixctl_command_reply(
                fd,
                "cip: " IPv4_BE_FMT ", cport: %u,"
                "vip: " IPv4_BE_FMT ", vport: %u,"
                "lip: " IPv4_BE_FMT ", lport: %u,"
                "rip: " IPv4_BE_FMT ", rport: %u,"
                "flags: 0x%x, usetime:%u, timeout=%u\n",
                IPv4_BE_ARG(conn->cip), rte_be_to_cpu_16(conn->cport),
                IPv4_BE_ARG(conn->vip), rte_be_to_cpu_16(conn->vport),
                IPv4_BE_ARG(conn->lip), rte_be_to_cpu_16(conn->lport),
                IPv4_BE_ARG(conn->rip), rte_be_to_cpu_16(conn->rport),
                conn->flags, conn->use_time, conn->timeout);
        }
        rte_spinlock_unlock(&ct->spinlock);
    }
}

UNIXCTL_CMD_REGISTER("udp/conn/dump", "", "Dump UDP connections.", 0, 0,
                     udp_conn_dump_cmd_cb);

static void
udp_conn_stats_normal(int fd) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;

    unixctl_command_reply(fd, "             ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        unixctl_command_reply(fd, "lcore%-5u  ", lcore_id);
    }
    unixctl_command_reply(fd, "\n");

    unixctl_command_reply(fd, "avail_conns  ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        unixctl_command_reply(fd, "%-10u  ", rte_mempool_avail_count(ct->mp));
    }
    unixctl_command_reply(fd, "\n");

    unixctl_command_reply(fd, "inuse_conns  ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        unixctl_command_reply(fd, "%-10u  ", rte_mempool_in_use_count(ct->mp));
    }
    unixctl_command_reply(fd, "\n");
}

static void
udp_conn_stats_json(int fd) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    uint8_t json_first_obj = 1;

    unixctl_command_reply(fd, "[");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        if (json_first_obj) {
            json_first_obj = 0;
            unixctl_command_reply(fd, "{");
        } else {
            unixctl_command_reply(fd, ",{");
        }
        unixctl_command_reply(fd, JSON_KV_32_FMT("lcore", ","), lcore_id);
        unixctl_command_reply(fd, JSON_KV_32_FMT("avail_conns", ","),
                              rte_mempool_avail_count(ct->mp));
        unixctl_command_reply(fd, JSON_KV_32_FMT("inuse_conns", ""),
                              rte_mempool_in_use_count(ct->mp));
        unixctl_command_reply(fd, "}");
    }
    unixctl_command_reply(fd, "]\n");
}

static void
udp_conn_stats_cmd_cb(int fd, char *argv[], int argc) {
    if (argc > 0 && strcmp(argv[0], "--json") == 0)
        udp_conn_stats_json(fd);
    else
        udp_conn_stats_normal(fd);
}

UNIXCTL_CMD_REGISTER("udp/conn/stats", "[--json].",
                     "Show the number of UDP connections.", 0, 1,
                     udp_conn_stats_cmd_cb);