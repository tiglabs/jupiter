/* Copyright (c) 2018. TIG developer. */

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "lb.h"
#include "lb_connection.h"
#include "lb_device.h"
#include "lb_ip_address.h"
#include "lb_service.h"
#include "lb_timer_wheel.h"
#include "lb_udp.h"

static void udp_timer_timeout_cb(struct lb_tw_timer *timer, void *arg);
static void udp_conn_destory(struct lb_connection *conn);

enum {
    UDP_TIMER_TIMEOUT,
    UDP_TIMER_MAX,
};

static lb_tw_timer_cb_t udp_timer_cbs[UDP_TIMER_MAX] = {
    [UDP_TIMER_TIMEOUT] = udp_timer_timeout_cb,
};

static uint32_t udp_timeout = 30 * MS_PER_S;

static struct lb_conn_table *udp_conn_table;

static void
udp_conn_timer_reset(struct lb_connection *conn, uint32_t timer_id,
                     uint32_t timeout) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_tw_timer_wheel *tw = &udp_conn_table->timer_wheels[lcore_id];

    lb_tw_timer_restart(tw, &conn->timers[timer_id], timeout,
                        udp_timer_cbs[timer_id], conn);
}

static void
udp_conn_timer_stop(struct lb_connection *conn, uint32_t timer_id) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_tw_timer_wheel *tw = &udp_conn_table->timer_wheels[lcore_id];

    lb_tw_timer_stop(tw, &conn->timers[timer_id]);
}

static void
udp_timer_timeout_cb(struct lb_tw_timer *timer, void *arg) {
    struct lb_connection *conn = arg;

    (void)timer;
    udp_conn_destory(conn);
}

static void
udp_set_conntrack_state(struct lb_connection *conn, lb_direction_t dir) {
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t lcore_id = rte_lcore_id();
    uint32_t timeout;

    if (dir == LB_DIR_OUT2IN) {
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
    if (conn->flags & LB_CONN_F_ACTIVE)
        timeout = vs->est_timeout ? vs->est_timeout : udp_timeout;
    else
        timeout = 0;
    udp_conn_timer_reset(conn, UDP_TIMER_TIMEOUT, timeout);
}

static void
udp_set_packet_stats(struct lb_connection *conn, uint32_t pkt_len,
                     uint8_t dir) {
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t cid = rte_lcore_id();

    vs->stats[cid].bytes[dir] += pkt_len;
    vs->stats[cid].packets[dir] += 1;
    rs->stats[cid].bytes[dir] += pkt_len;
    rs->stats[cid].packets[dir] += 1;
}

static struct lb_connection *
udp_conn_lookup(void *iphdr, struct udp_hdr *uh, lb_direction_t *dir,
                uint8_t is_ip4) {
    struct lb_conn_table *table = udp_conn_table;
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    if (is_ip4) {
        return lb_connection_lookup(table, &iph4->src_addr, &iph4->dst_addr,
                                    uh->src_port, uh->dst_port, dir, is_ip4);
    } else {
        return lb_connection_lookup(table, iph6->src_addr, iph6->dst_addr,
                                    uh->src_port, uh->dst_port, dir, is_ip4);
    }
}

static struct lb_connection *
udp_conn_create(void *iphdr, struct udp_hdr *uh, uint8_t is_ip4) {
    struct lb_conn_table *table = udp_conn_table;
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;
    struct lb_connection *conn;

    if (is_ip4) {
        conn = lb_connection_create(table, &iph4->src_addr, &iph4->dst_addr,
                                    uh->src_port, uh->dst_port, 0, is_ip4);
        if (!conn)
            return NULL;
    } else {
        conn = lb_connection_create(table, iph6->src_addr, iph6->dst_addr,
                                    uh->src_port, uh->dst_port, 0, is_ip4);
        if (!conn)
            return NULL;
    }

    lb_tw_timer_init(&conn->timers[UDP_TIMER_TIMEOUT]);
    return conn;
}

static void
udp_conn_destory(struct lb_connection *conn) {
    udp_conn_timer_stop(conn, UDP_TIMER_TIMEOUT);
    lb_connection_destory(conn);
}

static void
udp_fnat64_out2in_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    struct ipv4_hdr *iph4;
    uint32_t vtc_flow;
    uint8_t hop_limits;

    vtc_flow = rte_be_to_cpu_32(iph6->vtc_flow);
    hop_limits = iph6->hop_limits;

    rte_pktmbuf_adj(m, sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr));
    iph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv4_hdr));

    iph4->version_ihl = 0x45;
    iph4->type_of_service = (vtc_flow & 0x0ff00000) >> 20;
    iph4->total_length =
        rte_cpu_to_be_16(sizeof(*iph4) + rte_be_to_cpu_16(uh->dgram_len));
    iph4->packet_id = 0;
    iph4->fragment_offset = 0;
    iph4->time_to_live = hop_limits - 1;
    iph4->next_proto_id = IPPROTO_TCP;
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->laddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->raddr.ip4);
    uh->src_port = conn->lport;
    uh->dst_port = conn->rport;
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph4, uh);
    }
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
udp_fnat46_in2out_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    struct ipv6_hdr *iph6;
    uint8_t tos;
    uint16_t iphdr_size;
    uint8_t ttl;
    uint16_t payload_len;

    tos = iph4->type_of_service;
    ttl = iph4->time_to_live;
    iphdr_size = (iph4->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
    payload_len = rte_be_to_cpu_16(iph4->total_length) - iphdr_size;
    rte_pktmbuf_adj(m, sizeof(struct ether_hdr) + iphdr_size);
    iph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv6_hdr));
    iph6->vtc_flow = rte_cpu_to_be_32((0x6 << 28) | ((uint32_t)tos << 20));
    iph6->payload_len = rte_cpu_to_be_16(payload_len);
    iph6->proto = IPPROTO_TCP;
    iph6->hop_limits = ttl - 1;
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->caddr.ip6);
    uh->src_port = conn->vport;
    uh->dst_port = conn->cport;
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv6_udptcp_cksum(iph6, uh);
    }
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
udp_fnat44_out2in_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->laddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->raddr.ip4);
    iph4->time_to_live--;
    uh->src_port = conn->lport;
    uh->dst_port = conn->rport;
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph4, uh);
    }
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
udp_fnat44_in2out_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->vaddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->caddr.ip4);
    iph4->time_to_live--;
    uh->src_port = conn->vport;
    uh->dst_port = conn->cport;
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv4_udptcp_cksum(iph4, uh);
    }
    lb_outbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
udp_fnat66_out2in_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->laddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->raddr.ip6);
    iph6->hop_limits--;
    uh->src_port = conn->lport;
    uh->dst_port = conn->rport;
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv6_udptcp_cksum(iph6, uh);
    }
    lb_inbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
udp_fnat66_in2out_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct udp_hdr *uh, struct lb_connection *conn) {
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->caddr.ip6);
    iph6->hop_limits--;
    uh->src_port = conn->vport;
    uh->dst_port = conn->cport;
    if (uh->dgram_cksum != 0) {
        uh->dgram_cksum = 0;
        uh->dgram_cksum = rte_ipv6_udptcp_cksum(iph6, uh);
    }
    lb_outbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
udp_in2out_input(struct rte_mbuf *m, void *iphdr, struct udp_hdr *uh,
                 struct lb_connection *conn, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    udp_set_conntrack_state(conn, LB_DIR_IN2OUT);
    udp_set_packet_stats(conn, m->pkt_len, LB_DIR_IN2OUT);

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->caddr)) {
            udp_fnat44_in2out_handle(m, iph4, uh, conn);
        } else {
            udp_fnat46_in2out_handle(m, iph4, uh, conn);
        }
    } else {
        if (ip46_address_is_ip4(&conn->caddr)) {
            // udp_fnat64_in2out_handle(m, conn);
            rte_pktmbuf_free(m);
        } else {
            udp_fnat66_in2out_handle(m, iph6, uh, conn);
        }
    }
}

static void
udp_out2in_input(struct rte_mbuf *m, void *iphdr, struct udp_hdr *uh,
                 struct lb_connection *conn, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    if (conn != NULL) {
        udp_conn_destory(conn);
        conn = NULL;
    }

    if (conn == NULL) {
        if (!(conn = udp_conn_create(iphdr, uh, is_ip4))) {
            rte_pktmbuf_free(m);
            return;
        }
    }

    if (!(conn->real_service->flags & LB_RS_F_AVAILABLE)) {
        udp_conn_destory(conn);
        rte_pktmbuf_free(m);
        return;
    }

    udp_set_conntrack_state(conn, LB_DIR_OUT2IN);
    udp_set_packet_stats(conn, m->pkt_len, LB_DIR_OUT2IN);

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->raddr)) {
            udp_fnat44_out2in_handle(m, iph4, uh, conn);
        } else {
            // udp_fnat46_out2in_handle(m, conn);
            rte_pktmbuf_free(m);
        }
    } else {
        if (ip46_address_is_ip4(&conn->raddr)) {
            udp_fnat64_out2in_handle(m, iph6, uh, conn);
        } else {
            udp_fnat66_out2in_handle(m, iph6, uh, conn);
        }
    }
}

static inline struct udp_hdr *
udp_header(struct ipv4_hdr *iph4) {
    return (struct udp_hdr *)((char *)iph4 +
                              ((iph4->version_ihl & IPV4_HDR_IHL_MASK) << 2));
}

static inline struct udp_hdr *
udp6_header(struct ipv6_hdr *iph6) {
    return (struct udp_hdr *)(iph6 + 1);
}

void
lb_udp_input(struct rte_mbuf *m, void *iphdr, uint8_t is_ip4) {
    struct udp_hdr *uh;
    lb_direction_t dir;
    struct lb_connection *conn;

    uh = is_ip4 ? udp_header(iphdr) : udp6_header(iphdr);
    conn = udp_conn_lookup(iphdr, uh, &dir, is_ip4);
    if (dir == LB_DIR_OUT2IN)
        udp_out2in_input(m, iphdr, uh, conn, is_ip4);
    else
        udp_in2out_input(m, iphdr, uh, conn, is_ip4);
}

int
lb_udp_module_init(void) {
    udp_conn_table = lb_conn_table_create(LB_PROTO_UDP, 100 /*ms*/);
    if (!udp_conn_table) {
        log_err("%s(): create udp connection table failed.\n", __func__);
        return -1;
    }
    return 0;
}