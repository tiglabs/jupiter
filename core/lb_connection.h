/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_CONNECTION_H__
#define __LB_CONNECTION_H__

#include <rte_rwlock.h>
#include <rte_timer.h>

#include "lb.h"
#include "lb_fnat_laddr.h"
#include "lb_ip_address.h"
#include "lb_timer_wheel.h"

#define LB_CONN_TIMER_MAX 4

#define LB_CONN_F_SYNPROXY (0x01)
#define LB_CONN_F_ACTIVE (0x02)
#define LB_CONN_F_TOA (0x4)

struct lb_conn_table;

struct lb_connection {
    struct lb_conn_table *table;

    ip46_address_t caddr, vaddr, laddr, raddr;
    uint16_t cport, vport, lport, rport;

    uint32_t flags;
    uint32_t state;

    struct lb_real_service *real_service;

    /* local ip and port */
    struct lb_fnat_laddr *fnat_laddr;

    struct lb_tw_timer timers[LB_CONN_TIMER_MAX];

    /* client isn + new_isn_oft = new_isn */
    uint32_t new_isn;
    uint32_t new_isn_oft;

    /* backend isn + synproxy_isn_oft = synproxy_isn */
    uint32_t synproxy_isn;
    uint32_t synproxy_isn_oft;
    uint32_t synproxy_rto;
    struct rte_mbuf *synproxy_synpkt;
};

struct lb_conn_table {
    lb_proto_t proto;
    struct rte_hash *conn_hashs[RTE_MAX_LCORE];
    struct rte_mempool *conn_pool;
    struct lb_tw_timer_wheel timer_wheels[RTE_MAX_LCORE];
    rte_spinlock_t tw_spinlock[RTE_MAX_LCORE];
    struct rte_timer timers[RTE_MAX_LCORE];
};

void lb_connection_destory(struct lb_connection *conn);
struct lb_connection *lb_connection_create(struct lb_conn_table *table,
                                           void *caddr, void *vaddr,
                                           uint16_t cport, uint16_t vport,
                                           uint8_t is_synproxy, uint8_t is_ip4);
struct lb_connection *lb_connection_lookup(struct lb_conn_table *table,
                                           void *saddr, void *daddr,
                                           uint16_t sport, uint16_t dport,
                                           lb_direction_t *dir, uint8_t is_ip4);
struct lb_conn_table *lb_conn_table_create(lb_proto_t proto,
                                           uint32_t timer_interval);

#endif