/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_CONNECTION_H__
#define __LB_CONNECTION_H__

#include <sys/queue.h>

#include <rte_hash.h>
#include <rte_mempool.h>
#include <rte_timer.h>

struct lb_conn_4tuple {
    uint32_t sip, dip;
    uint16_t sport, dport;
} __attribute__((__packed__));

struct lb_connection_table;
struct lb_virt_service;
struct lb_local_ipv4_addr;
struct lb_real_service;

struct lb_connection {
    TAILQ_ENTRY(lb_connection) next;
    struct lb_conn_4tuple c4tuple;
    struct lb_conn_4tuple r4tuple;
    hash_sig_t csig, rsig;

    uint8_t proto;

    uint64_t create_time;
    uint64_t recent_use_time;
    uint64_t expire_period;

    uint32_t conntrack_state;
    uint32_t conntrack_flags;

    struct lb_real_service *real_service;
    struct lb_local_ipv4_addr *local_ipaddr;
    struct lb_connection_table *table;
};

struct conn_err_stats {
    uint64_t err_max_conn;
    uint64_t err_alloc_conn;
    uint64_t err_no_laddr;
    uint64_t err_no_table_room;
    uint64_t err_rs_sched;
};

struct lb_connection_table {
    struct rte_mempool *conn_pool;
    struct rte_hash *conn_htbl_percore[RTE_MAX_LCORE];
    uint64_t table_size;
    uint64_t count[RTE_MAX_LCORE];
    TAILQ_HEAD(, lb_connection) conn_expire_tbl_percore[RTE_MAX_LCORE];
    struct rte_timer expire_timer_percore[RTE_MAX_LCORE];
    uint32_t conn_expire_period;
    uint32_t timer_period;
    uint32_t max_expire_num;
    struct conn_err_stats err_stats[RTE_MAX_LCORE];
};

struct lb_connection_table *lb_connection_table_create(const char *name,
                                                       uint32_t max_conn_num,
                                                       uint32_t max_expire_num,
                                                       uint32_t expire_period,
                                                       uint64_t timer_period);
struct lb_connection *lb_connection_new(struct lb_connection_table *table,
                                        struct lb_virt_service *virt_service,
                                        uint32_t cip, uint16_t cport);
struct lb_connection *lb_connection_find(struct lb_connection_table *table,
                                         struct lb_conn_4tuple *tuple);
int lb_connection_update_real_service(struct lb_connection_table *table,
                                      struct lb_connection *conn,
                                      struct lb_virt_service *virt_service);
void lb_connection_expire(struct lb_connection *conn,
                          struct lb_connection_table *table);

#endif

