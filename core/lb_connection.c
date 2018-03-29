/* Copyright (c) 2017. TIG developer. */

#include <sys/queue.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_timer.h>

#include "lb_connection.h"
#include "lb_device.h"
#include "lb_service.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
    for ((var) = TAILQ_FIRST((head));                                          \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

#define CONN_INIT(table, conn, virt_srv, real_srv, local_addr, lport, cip,     \
                  cport)                                                       \
    do {                                                                       \
        struct rte_hash *conn_htbl = table->conn_htbl_percore[rte_lcore_id()]; \
        conn->c4tuple.sip = cip;                                               \
        conn->c4tuple.dip = virt_srv->vip;                                     \
        conn->c4tuple.sport = cport;                                           \
        conn->c4tuple.dport = virt_srv->vport;                                 \
        conn->csig = rte_hash_hash(conn_htbl, &conn->c4tuple);                 \
        conn->r4tuple.sip = real_srv->rip;                                     \
        conn->r4tuple.dip = local_addr->ip;                                    \
        conn->r4tuple.sport = real_srv->rport;                                 \
        conn->r4tuple.dport = lport;                                           \
        conn->rsig = rte_hash_hash(conn_htbl, &conn->r4tuple);                 \
        conn->proto = virt_srv->proto_type;                                    \
        conn->create_time = rte_rdtsc();                                       \
        conn->recent_use_time = conn->create_time;                             \
        conn->expire_period = virt_srv->conn_expire_period;                    \
        rte_atomic32_add(&real_srv->refcnt, 1);                                \
        conn->real_service = real_srv;                                         \
        conn->local_ipaddr = local_addr;                                       \
        conn->conntrack_state = 0;                                             \
        conn->conntrack_flags = 0;                                             \
    } while (0)

static inline int
__conn_tbl_add(struct lb_connection_table *tbl, struct lb_connection *conn) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_hash *conn_htbl = tbl->conn_htbl_percore[lcore_id];

    if (rte_hash_add_key_with_hash_data(conn_htbl, (const void *)&conn->c4tuple,
                                        conn->csig, (void *)conn) < 0) {
        return -1;
    }
    if (rte_hash_add_key_with_hash_data(conn_htbl, (const void *)&conn->r4tuple,
                                        conn->rsig, (void *)conn) < 0) {
        rte_hash_del_key_with_hash(conn_htbl, (const void *)&conn->c4tuple,
                                   conn->csig);
        return -1;
    }
    TAILQ_INSERT_TAIL(&tbl->conn_expire_tbl_percore[lcore_id], conn, next);
    tbl->count[lcore_id]++;
    return 0;
}

static inline void
__conn_tbl_del(struct lb_connection_table *tbl, struct lb_connection *conn) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_hash *conn_htbl = tbl->conn_htbl_percore[lcore_id];

    rte_hash_del_key_with_hash(conn_htbl, (const void *)&conn->c4tuple,
                               conn->csig);
    rte_hash_del_key_with_hash(conn_htbl, (const void *)&conn->r4tuple,
                               conn->rsig);
    TAILQ_REMOVE(&tbl->conn_expire_tbl_percore[lcore_id], conn, next);
    tbl->count[lcore_id]--;
}

static inline int
is_connection_table_full(struct lb_connection_table *table) {
    uint32_t lcore_id = rte_lcore_id();
    return table->count[lcore_id] >= table->table_size;
}

struct lb_connection *
lb_connection_new(struct lb_connection_table *table,
                  struct lb_virt_service *virt_service, uint32_t cip,
                  uint16_t cport) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_connection *conn;
    struct lb_real_service *real_service;
    struct lb_local_ipv4_addr *local_addr;
    uint16_t lport;

    if (rte_atomic32_read(&virt_service->active_conns) >
        virt_service->max_conns) {
        table->err_stats[lcore_id].err_max_conn++;
        return NULL;
    }
    if (is_connection_table_full(table)) {
        table->err_stats[lcore_id].err_no_table_room++;
        return NULL;
    }
    if (rte_mempool_get(table->conn_pool, (void **)&conn) < 0) {
        table->err_stats[lcore_id].err_alloc_conn++;
        return NULL;
    }
    real_service = virt_service->sched->dispatch(virt_service, cip, cport);
    if (!real_service) {
        table->err_stats[lcore_id].err_rs_sched++;
        rte_mempool_put(table->conn_pool, conn);
        return NULL;
    }
    if (lb_local_ipv4_addr_get(&local_addr, &lport,
                               virt_service->proto_type == IPPROTO_TCP
                                   ? LB_PROTO_TCP
                                   : LB_PROTO_UDP) < 0) {
        table->err_stats[lcore_id].err_no_laddr++;
        rte_mempool_put(table->conn_pool, conn);
        return NULL;
    }
    CONN_INIT(table, conn, virt_service, real_service, local_addr, lport, cip,
              cport);
    if (__conn_tbl_add(table, conn) < 0) {
        lb_real_service_destory(conn->real_service);
        lb_local_ipv4_addr_put(conn->local_ipaddr, conn->r4tuple.dport,
                               conn->proto == IPPROTO_TCP ? LB_PROTO_TCP
                                                          : LB_PROTO_UDP);
        rte_mempool_put(table->conn_pool, conn);
        return NULL;
    }
    rte_atomic32_add(&conn->real_service->active_conns, 1);
    rte_atomic32_add(&conn->real_service->virt_service->active_conns, 1);
    LB_VS_CONN_INC(conn->real_service->virt_service);
    LB_RS_CONN_INC(conn->real_service);
    return conn;
}

void
lb_connection_expire(struct lb_connection *conn,
                     struct lb_connection_table *table) {
    rte_atomic32_add(&conn->real_service->active_conns, -1);
    rte_atomic32_add(&conn->real_service->virt_service->active_conns, -1);
    __conn_tbl_del(table, conn);
    lb_real_service_destory(conn->real_service);
    lb_local_ipv4_addr_put(conn->local_ipaddr, conn->r4tuple.dport,
                           conn->proto == IPPROTO_TCP ? LB_PROTO_TCP
                                                      : LB_PROTO_UDP);
    rte_mempool_put(table->conn_pool, conn);
}

struct lb_connection *
lb_connection_find(struct lb_connection_table *table,
                   struct lb_conn_4tuple *tuple) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_connection *conn;

    if (rte_hash_lookup_data(table->conn_htbl_percore[lcore_id],
                             (const void *)tuple, (void **)&conn) >= 0) {
        conn->recent_use_time = rte_rdtsc();
        TAILQ_REMOVE(&table->conn_expire_tbl_percore[lcore_id], conn, next);
        TAILQ_INSERT_TAIL(&table->conn_expire_tbl_percore[lcore_id], conn,
                          next);
        return conn;
    }
    return NULL;
}

int
lb_connection_update_real_service(struct lb_connection_table *table,
                                  struct lb_connection *conn,
                                  struct lb_virt_service *virt_service) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_hash *conn_htbl = table->conn_htbl_percore[lcore_id];
    struct lb_real_service *real_service;

    real_service = virt_service->sched->dispatch(
        virt_service, conn->c4tuple.sip, conn->c4tuple.sport);
    if (!real_service) {
        table->err_stats[lcore_id].err_rs_sched++;
        return -1;
    }
    if (conn->real_service != real_service) {
        rte_hash_del_key_with_hash(conn_htbl, (const void *)&conn->r4tuple,
                                   conn->rsig);
        TAILQ_REMOVE(&table->conn_expire_tbl_percore[lcore_id], conn, next);

        conn->create_time = conn->recent_use_time;
        conn->r4tuple.sip = real_service->rip;
        conn->r4tuple.sport = real_service->rport;
        conn->rsig = rte_hash_hash(conn_htbl, &conn->r4tuple);
        rte_hash_add_key_with_hash_data(conn_htbl, (const void *)&conn->r4tuple,
                                        conn->rsig, (void *)conn);
        TAILQ_INSERT_TAIL(&table->conn_expire_tbl_percore[lcore_id], conn,
                          next);
        conn->real_service = real_service;
		conn->conntrack_flags = 0;
		conn->conntrack_state = 0;
    }
    LB_VS_CONN_INC(conn->real_service->virt_service);
    LB_RS_CONN_INC(conn->real_service);
    return 0;
}

static inline int
is_connection_expire(struct lb_connection *conn, uint64_t cur_time) {
    return cur_time - conn->recent_use_time >= conn->expire_period;
}

static void
connnection_table_timer_cb(__attribute__((unused)) struct rte_timer *timer,
                           void *arg) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_connection_table *table = arg;
    uint32_t expire_count = 0;
    uint64_t cur_time = rte_rdtsc();
    struct lb_connection *conn;
    void *tmp;

    TAILQ_FOREACH_SAFE(conn, &table->conn_expire_tbl_percore[lcore_id], next,
                       tmp) {
        if (!is_connection_expire(conn, cur_time))
            break;
        lb_connection_expire(conn, table);
        if (++expire_count >= table->max_expire_num)
            break;
    }
}

struct lb_connection_table *
lb_connection_table_create(const char *name, uint32_t max_conn_num,
                           uint32_t max_expire_num, uint32_t expire_period,
                           uint64_t timer_period) {
    struct lb_connection_table *table;
    char mempool_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t lcore_id;

    table = rte_zmalloc(name, sizeof(struct lb_connection_table), 0);
    if (!table)
        rte_exit(EXIT_FAILURE, "Alloc memory %s for connection table failed.\n",
                 name);
    table->table_size = max_conn_num;
    table->conn_expire_period = expire_period * rte_get_tsc_hz();
    table->timer_period = timer_period * rte_get_tsc_hz();
    table->max_expire_num = (max_expire_num == 0 ? UINT32_MAX : max_expire_num);

    /* init mempool */
    snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE, "%s_pool", name);
    table->conn_pool = rte_mempool_create(
        mempool_name, max_conn_num, sizeof(struct lb_connection),
        256 /* cache size*/, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (!table->conn_pool)
        rte_exit(EXIT_FAILURE,
                 "Create mempool %s for connection table failed.\n",
                 mempool_name);

    /* init hash table */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        struct rte_hash_parameters params = {0};
        char htbl_name[RTE_HASH_NAMESIZE];

        snprintf(htbl_name, RTE_HASH_NAMESIZE, "%s_htbl%u", name, lcore_id);
        params.name = htbl_name;
        params.entries = max_conn_num;
        params.key_len = sizeof(struct lb_conn_4tuple);
        params.hash_func = rte_hash_crc;
        params.socket_id = rte_socket_id();
        table->conn_htbl_percore[lcore_id] = rte_hash_create(&params);
        if (!table->conn_htbl_percore[lcore_id])
            rte_exit(EXIT_FAILURE,
                     "Create hash table %s for connection table failed.\n",
                     htbl_name);
    }

    /* init timer */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        TAILQ_INIT(&table->conn_expire_tbl_percore[lcore_id]);
        rte_timer_init(&table->expire_timer_percore[lcore_id]);
        if (rte_timer_reset(&table->expire_timer_percore[lcore_id],
                            table->timer_period, PERIODICAL, lcore_id,
                            connnection_table_timer_cb, (void *)table) < 0)
            rte_exit(EXIT_FAILURE, "Add timer for connection table failed.\n");
    }
    return table;
}

