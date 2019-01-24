/* Copyright (c) 2018. TIG developer. */

#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_timer.h>

#include "lb.h"
#include "lb_connection.h"
#include "lb_fnat_laddr.h"
#include "lb_service.h"

typedef struct {
    uint64_t as_u64[5];
} hash_key_40_t;

static inline void
make_hash_key_40(hash_key_40_t *k, ip46_address_t *saddr, ip46_address_t *daddr,
                 uint16_t sport, uint16_t dport) {
    k->as_u64[0] = saddr->as_u64[0];
    k->as_u64[1] = saddr->as_u64[1];
    k->as_u64[2] = daddr->as_u64[0];
    k->as_u64[3] = daddr->as_u64[1];
    k->as_u64[4] = (uint64_t)sport << 32 | (uint64_t)dport;
}

static void
conn_timer_expire(struct rte_timer *timer, void *arg) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_conn_table *table = arg;

    (void)timer;
    rte_spinlock_lock(&table->tw_spinlock[lcore_id]);
    lb_tw_timer_wheel_expire(&table->timer_wheels[lcore_id]);
    rte_spinlock_unlock(&table->tw_spinlock[lcore_id]);
}

struct lb_conn_table *
lb_conn_table_create(lb_proto_t proto, uint32_t timer_interval) {
    uint32_t lcore_id;
    struct lb_conn_table *table;
    struct rte_hash_parameters hash_param;
    char hash_name[RTE_HASH_NAMESIZE];
    char mp_name[RTE_MEMPOOL_NAMESIZE];
    uint32_t size;

    table = rte_malloc(NULL, sizeof(struct lb_conn_table), 0);
    if (!table) {
        return NULL;
    }

    table->proto = proto;

    size = lb_fnat_laddrs_num * 65536;
    snprintf(mp_name, sizeof(mp_name), "ct_mp%p", table);
    table->conn_pool =
        rte_mempool_create(mp_name, size, sizeof(struct lb_connection), 0, 0,
                           NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
    if (!table->conn_pool) {
        log_err("%s(): Create conn mempool failed, %s\n", __func__,
                rte_strerror(rte_errno));
        return NULL;
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        memset(&hash_param, 0, sizeof(hash_param));
        snprintf(hash_name, sizeof(hash_name), "ct_hash-%p-%u", table,
                 lcore_id);
        hash_param.name = hash_name;
        hash_param.entries = size * 2;
        hash_param.key_len = sizeof(hash_key_40_t);
        hash_param.hash_func = rte_hash_crc;
        hash_param.socket_id = SOCKET_ID_ANY;
        if (!(table->conn_hashs[lcore_id] = rte_hash_create(&hash_param))) {
            log_err("%s(): Create conn hash table failed, %s.\n", __func__,
                    rte_strerror(rte_errno));
            return NULL;
        }
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        int rc;

        lb_tw_timer_wheel_init(&table->timer_wheels[lcore_id], timer_interval);
        rte_timer_init(&table->timers[lcore_id]);
        rc = rte_timer_reset(&table->timers[lcore_id],
                             MS_TO_CYCLES(timer_interval), PERIODICAL, lcore_id,
                             conn_timer_expire, table);
        if (rc < 0) {
            log_err("%s(): reset timer failed.\n", __func__);
            return NULL;
        }
        rte_spinlock_init(&table->tw_spinlock[lcore_id]);
    }

    return table;
}

static struct lb_connection *
conn_alloc_and_init(struct lb_conn_table *table, ip46_address_t *caddr,
                    uint16_t cport, struct lb_real_service *rs,
                    uint8_t is_synproxy) {
    uint32_t lcore_id = rte_lcore_id();
    hash_key_40_t _k, *k = &_k;
    struct rte_mempool *pool = table->conn_pool;
    struct rte_hash *h = table->conn_hashs[lcore_id];
    struct lb_connection *conn;
    struct lb_virt_service *vs = rs->virt_service;

    if (rte_mempool_get(pool, (void **)&conn) < 0) {
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));

    if (lb_fnat_laddr_and_port_get(table->proto,
                                   ip46_address_is_ip4(&rs->raddr),
                                   &conn->fnat_laddr, &conn->lport) < 0) {
        rte_mempool_put(pool, conn);
        return NULL;
    }

    conn->table = table;
    ip46_address_copy(&conn->caddr, caddr);
    ip46_address_copy(&conn->vaddr, &vs->vaddr);
    ip46_address_copy(&conn->laddr, &conn->fnat_laddr->ip46);
    ip46_address_copy(&conn->raddr, &rs->raddr);
    conn->cport = cport;
    conn->vport = vs->vport;
    conn->rport = rs->rport;
    if (rs->virt_service->flags & LB_VS_F_TOA)
        conn->flags |= LB_CONN_F_TOA;
    if (is_synproxy)
        conn->flags |= LB_CONN_F_SYNPROXY;
    conn->real_service = rs;

    make_hash_key_40(k, &conn->caddr, &conn->vaddr, conn->cport, conn->vport);
    if (rte_hash_add_key_data(h, k, conn) < 0) {
        lb_fnat_laddr_and_port_put(table->proto, conn->fnat_laddr, conn->lport);
        rte_mempool_put(pool, conn);
        return NULL;
    }

    make_hash_key_40(k, &conn->raddr, &conn->laddr, conn->rport, conn->lport);
    if (rte_hash_add_key_data(h, k, conn) < 0) {
        make_hash_key_40(k, &conn->caddr, &conn->vaddr, conn->cport,
                         conn->vport);
        rte_hash_del_key(h, k);
        lb_fnat_laddr_and_port_put(table->proto, conn->fnat_laddr, conn->lport);
        rte_mempool_put(pool, conn);
        return NULL;
    }

    return conn;
}

struct lb_connection *
lb_connection_create(struct lb_conn_table *table, void *caddr, void *vaddr,
                     uint16_t cport, uint16_t vport, uint8_t is_synproxy,
                     uint8_t is_ip4) {
    struct lb_virt_service *vs = NULL;
    struct lb_real_service *rs = NULL;
    lb_proto_t proto = table->proto;
    struct lb_connection *conn;
    ip46_address_t sip46;

    if (is_ip4)
        ip46_address_set_ip4(&sip46, caddr);
    else
        ip46_address_set_ip6(&sip46, caddr);
    if ((vs = lb_vs_get(vaddr, vport, proto, is_ip4)) &&
        (rs = lb_vs_get_rs(vs, caddr, cport, is_ip4)) &&
        (conn = conn_alloc_and_init(table, &sip46, cport, rs, is_synproxy))) {
        lb_vs_put(vs);
        return conn;
    } else {
        lb_rs_put(rs);
        lb_vs_put(vs);
        return NULL;
    }
}

void
lb_connection_destory(struct lb_connection *conn) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_conn_table *table = conn->table;
    struct rte_mempool *pool = table->conn_pool;
    struct rte_hash *h = table->conn_hashs[lcore_id];
    hash_key_40_t _k, *k = &_k;

    make_hash_key_40(k, &conn->caddr, &conn->vaddr, conn->cport, conn->vport);
    rte_hash_del_key(h, k);

    make_hash_key_40(k, &conn->raddr, &conn->laddr, conn->rport, conn->lport);
    rte_hash_del_key(h, k);

    lb_fnat_laddr_and_port_put(table->proto, conn->fnat_laddr, conn->lport);
    lb_rs_put(conn->real_service);
    rte_mempool_put(pool, conn);
}

static inline struct lb_connection *
conn_lookup_inline(struct lb_conn_table *table, void *saddr, void *daddr,
                   uint16_t sport, uint16_t dport, lb_direction_t *dir) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_hash *h = table->conn_hashs[lcore_id];
    hash_key_40_t _k, *k = &_k;
    struct lb_connection *conn;

    make_hash_key_40(k, saddr, daddr, sport, dport);
    if (rte_hash_lookup_data(h, k, (void **)&conn) < 0) {
        *dir = LB_DIR_OUT2IN;
        return NULL;
    }
    if (conn->cport == sport && ip46_address_cmp(&conn->caddr, saddr) == 0) {
        *dir = LB_DIR_OUT2IN;
    } else {
        *dir = LB_DIR_IN2OUT;
    }
    return conn;
}

struct lb_connection *
lb_connection_lookup(struct lb_conn_table *table, void *saddr, void *daddr,
                     uint16_t sport, uint16_t dport, lb_direction_t *dir,
                     uint8_t is_ip4) {
    ip46_address_t sip46, dip46;

    if (is_ip4) {
        ip46_address_set_ip4(&sip46, saddr);
        ip46_address_set_ip4(&dip46, daddr);
    } else {
        ip46_address_set_ip6(&sip46, saddr);
        ip46_address_set_ip6(&dip46, daddr);
    }
    return conn_lookup_inline(table, &sip46, &dip46, sport, dport, dir);
}