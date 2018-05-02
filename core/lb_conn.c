/* Copyright (c) 2018. TIG developer. */

#include <string.h>

#include <sys/queue.h>

#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_timer.h>

#include <unixctl_command.h>

#include "lb_clock.h"
#include "lb_conn.h"
#include "lb_proto.h"
#include "lb_service.h"

#define CONN_TIMER_CYCLE MS_TO_CYCLES(10)

struct lb_conn *
lb_conn_new(struct lb_conn_table *ct, uint32_t cip, uint32_t cport,
            struct lb_real_service *rs, uint8_t is_synproxy,
            struct lb_device *dev) {
    struct lb_conn *conn;
    struct ipv4_4tuple tuple;
    int rc;

    rc = rte_mempool_get(ct->mp, (void **)&conn);
    if (rc < 0) {
        return NULL;
    }

    rc = lb_laddr_get(dev, ct->type, &conn->laddr, &conn->lport);
    if (rc < 0) {
        rte_mempool_put(ct->mp, conn);
        return NULL;
    }

    conn->ct = ct;
    conn->dev = dev;
    conn->lip = conn->laddr->ipv4;
    conn->cip = cip;
    conn->cport = cport;
    conn->vip = rs->virt_service->vip;
    conn->vport = rs->virt_service->vport;
    conn->rip = rs->rip;
    conn->rport = rs->rport;

    conn->use_time = LB_CLOCK();
    conn->timeout = ct->timeout;

    conn->real_service = rs;
    conn->flags = 0;
    if (rs->virt_service->flags & LB_VS_F_TOA)
        conn->flags |= LB_CONN_F_TOA;

    if (is_synproxy) {
        conn->flags |= LB_CONN_F_SYNPROXY;
        conn->proxy.syn_mbuf = NULL;
        conn->proxy.ack_mbuf = NULL;
        conn->proxy.isn = 0;
        conn->proxy.oft = 0;
        conn->proxy.syn_retry = 5;
    }

    conn->tseq.isn = 0;
    conn->tseq.oft = 0;

    IPv4_4TUPLE(&tuple, conn->cip, conn->cport, conn->vip, conn->vport);
    rc = rte_hash_add_key_data(ct->hash, (const void *)&tuple, conn);
    if (rc < 0) {
        lb_laddr_put(conn->laddr, conn->lport, ct->type);
        rte_mempool_put(ct->mp, conn);
        return NULL;
    }

    IPv4_4TUPLE(&tuple, conn->rip, conn->rport, conn->lip, conn->lport);
    rc = rte_hash_add_key_data(ct->hash, (const void *)&tuple, conn);
    if (rc < 0) {
        IPv4_4TUPLE(&tuple, conn->cip, conn->cport, conn->vip, conn->vport);
        rte_hash_del_key(ct->hash, (const void *)&tuple);
        lb_laddr_put(conn->laddr, conn->lport, ct->type);
        rte_mempool_put(ct->mp, conn);
        return NULL;
    }

    rte_spinlock_lock(&ct->spinlock);
    TAILQ_INSERT_TAIL(&ct->timeout_list, conn, next);
    rte_spinlock_unlock(&ct->spinlock);

    return conn;
}

struct lb_conn *
lb_conn_find(struct lb_conn_table *ct, uint32_t sip, uint32_t dip,
             uint16_t sport, uint16_t dport, uint8_t *dir) {
    struct lb_conn *conn;
    struct ipv4_4tuple tuple;
    int rc;

    IPv4_4TUPLE(&tuple, sip, sport, dip, dport);
    rc = rte_hash_lookup_data(ct->hash, (const void *)&tuple, (void **)&conn);
    if (rc < 0) {
        *dir = LB_DIR_ORIGINAL;
        return NULL;
    }

    conn->use_time = LB_CLOCK();

    if (conn->cip == sip && conn->cport == sport)
        *dir = LB_DIR_ORIGINAL;
    else
        *dir = LB_DIR_REPLY;

    return conn;
}

static void
__conn_expire(struct lb_conn_table *ct, struct lb_conn *conn) {
    struct ipv4_4tuple tuple;

    if (conn->flags & LB_CONN_F_SYNPROXY) {
        rte_pktmbuf_free(conn->proxy.syn_mbuf);
        rte_pktmbuf_free(conn->proxy.ack_mbuf);
    }

    if (conn->flags & LB_CONN_F_ACTIVE) {
        rte_atomic32_add(&conn->real_service->active_conns, -1);
        rte_atomic32_add(&conn->real_service->virt_service->active_conns, -1);
    }

    IPv4_4TUPLE(&tuple, conn->cip, conn->cport, conn->vip, conn->vport);
    rte_hash_del_key(ct->hash, (const void *)&tuple);

    IPv4_4TUPLE(&tuple, conn->lip, conn->lport, conn->rip, conn->rport);
    rte_hash_del_key(ct->hash, (const void *)&tuple);

    lb_laddr_put(conn->laddr, conn->lport, ct->type);
    lb_vs_put_rs(conn->real_service);
    rte_mempool_put(ct->mp, conn);

    TAILQ_REMOVE(&ct->timeout_list, conn, next);
}

void
lb_conn_expire(struct lb_conn_table *ct, struct lb_conn *conn) {
    rte_spinlock_lock(&ct->spinlock);
    __conn_expire(ct, conn);
    rte_spinlock_unlock(&ct->spinlock);
}

static void
conn_table_expire_cb(__attribute((unused)) struct rte_timer *timer, void *arg) {
    struct lb_conn_table *ct = arg;
    struct lb_conn *conn;
    void *tmp;
    uint32_t curr_time;

    curr_time = LB_CLOCK();
    rte_spinlock_lock(&ct->spinlock);
    for_each_conn_safe(conn, &ct->timeout_list, next, tmp) {
        if (ct->timer_task_cb)
            ct->timer_task_cb(conn);
        if (ct->timer_expire_cb &&
            (ct->timer_expire_cb(conn, curr_time) == 0)) {
            __conn_expire(ct, conn);
        }
    }
    rte_spinlock_unlock(&ct->spinlock);
}

int
lb_conn_table_init(struct lb_conn_table *ct, enum lb_proto_type type,
                   uint32_t lcore_id, uint32_t timeout,
                   void (*task_cb)(struct lb_conn *),
                   int (*expire_cb)(struct lb_conn *, uint32_t)) {
    struct rte_hash_parameters param;
    char name[RTE_HASH_NAMESIZE];
    uint32_t socket_id;

    socket_id = rte_lcore_to_socket_id(lcore_id);

    ct->type = type;

    memset(&param, 0, sizeof(param));
    snprintf(name, sizeof(name), "ct_hash%p", ct);
    param.name = name;
    param.entries = LB_MAX_CONN * 2;
    param.key_len = sizeof(struct ipv4_4tuple);
    param.hash_func = rte_hash_crc;
    param.socket_id = socket_id;

    ct->hash = rte_hash_create(&param);
    if (ct->hash == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create hash table %s failed, %s.\n",
                __func__, name, rte_strerror(rte_errno));
        return -1;
    }

    snprintf(name, sizeof(name), "ct_mp%p", ct);
    ct->mp = rte_mempool_create(name, LB_MAX_CONN, sizeof(struct lb_conn), 0, 0,
                                NULL, NULL, NULL, NULL, socket_id,
                                MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (ct->mp == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create mempool %s failed, %s\n", __func__,
                name, rte_strerror(rte_errno));
        return -1;
    }

    TAILQ_INIT(&ct->timeout_list);
    ct->timeout = timeout;
    ct->timer_task_cb = task_cb;
    ct->timer_expire_cb = expire_cb;
    rte_timer_init(&ct->timer);
    rte_timer_reset(&ct->timer, CONN_TIMER_CYCLE, PERIODICAL, lcore_id,
                    conn_table_expire_cb, ct);
    rte_spinlock_init(&ct->spinlock);

    return 0;
}
