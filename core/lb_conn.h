/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_CONN_H__
#define __LB_CONN_H__

#include <sys/queue.h>

#include <rte_hash.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>
#include <rte_timer.h>

#include "lb_device.h"
#include "lb_proto.h"
#include "lb_service.h"
#include "lb_synproxy.h"
#include "lb_tcp_secret_seq.h"

#define LB_MAX_CONN (1 << 20)

#define LB_CONN_F_SYNPROXY (0x01)
#define LB_CONN_F_ACTIVE (0x02)
#define LB_CONN_F_TOA (0x4)

struct ipv4_4tuple {
    uint32_t sip, dip;
    uint16_t sport, dport;
} __attribute__((__packed__));

#define IPv4_4TUPLE(t, si, sp, di, dp)                                         \
    do {                                                                       \
        (t)->sip = si;                                                         \
        (t)->sport = sp;                                                       \
        (t)->dip = di;                                                         \
        (t)->dport = dp;                                                       \
    } while (0)

struct lb_conn {
    TAILQ_ENTRY(lb_conn) next;

    struct lb_conn_table *ct;
    struct lb_device *dev;

    uint32_t cip, vip, lip, rip;
    uint16_t cport, vport, lport, rport;

    uint32_t timeout;
    uint32_t create_time;
    uint32_t use_time;

    struct rte_timer timer;

    struct lb_real_service *real_service;
    struct lb_laddr *laddr;

    uint32_t flags;
    uint32_t state;

    struct synproxy proxy;

    /* tcp seq adjust */
    struct tcp_secret_seq tseq;
};

struct lb_conn_table {
    enum lb_proto_type type;
    struct rte_hash *hash;
    struct rte_mempool *mp;
    uint32_t timeout;
    rte_spinlock_t spinlock;
    TAILQ_HEAD(, lb_conn) timeout_list;
    struct rte_timer timer;
    int (*timer_expire_cb)(struct lb_conn *, uint32_t);
    void (*timer_task_cb)(struct lb_conn *);
};

#define for_each_conn_safe(var, head, field, tvar)                             \
    for ((var) = TAILQ_FIRST((head));                                          \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))

struct lb_conn *lb_conn_new(struct lb_conn_table *ct, uint32_t cip,
                            uint32_t cport, struct lb_real_service *rs,
                            uint8_t is_synproxy, struct lb_device *dev);
void lb_conn_expire(struct lb_conn_table *ct, struct lb_conn *conn);
struct lb_conn *lb_conn_find(struct lb_conn_table *ct, uint32_t sip,
                             uint32_t dip, uint16_t sport, uint16_t dport,
                             uint8_t *dir);
int lb_conn_table_init(struct lb_conn_table *ct, enum lb_proto_type type,
                       uint32_t lcore_id, uint32_t timeout,
                       void (*task_cb)(struct lb_conn *),
                       int (*expire_cb)(struct lb_conn *, uint32_t));

#endif
