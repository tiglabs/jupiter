/* Copyright (c) 2017. TIG developer. */

#include <stdint.h>
#include <sys/queue.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "lb_cql.h"

struct cql_entry {
    TAILQ_ENTRY(cql_entry) next;
    uint64_t time;
};

struct cql_rule {
    uint32_t ip;
    uint32_t qps;
    rte_spinlock_t lock;
    TAILQ_HEAD(, cql_entry) tbl;
    struct cql_entry entries[0];
};

struct lb_cql {
    struct rte_hash *h;
    uint32_t size;
    uint32_t socket_id;
};

static struct cql_rule *
cql_rule_create(uint32_t ip, uint32_t qps, uint32_t socket_id) {
    struct cql_rule *r;
    uint32_t size;
    uint32_t i;

    size = sizeof(struct cql_rule) + qps * sizeof(struct cql_entry);
    r = rte_zmalloc_socket(NULL, size, RTE_CACHE_LINE_SIZE, socket_id);
    if (!r) {
        return NULL;
    }
    r->ip = ip;
    r->qps = qps;
    rte_spinlock_init(&r->lock);
    TAILQ_INIT(&r->tbl);
    for (i = 0; i < qps; i++) {
        TAILQ_INSERT_TAIL(&r->tbl, &r->entries[i], next);
    }
    return r;
}

static void
cql_rule_free(struct cql_rule *r) {
    rte_free(r);
}

static int
cql_rule_enqueue(struct cql_rule *r, uint64_t time) {
    struct cql_entry *e;

    rte_spinlock_lock(&r->lock);
    e = TAILQ_FIRST(&r->tbl);
    if (e && (e->time + rte_get_tsc_hz() < time)) {
        e->time = time;
        TAILQ_REMOVE(&r->tbl, e, next);
        TAILQ_INSERT_TAIL(&r->tbl, e, next);
        rte_spinlock_unlock(&r->lock);
        return 0;
    }
    rte_spinlock_unlock(&r->lock);
    return -1;
}

static void
__cql_rule_del(struct lb_cql *cql, uint32_t ip) {
    struct cql_rule *r;

    if (rte_hash_lookup_data(cql->h, (const void *)&ip, (void **)&r) >= 0) {
        rte_hash_del_key(cql->h, (const void *)&ip);
        cql_rule_free(r);
    }
}

int
lb_cql_rule_add(struct lb_cql *cql, uint32_t ip, uint32_t qps) {
    struct cql_rule *r;

    r = cql_rule_create(ip, qps, cql->socket_id);
    if (!r) {
        return -1;
    }
    __cql_rule_del(cql, ip);
    if (rte_hash_add_key_data(cql->h, (const void *)&ip, r) < 0) {
        cql_rule_free(r);
        return -1;
    }
    return 0;
}

void
lb_cql_rule_del(struct lb_cql *cql, uint32_t ip) {
    __cql_rule_del(cql, ip);
}

int
lb_cql_rule_iterate(struct lb_cql *cql, uint32_t *ip, uint32_t *qps,
                    uint32_t *next) {
    uint32_t *k;
    struct cql_rule *r;
    int pos;

    pos = rte_hash_iterate(cql->h, (const void **)&k, (void **)&r, next);
    if (pos >= 0) {
        *ip = r->ip;
        *qps = r->qps;
    }
    return pos;
}

int
lb_cql_check(struct lb_cql *cql, uint32_t ip, uint64_t time) {
    struct cql_rule *r;

    if (rte_hash_lookup_data(cql->h, (const void **)&ip, (void **)&r) < 0) {
        return 0;
    }
    return cql_rule_enqueue(r, time);
}

uint32_t
lb_cql_size(struct lb_cql *cql) {
    return cql->size;
}

struct lb_cql *
lb_cql_create(const char *name, uint32_t size, uint32_t socket_id) {
    struct lb_cql *cql;
    struct rte_hash_parameters params = {0};

    cql = rte_zmalloc_socket(NULL, sizeof(struct lb_cql), 0, socket_id);
    if (!cql) {
        return NULL;
    }
    cql->size = size;
    cql->socket_id = socket_id;

    params.name = name;
    params.entries = size;
    params.key_len = sizeof(uint32_t);
    params.hash_func = rte_hash_crc;
    params.socket_id = socket_id;
    cql->h = rte_hash_create(&params);
    if (!cql->h) {
        rte_free(cql);
        return NULL;
    }
    return cql;
}

void
lb_cql_destory(struct lb_cql *cql) {
    const void *k;
    struct cql_rule *r;
    uint32_t n = 0;

    if (!cql) {
        return;
    }
    while (rte_hash_iterate(cql->h, &k, (void **)&r, &n) >= 0) {
        cql_rule_free(r);
    }
    rte_hash_free(cql->h);
    rte_free(cql);
}

