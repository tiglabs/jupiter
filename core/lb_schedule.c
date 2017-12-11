/* Copyright (c) 2017. TIG developer. */

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>
#include <rte_rwlock.h>

#include "conhash.h"
#include "lb_rwlock.h"
#include "lb_schedule.h"
#include "lb_service.h"

#define MAX_RS_REPLICA 256

#define UDP_CONHASH_CRC

#ifdef UDP_CONHASH_CRC
#include <rte_hash_crc.h>
static long
conhash_crc_cb(const char *data, unsigned int length) {
    return rte_hash_crc(data, length, 0);
}
#endif

static int
conhash_sched_init(struct lb_virt_service *virt_srv) {
    struct conhash_s *conhash;

#ifdef UDP_CONHASH_CRC
    if (virt_srv->proto_type == IPPROTO_UDP)
        conhash = conhash_init(conhash_crc_cb);
    else
#endif
        conhash = conhash_init(NULL);
    if (conhash == NULL)
        return -1;
    virt_srv->sched_data = conhash;
    return 0;
}

static void
conhash_sched_fini(struct lb_virt_service *virt_srv) {
    conhash_fini(virt_srv->sched_data);
}

static int
conhash_sched_add(struct lb_virt_service *virt_srv,
                  struct lb_real_service *real_srv) {
    struct conhash_s *conhash = virt_srv->sched_data;
    struct node_s *node;
    char buf[8];

    if (real_srv->online)
        return 0;
    if (!(node = rte_zmalloc(NULL, sizeof(struct node_s), 0))) {
        return -1;
    }
    buf[0] = (unsigned char)(real_srv->rip >> 24 & 0xff);
    buf[1] = (unsigned char)(real_srv->rip >> 16 & 0xff);
    buf[2] = (unsigned char)(real_srv->rip >> 8 & 0xff);
    buf[3] = (unsigned char)(real_srv->rip & 0xff);
    buf[4] = (unsigned char)(real_srv->rport >> 8 & 0xff);
    buf[5] = (unsigned char)(real_srv->rport & 0xff);
    buf[6] = '\0';
    conhash_set_node(node, buf, MAX_RS_REPLICA, real_srv);
    real_srv->userdata = node;
    if (conhash_add_node(conhash, real_srv->userdata) < 0) {
        rte_free(real_srv->userdata);
        return -1;
    } else {
        real_srv->online = 1;
        return 0;
    }
}

static int
conhash_sched_del(struct lb_virt_service *virt_srv,
                  struct lb_real_service *real_srv) {
    struct conhash_s *conhash = virt_srv->sched_data;

    if (!real_srv->online)
        return 0;
    conhash_del_node(conhash, real_srv->userdata);
    real_srv->online = 0;
    rte_free(real_srv->userdata);
    return 0;
}

#define virt_service_key(ip, port)                                             \
    (((uint64_t)(ip) << 32) | ((uint64_t)(port) << 16))

static struct lb_real_service *
conhash_schedule_ipport(struct lb_virt_service *virt_srv, uint32_t ip,
                        uint16_t port) {
    struct conhash_s *conhash = virt_srv->sched_data;
    uint64_t key;
    struct node_s *node;

    key = virt_service_key(ip, port);
    node = conhash_lookup(conhash, (const char *)&key, sizeof(uint64_t));
    return node != NULL ? node->userdata : NULL;
}

static struct lb_real_service *
conhash_schedule_iponly(struct lb_virt_service *virt_srv, uint32_t ip,
                        uint16_t port) {
    struct conhash_s *conhash = virt_srv->sched_data;
    struct node_s *node;

    (void)port;
    node = conhash_lookup(conhash, (const char *)&ip, sizeof(uint32_t));
    return node != NULL ? node->userdata : NULL;
}

static int
lc_sched_add(struct lb_virt_service *virt_srv,
             struct lb_real_service *real_srv) {
    (void)virt_srv;
    if (!real_srv->online) {
        real_srv->online = 1;
    }
    return 0;
}

static int
lc_sched_del(struct lb_virt_service *virt_srv,
             struct lb_real_service *real_srv) {
    (void)virt_srv;
    if (real_srv->online) {
        real_srv->online = 0;
    }
    return 0;
}

static struct lb_real_service *
lc_schedule(struct lb_virt_service *virt_srv, uint32_t ip, uint16_t port) {
    struct lb_real_service *real_srv;
    struct lb_real_service *min_real = NULL;
    int32_t min_conns = INT32_MAX;
    int32_t conns;

    (void)ip;
    (void)port;
    LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
        if (!real_srv->online)
            continue;
        conns = rte_atomic32_read(&real_srv->active_conns);
        if (min_conns > conns) {
            min_conns = conns;
            min_real = real_srv;
        }
    }
    return min_real;
}

static int
rr_sched_init(struct lb_virt_service *virt_srv) {
    uint64_t *rs_percore;

    rs_percore = rte_calloc("rs_pointer", sizeof(uint64_t), RTE_MAX_LCORE, 0);
    if (rs_percore == NULL)
        return -1;
    virt_srv->sched_data = rs_percore;
    return 0;
}

static void
rr_sched_fini(struct lb_virt_service *virt_srv) {
    rte_free(virt_srv->sched_data);
}

static int
rr_sched_add(struct lb_virt_service *virt_srv,
             struct lb_real_service *real_srv) {
    (void)virt_srv;
    if (!real_srv->online) {
        real_srv->online = 1;
    }
    return 0;
}

static int
rr_sched_del(struct lb_virt_service *virt_srv,
             struct lb_real_service *real_srv) {
    uint64_t *rs_percore = virt_srv->sched_data;

    (void)virt_srv;
    if (real_srv->online) {
        real_srv->online = 0;
        memset(rs_percore, 0, sizeof(uint64_t) * RTE_MAX_LCORE);
    }
    return 0;
}

static struct lb_real_service *
rr_schedule(struct lb_virt_service *virt_srv, uint32_t ip, uint16_t port) {
    unsigned lcore_id = rte_lcore_id();
    uint64_t *rs_percore = virt_srv->sched_data;
    struct lb_real_service *rs, *next_rs;

    (void)ip;
    (void)port;
    if (unlikely(LIST_EMPTY(&virt_srv->real_services)))
        return NULL;
    if (unlikely(rs_percore[lcore_id] == 0)) {
        rs = LIST_FIRST(&virt_srv->real_services);
    } else {
        rs = (struct lb_real_service *)(uintptr_t)rs_percore[lcore_id];
        rs = LIST_NEXT(rs, next);
        if (rs == NULL)
            rs = LIST_FIRST(&virt_srv->real_services);
    }
    next_rs = rs;
    do {
        if (next_rs->online) {
            rs_percore[lcore_id] = (uint64_t)(uintptr_t)next_rs;
            return next_rs;
        }
        next_rs = LIST_NEXT(next_rs, next);
        if (next_rs == NULL)
            next_rs = LIST_FIRST(&virt_srv->real_services);
    } while (next_rs != rs);
    return NULL;
}

enum sched_type {
    SCHED_TYPE_IPPORT,
    SCHED_TYPE_IPONLY,
    SCHED_TYPE_LC,
    SCHED_TYPE_RR,
    SCHED_TYPE_NONE,
};

static const struct lb_scheduler schedulers[SCHED_TYPE_NONE] = {
        [SCHED_TYPE_IPPORT] =
            {
                .name = "ipport",
                .construct = conhash_sched_init,
                .destruct = conhash_sched_fini,
                .add = conhash_sched_add,
                .del = conhash_sched_del,
                .dispatch = conhash_schedule_ipport,
            },
        [SCHED_TYPE_IPONLY] =
            {
                .name = "iponly",
                .construct = conhash_sched_init,
                .destruct = conhash_sched_fini,
                .add = conhash_sched_add,
                .del = conhash_sched_del,
                .dispatch = conhash_schedule_iponly,
            },
        [SCHED_TYPE_LC] =
            {
                .name = "lc",
                .construct = NULL,
                .destruct = NULL,
                .add = lc_sched_add,
                .del = lc_sched_del,
                .dispatch = lc_schedule,
            },
        [SCHED_TYPE_RR] =
            {
                .name = "rr",
                .construct = rr_sched_init,
                .destruct = rr_sched_fini,
                .add = rr_sched_add,
                .del = rr_sched_del,
                .dispatch = rr_schedule,
            },
};

const struct lb_scheduler *
lb_scheduler_lookup_by_name(const char *name) {
    int i;

    for (i = 0; i < SCHED_TYPE_NONE; i++) {
        if (strcasecmp(name, schedulers[i].name) == 0)
            return &schedulers[i];
    }
    return NULL;
}

