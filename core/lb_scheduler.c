/* Copyright (c) 2018. TIG developer. */

#include <assert.h>
#include <string.h>

#include <sys/queue.h>

#include <rte_atomic.h>
#include <rte_malloc.h>

#include "conhash.h"
#include "lb_format.h"
#include "lb_scheduler.h"
#include "lb_service.h"

//#define SCHED_DEBUG
#ifdef SCHED_DEBUG
#define SCHED_PRINT(...)                                                       \
    do {                                                                       \
        fprintf(stderr, __VA_ARGS__);                                          \
    } while (0)
#else
#define SCHED_PRINT(...)                                                       \
    do {                                                                       \
    } while (0)
#endif

#define MAX_RS_REPLICA 256

static int
conhash_sched_init(struct lb_virt_service *vs) {
    vs->sched_data = conhash_init(NULL);
    return vs->sched_data != NULL ? 0 : -1;
}

static void
conhash_sched_fini(struct lb_virt_service *vs) {
    conhash_fini(vs->sched_data);
}

#define IP_PORT_TO_STR(ip, port, s)                                            \
    do {                                                                       \
        s[0] = (unsigned char)((ip) >> 24 & 0xff);                             \
        s[1] = (unsigned char)((ip) >> 16 & 0xff);                             \
        s[2] = (unsigned char)((ip) >> 8 & 0xff);                              \
        s[3] = (unsigned char)((ip)&0xff);                                     \
        s[4] = (unsigned char)((port) >> 8 & 0xff);                            \
        s[5] = (unsigned char)((port)&0xff);                                   \
        s[6] = '\0';                                                           \
    } while (0)

static int
conhash_sched_add(struct lb_virt_service *vs, struct lb_real_service *rs) {
    struct conhash_s *conhash = vs->sched_data;
    struct node_s *node;
    char buf[8];

    if (unlikely(conhash == NULL))
        return -1;
    node = rte_zmalloc_socket(NULL, sizeof(struct node_s), RTE_CACHE_LINE_SIZE,
                              vs->socket_id);
    if (node != NULL) {
        IP_PORT_TO_STR(rs->rip, rs->rport, buf);
        conhash_set_node(node, buf, MAX_RS_REPLICA, rs);
        conhash_add_node(conhash, node);
    }
    return (rs->sched_node = node) != NULL ? 0 : -1;
}

static int
conhash_sched_del(struct lb_virt_service *vs, struct lb_real_service *rs) {
    struct conhash_s *conhash = vs->sched_data;

    if (unlikely(conhash == NULL))
        return -1;
    conhash_del_node(conhash, rs->sched_node);
    rte_free(rs->sched_node);
    rs->sched_node = NULL;
    return 0;
}

static int
conhash_sched_update(__rte_unused struct lb_virt_service *vs,
                     __rte_unused struct lb_real_service *rs) {
    return 0;
}

#define IP_PORT_TO_UINT64(ip, port)                                            \
    (((uint64_t)(ip) << 32) | ((uint64_t)(port) << 16))

static struct lb_real_service *
conhash_schedule_ipport(struct lb_virt_service *vs, uint32_t ip,
                        uint16_t port) {
    struct conhash_s *conhash = vs->sched_data;
    uint64_t key;
    struct node_s *node;

    if (unlikely(conhash == NULL))
        return NULL;
    key = IP_PORT_TO_UINT64(ip, port);
    node = conhash_lookup(conhash, (const char *)&key, sizeof(uint64_t));
    return node != NULL ? node->userdata : NULL;
}

static struct lb_real_service *
conhash_schedule_iponly(struct lb_virt_service *vs, uint32_t ip,
                        __rte_unused uint16_t port) {
    struct conhash_s *conhash = vs->sched_data;
    struct node_s *node;

    if (unlikely(conhash == NULL))
        return NULL;
    node = conhash_lookup(conhash, (const char *)&ip, sizeof(uint32_t));
    return node != NULL ? node->userdata : NULL;
}

struct rr_data {
    struct lb_real_service *real_services[RTE_MAX_LCORE];
} __rte_cache_aligned;

static int
rr_sched_init(struct lb_virt_service *vs) {
    struct rr_data *rr;

    rr = rte_zmalloc_socket(NULL, sizeof(struct rr_data), RTE_CACHE_LINE_SIZE,
                            vs->socket_id);
    return (vs->sched_data = rr) != NULL ? 0 : -1;
}

static void
rr_sched_fini(struct lb_virt_service *vs) {
    rte_free(vs->sched_data);
}

static int
rr_sched_add(struct lb_virt_service *vs,
             __rte_unused struct lb_real_service *rs) {
    struct rr_data *rr = vs->sched_data;
    uint32_t lcore_id;

    if (unlikely(rr == NULL))
        return -1;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rr->real_services[lcore_id] = LIST_FIRST(&vs->real_services);
    }
    return 0;
}

static int
rr_sched_del(struct lb_virt_service *vs,
             __rte_unused struct lb_real_service *rs) {
    struct rr_data *rr = vs->sched_data;
    uint32_t lcore_id;

    if (unlikely(rr == NULL))
        return -1;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rr->real_services[lcore_id] = LIST_FIRST(&vs->real_services);
    }
    return 0;
}

static int
rr_sched_update(__rte_unused struct lb_virt_service *vs,
                __rte_unused struct lb_real_service *rs) {
    return 0;
}

static struct lb_real_service *
rr_schedule(struct lb_virt_service *vs, __rte_unused uint32_t ip,
            __rte_unused uint16_t port) {
    uint32_t lcore_id = rte_lcore_id();
    struct rr_data *rr = vs->sched_data;
    struct lb_real_service *rs, *p;

    if (unlikely(rr == NULL))
        return NULL;

    rs = rr->real_services[lcore_id];
    if (rs == NULL)
        return NULL;
    p = rs;

    do {
        if (rs->flags & LB_RS_F_AVAILABLE)
            goto hit;
        rs = LIST_NEXT(rs, next);
        if (rs == NULL)
            rs = LIST_FIRST(&vs->real_services);
    } while (rs != p);

    return NULL;

hit:
    SCHED_PRINT(
        "RR: lcore%u, vip=" IPv4_BE_FMT ", vport=%u, proto=%u, rip=" IPv4_BE_FMT
        ", rport=%u, weight=%u\n",
        lcore_id, IPv4_BE_ARG(vs->vip), rte_be_to_cpu_16(vs->vport), vs->proto,
        IPv4_BE_ARG(rs->rip), rte_be_to_cpu_16(rs->rport), rs->weight);
    p = LIST_NEXT(rs, next);
    if (p == NULL)
        p = LIST_FIRST(&vs->real_services);
    rr->real_services[lcore_id] = p;
    return rs;
}

struct wrr_data {
    struct {
        struct lb_real_service *real_service;
        int cw;
    } __rte_cache_aligned cores[RTE_MAX_LCORE];
    int mw;
    int dw;
};

static int
wrr_sched_init(struct lb_virt_service *vs) {
    struct wrr_data *wrr;

    wrr = rte_zmalloc_socket(NULL, sizeof(struct wrr_data), RTE_CACHE_LINE_SIZE,
                             vs->socket_id);
    return (vs->sched_data = wrr) != NULL ? 0 : -1;
}

static void
wrr_sched_fini(struct lb_virt_service *vs) {
    rte_free(vs->sched_data);
}

static int
wrr_max_weight(struct lb_virt_service *vs) {
    struct lb_real_service *rs;
    int max = 0;

    LIST_FOREACH(rs, &vs->real_services, next) {
        if (!(rs->flags & LB_RS_F_AVAILABLE))
            continue;
        if (max < rs->weight)
            max = rs->weight;
    }
    return max;
}

static int
gcd(int a, int b) {
    int c;

    while ((c = a % b)) {
        a = b;
        b = c;
    }
    return b;
}

static int
wrr_gcd_weight(struct lb_virt_service *vs) {
    struct lb_real_service *rs;
    int g = 0;

    LIST_FOREACH(rs, &vs->real_services, next) {
        if (!(rs->flags & LB_RS_F_AVAILABLE))
            continue;
        if (rs->weight == 0)
            continue;
        if (g == 0)
            g = rs->weight;
        else
            g = gcd(g, rs->weight);
    }
    return g ? g : 1;
}

static void
wrr_update_weight(struct lb_virt_service *vs) {
    struct wrr_data *wrr = vs->sched_data;
    struct lb_real_service *real_service;
    uint32_t lcore_id;
    int weight = 0;

    if (unlikely(wrr == NULL))
        return;

    wrr->mw = wrr_max_weight(vs);
    wrr->dw = wrr_gcd_weight(vs);
    LIST_FOREACH(real_service, &vs->real_services, next) {
        if ((real_service->flags & LB_RS_F_AVAILABLE) &&
            (real_service->weight != 0)) {
            weight = real_service->weight;
            break;
        }
    }
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        wrr->cores[lcore_id].real_service = real_service;
        wrr->cores[lcore_id].cw = weight;
    }
}

static int
wrr_sched_add(struct lb_virt_service *vs,
              __rte_unused struct lb_real_service *rs) {
    wrr_update_weight(vs);
    return 0;
}

static int
wrr_sched_del(struct lb_virt_service *vs,
              __rte_unused struct lb_real_service *rs) {
    wrr_update_weight(vs);
    return 0;
}

static int
wrr_sched_update(struct lb_virt_service *vs,
                 __rte_unused struct lb_real_service *rs) {
    wrr_update_weight(vs);
    return 0;
}

static struct lb_real_service *
wrr_schedule(struct lb_virt_service *vs, __rte_unused uint32_t ip,
             __rte_unused uint16_t port) {
    uint32_t lcore_id = rte_lcore_id();
    struct wrr_data *wrr = vs->sched_data;
    struct lb_real_service *rs, *p;
    int cw;

    if (unlikely(wrr == NULL))
        return NULL;

    cw = wrr->cores[lcore_id].cw;
    rs = wrr->cores[lcore_id].real_service;
    if (rs == NULL)
        return NULL;
    p = rs;

    cw -= wrr->dw;
    if (cw >= 0)
        goto hit;

    do {
        rs = LIST_NEXT(rs, next);
        if (rs == NULL)
            rs = LIST_FIRST(&vs->real_services);
        if (rs->flags & LB_RS_F_AVAILABLE) {
            cw = rs->weight;
            cw -= wrr->dw;
            if (cw >= 0)
                goto hit;
        }
    } while (rs != p);

    return NULL;

hit:
    SCHED_PRINT(
        "WRR: lcore%u, vip=" IPv4_BE_FMT
        ", vport=%u, proto=%u, rip=" IPv4_BE_FMT ", rport=%u, weight=%u\n",
        lcore_id, IPv4_BE_ARG(vs->vip), rte_be_to_cpu_16(vs->vport), vs->proto,
        IPv4_BE_ARG(rs->rip), rte_be_to_cpu_16(rs->rport), rs->weight);
    wrr->cores[lcore_id].cw = cw;
    wrr->cores[lcore_id].real_service = rs;
    return rs;
}

enum sched_type {
    LB_SCHED_T_IPPORT,
    LB_SCHED_T_IPONLY,
    LB_SCHED_T_RR,
    LB_SCHED_T_WRR,
    LB_SCHED_T_NONE,
};

static const struct lb_scheduler schedulers[LB_SCHED_T_NONE] = {
    [LB_SCHED_T_IPPORT] =
        {
            .name = "ipport",
            .init = conhash_sched_init,
            .fini = conhash_sched_fini,
            .add = conhash_sched_add,
            .del = conhash_sched_del,
            .update = conhash_sched_update,
            .dispatch = conhash_schedule_ipport,
        },
    [LB_SCHED_T_IPONLY] =
        {
            .name = "iponly",
            .init = conhash_sched_init,
            .fini = conhash_sched_fini,
            .add = conhash_sched_add,
            .del = conhash_sched_del,
            .update = conhash_sched_update,
            .dispatch = conhash_schedule_iponly,
        },
    [LB_SCHED_T_RR] =
        {
            .name = "rr",
            .init = rr_sched_init,
            .fini = rr_sched_fini,
            .add = rr_sched_add,
            .del = rr_sched_del,
            .update = rr_sched_update,
            .dispatch = rr_schedule,
        },
    [LB_SCHED_T_WRR] =
        {
            .name = "wrr",
            .init = wrr_sched_init,
            .fini = wrr_sched_fini,
            .add = wrr_sched_add,
            .del = wrr_sched_del,
            .update = wrr_sched_update,
            .dispatch = wrr_schedule,
        },
};

int
lb_scheduler_lookup_by_name(const char *name,
                            const struct lb_scheduler **sched) {
    int i;

    for (i = 0; i < LB_SCHED_T_NONE; i++) {
        if (strcasecmp(name, schedulers[i].name) == 0) {
            *sched = &schedulers[i];
            return 0;
        }
    }
    return -1;
}

