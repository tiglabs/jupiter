/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_SERVICE_H__
#define __LB_SERVICE_H__

#include <sys/queue.h>

#include <rte_atomic.h>
#include <rte_rwlock.h>

#include "lb_proto.h"
#include "lb_scheduler.h"

#define LB_MAX_VS (1 << 16)

#define LB_VS_F_SYNPROXY (0x01)
#define LB_VS_F_TOA (0x02)
#define LB_VS_F_CQL (0x04)

#define LB_RS_F_AVAILABLE (0x1)

struct lb_service_stats {
    uint64_t packets[LB_DIR_MAX];
    uint64_t bytes[LB_DIR_MAX];
    uint64_t drops[LB_DIR_MAX];
    uint64_t conns;
};

struct lb_real_service;

struct lb_virt_service {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;

    uint32_t est_timeout;
    int max_conns;
    rte_atomic32_t active_conns;
    rte_atomic32_t refcnt;

    uint32_t flags;

    uint32_t socket_id;

    rte_rwlock_t rwlock;

    const struct lb_scheduler *sched;
    void *sched_data;

    LIST_HEAD(, lb_real_service) real_services;

    struct lb_service_stats stats[RTE_MAX_LCORE];
};

struct lb_real_service {
    LIST_ENTRY(lb_real_service) next;
    uint32_t rip;
    uint16_t rport;
    uint8_t proto;

    uint32_t flags;

    rte_atomic32_t active_conns;
    rte_atomic32_t refcnt;

    int weight;

    struct lb_virt_service *virt_service;
    void *sched_node;

    struct lb_service_stats stats[RTE_MAX_LCORE];
};

int lb_is_vip_exist(uint32_t vip);
struct lb_virt_service *lb_vs_get(uint32_t vip, uint16_t vport, uint8_t proto);
void lb_vs_put(struct lb_virt_service *vs);
struct lb_real_service *lb_vs_get_rs(struct lb_virt_service *vs, uint32_t cip,
                                     uint16_t cport);
void lb_vs_put_rs(struct lb_real_service *rs);
void lb_vs_free(struct lb_virt_service *vs);
void lb_rs_free(struct lb_real_service *rs);
int lb_service_init(void);

static inline int
lb_vs_check_max_conn(struct lb_virt_service *vs) {
    return rte_atomic32_read(&vs->active_conns) >= vs->max_conns;
}

#endif

