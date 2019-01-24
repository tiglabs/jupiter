/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_SERVICE_H__
#define __LB_SERVICE_H__

#include <rte_rwlock.h>
#include <sys/queue.h>

#include "lb.h"
#include "lb_ip_address.h"
#include "lb_scheduler.h"

#define LB_VS_F_SYNPROXY (0x01)
#define LB_VS_F_TOA (0x02)

#define LB_RS_F_AVAILABLE (0x1)

struct lb_service_stats {
    uint64_t packets[LB_DIR_MAX];
    uint64_t bytes[LB_DIR_MAX];
    uint64_t drops[LB_DIR_MAX];
    uint64_t conns;
};

struct lb_real_service;

struct lb_virt_service {
    ip46_address_t vaddr;
    uint16_t vport;
    lb_proto_t proto;
    uint32_t flags;
    rte_atomic32_t active_conns;
    rte_atomic32_t refcnt;
    rte_rwlock_t rwlock;
    struct lb_scheduler sched;
    LIST_HEAD(, lb_real_service) real_services;
    uint32_t est_timeout;
    int max_conns;
    struct lb_service_stats stats[RTE_MAX_LCORE];
};

struct lb_real_service {
    struct lb_sched_node sched_node;
    LIST_ENTRY(lb_real_service) next;
    struct lb_virt_service *virt_service;
    ip46_address_t raddr;
    uint16_t rport;
    uint32_t flags;
    rte_atomic32_t active_conns;
    rte_atomic32_t refcnt;
    struct lb_service_stats stats[RTE_MAX_LCORE];
};

struct lb_virt_service *lb_vs_get(void *ip, uint16_t vport, lb_proto_t proto,
                                  uint8_t is_ip4);
struct lb_real_service *lb_vs_get_rs(struct lb_virt_service *vs, void *caddr,
                                     uint16_t cport, uint8_t is_ip4);
void lb_vs_put(struct lb_virt_service *vs);
void lb_rs_put(struct lb_real_service *rs);
int lb_service_module_init(void);

#endif