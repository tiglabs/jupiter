/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_SERVICE_H__
#define __LB_SERVICE_H__

#include <sys/queue.h>

#include <rte_rwlock.h>

#include "lb_cql.h"
#include "lb_schedule.h"

struct lb_traffic_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t drops;
};

struct lb_virt_service;

struct lb_real_service {
    LIST_ENTRY(lb_real_service) next;
    uint32_t rip;
    uint16_t rport;
    uint8_t proto_type;
    uint8_t online;        /* 是否可被调度 */
    uint8_t deleted;       /* 是否被删除 */
    rte_atomic32_t refcnt; /* 引用计数，refcnt为0时，执行内存释放 */
    void *userdata; /* 调度器的相关数据，例如conhash调度器的node节点 */
    struct lb_virt_service *virt_service;
    rte_atomic32_t active_conns; /* 活动连接数 */
    /* real_service的报文统计项包括：
         - virt_service向real_service转发的client请求报文
         - virt_service向client转发的real_service响应报文

       stats[lcore_id][dir]含义：
         - dir为0，统计client的请求报文
         - dir为1，统计real_service的响应报文
     */
    struct lb_traffic_stats stats[RTE_MAX_LCORE][2];
    /* 统计real_service累计接收的请求数 */
    uint64_t history_conns[RTE_MAX_LCORE];
};

struct lb_virt_service {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto_type;
    uint8_t deleted;             /* 是否被删除 */
    uint64_t conn_expire_period; /* 连接老化时间周期 */
    int32_t max_conns;           /* 支持的活动连接数上限 */
    rte_atomic32_t active_conns; /* 活动连接数 */
    rte_atomic32_t refcnt; /* 引用计数，为0时，执行内存释放 */
    const struct lb_scheduler *sched; /* 调度器 */
    void *sched_data; /* 调度器相关数据，例如conhash调度器的表 */
    struct lb_cql *cql;                         /* 限制客户端QPS */
    LIST_HEAD(, lb_real_service) real_services; /* real_service集合 */
    /* virt_service的报文统计项包括：
         - virt_service接收的client请求报文
         - virt_service丢弃的client请求报文
         - virt_service接收的real_service响应报文
         - virt_service丢弃的real_service响应报文

       stats[lcore_id][dir]含义：
         - dir为0，统计client的请求报文
         - dir为1，统计real_service的响应报文
     */
    struct lb_traffic_stats stats[RTE_MAX_LCORE][2];
    /* 统计virt_service累计接收的请求数 */
    uint64_t history_conns[RTE_MAX_LCORE];
    uint8_t conn_recycle_fast;   /* 快速回收连接，未实现 */
    uint8_t source_ip_transport; /* 客户端源IP通过TOA/IPOA传给后端 */
};

/* 统计real_service的报文 */
#define LB_RS_STATS_INC(rs, dir, b)                                            \
    do {                                                                       \
        (rs)->stats[rte_lcore_id()][dir].packets += 1;                         \
        (rs)->stats[rte_lcore_id()][dir].bytes += b;                           \
    } while (0)

/* 统计virt_service接收的报文 */
#define LB_VS_STATS_INC(vs, dir, b)                                            \
    do {                                                                       \
        (vs)->stats[rte_lcore_id()][dir].packets += 1;                         \
        (vs)->stats[rte_lcore_id()][dir].bytes += b;                           \
    } while (0)

/* 统计virt_service丢弃的报文        */
#define LB_VS_STATS_DROP(vs, dir)                                              \
    do {                                                                       \
        (vs)->stats[rte_lcore_id()][dir].drops += 1;                           \
    } while (0)

#define LB_VS_CONN_INC(vs)                                                     \
    do {                                                                       \
        (vs)->history_conns[rte_lcore_id()] += 1;                              \
    } while (0)

#define LB_RS_CONN_INC(rs)                                                     \
    do {                                                                       \
        (rs)->history_conns[rte_lcore_id()] += 1;                              \
    } while (0)

static inline int
lb_virt_service_cql(struct lb_virt_service *virt_srv, uint32_t ip,
                    uint64_t time) {
    return virt_srv->cql ? lb_cql_check(virt_srv->cql, ip, time) : 0;
}

struct lb_virt_service *lb_virt_service_find(uint32_t vip, uint16_t vport,
                                             uint8_t proto_type);
void lb_real_service_destory(struct lb_real_service *real_srv);
int lb_is_vip_exist(uint32_t vip);
void lb_service_table_init(void);

#endif

