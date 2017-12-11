/* Copyright (c) 2017. TIG developer. */

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_timer.h>

#include "lb_config.h"
#include "lb_rwlock.h"
#include "lb_schedule.h"
#include "lb_service.h"
#include "parser.h"
#include "unixctl_command.h"

#define __CONN_REPORT_CMD__
#ifdef __CONN_REPORT_CMD__
#include "lb_proto_tcp.h"
#include "lb_proto_udp.h"
#endif

#define RTE_LOGTYPE_LB RTE_LOGTYPE_USER1

struct lb_service_table {
    struct rte_hash *virt_services;
    struct rte_hash *vips;

    uint32_t table_size;
    uint32_t service_count;

    uint64_t tcp_conn_expire_period;
    uint64_t udp_conn_expire_period;
};

static struct lb_service_table *service_table;

#define virt_service_key(ip, port, proto)                                      \
    (((uint64_t)(ip) << 32) | ((uint64_t)(port) << 16) | (uint64_t)(proto))

static inline struct lb_virt_service *
virt_service_ref(struct lb_virt_service *virt_srv) {
    rte_atomic32_add(&virt_srv->refcnt, 1);
    return virt_srv;
}

static struct lb_virt_service *
virt_service_create(uint32_t vip, uint16_t vport, uint8_t proto_type,
                    const struct lb_scheduler *scheduler) {
    struct lb_virt_service *virt_srv;

    virt_srv = rte_zmalloc(NULL, sizeof(struct lb_virt_service), 0);
    if (!virt_srv) {
        RTE_LOG(ERR, LB, "Alloc memory for virt service failed.\n");
        return NULL;
    }
    if (scheduler->construct && scheduler->construct(virt_srv) < 0) {
        RTE_LOG(ERR, LB, "Construct scheduler for virt service failed.\n");
        rte_free(virt_srv);
        return NULL;
    }
    virt_srv->sched = scheduler;
    virt_srv->vip = vip;
    virt_srv->vport = vport;
    virt_srv->proto_type = proto_type;
    virt_srv->deleted = 0;
    virt_srv->max_conns = INT32_MAX;
    virt_srv->conn_expire_period = (proto_type == IPPROTO_TCP)
                                       ? service_table->tcp_conn_expire_period
                                       : service_table->udp_conn_expire_period;
    LIST_INIT(&virt_srv->real_services);
    rte_atomic32_set(&virt_srv->refcnt, 1);
    return virt_srv;
}

static void
virt_service_destory(struct lb_virt_service *virt_srv) {
    if (!virt_srv)
        return;
    if (rte_atomic32_add_return(&virt_srv->refcnt, -1) != 0)
        return;
    if (virt_srv->sched->destruct)
        virt_srv->sched->destruct(virt_srv);
    rte_free(virt_srv);
}

static struct lb_real_service *
real_service_create(uint32_t rip, uint16_t rport,
                    struct lb_virt_service *virt_srv) {
    struct lb_real_service *real_srv;

    real_srv = rte_zmalloc(NULL, sizeof(struct lb_real_service), 0);
    if (!real_srv) {
        RTE_LOG(ERR, LB, "Alloc memory for real service failed.\n");
        return NULL;
    }
    real_srv->rip = rip;
    real_srv->rport = rport;
    real_srv->proto_type = virt_srv->proto_type;
    real_srv->virt_service = virt_service_ref(virt_srv);
    rte_atomic32_set(&real_srv->refcnt, 1);
    return real_srv;
}

void
lb_real_service_destory(struct lb_real_service *real_srv) {
    if (!real_srv)
        return;
    if (rte_atomic32_add_return(&real_srv->refcnt, -1) != 0)
        return;
    virt_service_destory(real_srv->virt_service);
    rte_free(real_srv);
}

struct lb_virt_service *
lb_virt_service_find(uint32_t vip, uint16_t vport, uint8_t proto_type) {
    struct rte_hash *virt_services = service_table->virt_services;
    uint64_t key = virt_service_key(vip, vport, proto_type);
    struct lb_virt_service *virt_srv;

    return rte_hash_lookup_data(virt_services, &key, (void **)&virt_srv) < 0
               ? NULL
               : virt_srv;
}

int
lb_is_vip_exist(uint32_t vip) {
    return rte_hash_lookup(service_table->vips, &vip) < 0 ? 0 : 1;
}

static int
is_virt_service_table_full(struct lb_service_table *table) {
    return table->service_count >= table->table_size ? 1 : 0;
}

static int
virt_service_table_add(struct lb_service_table *table,
                       struct lb_virt_service *virt_srv) {
    uint64_t key =
        virt_service_key(virt_srv->vip, virt_srv->vport, virt_srv->proto_type);
    uint32_t vip = virt_srv->vip;
    uint32_t vip_count;
    void *data;

    if (rte_hash_add_key_data(table->virt_services, &key, virt_srv) < 0)
        return -1;
    if (rte_hash_lookup_data(table->vips, &vip, (void **)&data) < 0) {
        vip_count = 1;
    } else {
        vip_count = (uint32_t)(uintptr_t)data + 1;
    }
    if (rte_hash_add_key_data(table->vips, &vip, (void *)(uintptr_t)vip_count) <
        0) {
        rte_hash_del_key(table->virt_services, &key);
        return -1;
    }
    table->service_count++;
    return 0;
}

static void
virt_service_table_del(struct lb_service_table *table,
                       struct lb_virt_service *virt_srv) {
    uint64_t key =
        virt_service_key(virt_srv->vip, virt_srv->vport, virt_srv->proto_type);
    uint32_t vip = virt_srv->vip;
    uint32_t vip_count;
    void *data;

    if (rte_hash_del_key(table->virt_services, &key) < 0)
        return;
    if (rte_hash_lookup_data(table->vips, &vip, (void **)&data) < 0)
        return;
    vip_count = (uint32_t)(uintptr_t)data - 1;
    if (vip_count == 0) {
        rte_hash_del_key(table->vips, &vip);
    } else {
        rte_hash_add_key_data(table->vips, &vip, (void *)(uintptr_t)vip_count);
    }
    table->service_count--;
}

static struct lb_real_service *
real_service_find(struct lb_virt_service *virt_srv, uint32_t rip,
                  uint16_t rport) {
    struct lb_real_service *real_srv;

    LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
        if (real_srv->rip == rip && real_srv->rport == rport) {
            return real_srv;
        }
    }
    return NULL;
}

static inline int
__real_srv_disable_schedule(struct lb_real_service *real_srv) {
    struct lb_virt_service *virt_srv = real_srv->virt_service;
    return virt_srv->sched->del(virt_srv, real_srv);
}

static inline int
__real_srv_enable_schedule(struct lb_real_service *real_srv) {
    struct lb_virt_service *virt_srv = real_srv->virt_service;
    return virt_srv->sched->add(virt_srv, real_srv);
}

static void
virt_service_add_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto_type;
    const struct lb_scheduler *scheduler;
    struct lb_virt_service *virt_srv;

    /* parse args */
    if (parse_ipv4_port(argv[0], &vip, &vport) < 0) {
        unixctl_command_reply_error(fd, "Invalid IPv4 address: %s.\n", argv[0]);
        return;
    }
    if (parse_l4_proto(argv[1], &proto_type) < 0) {
        unixctl_command_reply_error(fd, "Invalid proto type: %s.\n", argv[1]);
        return;
    }
    if (argc > 2) {
        scheduler = lb_scheduler_lookup_by_name(argv[2]);
    } else {
        scheduler = lb_scheduler_lookup_by_name("ipport");
    }
    if (!scheduler) {
        unixctl_command_reply_error(fd, "Invalid scheduler type.\n");
        return;
    }
    /* check cond */
    if (is_virt_service_table_full(service_table)) {
        unixctl_command_reply_error(fd, "Virt service table is full.\n");
        return;
    }
    if (lb_virt_service_find(vip, vport, proto_type)) {
        unixctl_command_reply_error(fd, "Virt service is exist.\n");
        return;
    }
    /* create virt-service */
    virt_srv = virt_service_create(vip, vport, proto_type, scheduler);
    if (!virt_srv) {
        unixctl_command_reply_error(fd, "Create virt service failed.\n");
        return;
    }
    if (virt_service_table_add(service_table, virt_srv) < 0) {
        virt_service_destory(virt_srv);
        unixctl_command_reply_error(fd,
                                    "Insert virt service to table failed.\n");
    }
}

static inline void
real_service_table_del_all(struct lb_virt_service *virt_srv) {
    struct lb_real_service *real_srv;

    while ((real_srv = LIST_FIRST(&virt_srv->real_services))) {
        LIST_REMOVE(real_srv, next);
        __real_srv_disable_schedule(real_srv);
        lb_real_service_destory(real_srv);
    }
}

static inline int
__virt_service_get_by_args(int fd, char *argv[],
                           struct lb_virt_service **virt_srv) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto_type;

    /* parse args */
    if (parse_ipv4_port(argv[0], &vip, &vport) < 0) {
        unixctl_command_reply_error(fd, "Invalid IPv4 address: %s.\n", argv[0]);
        return -1;
    }
    if (parse_l4_proto(argv[1], &proto_type) < 0) {
        unixctl_command_reply_error(fd, "Invalid proto type: %s.\n", argv[1]);
        return -1;
    }
    if (!(*virt_srv = lb_virt_service_find(vip, vport, proto_type))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return -1;
    }
    return 0;
}

static void
virt_service_del_cmd_cb(int fd, char *argv[], __attribute((unused)) int argc) {
    struct lb_virt_service *virt_srv;

    /* parse args */
    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    thread_write_lock();
    /* delete all real service */
    real_service_table_del_all(virt_srv);
    /* delete virt service */
    virt_service_table_del(service_table, virt_srv);
    virt_service_destory(virt_srv);
    thread_write_unlock();
}

static inline const char *
l4proto_format(uint8_t l4proto) {
    if (l4proto == IPPROTO_TCP)
        return "tcp";
    if (l4proto == IPPROTO_UDP)
        return "udp";
    return "oth";
}

static void
virt_service_list_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}"
#define _(K, V, S) "\"" K "\":" V S
    static const char *output_json_fmt = _JSON_FMT(
        _("IP", "\"%s\"", ",") _("Port", "%u", ",") _("Type", "\"%s\"", ",")
            _("Sched", "\"%s\"", ",") _("Refcnt", "%d", ",")
                _("Max_conns", "%d", ",") _("Active_conns", "%d", ""));
#undef _
#undef _JSON_FMT

    if (argc > 0) {
        struct lb_virt_service *virt_srv;
        const void *key;
        uint32_t next = 0;
        char ipbuf[32];
        uint8_t is_first = 1;

        if (strcmp(argv[0], "--json") == 0) {
            unixctl_command_reply(fd, "[");
            while (rte_hash_iterate(service_table->virt_services, &key,
                                    (void **)&virt_srv, &next) >= 0) {
                if (is_first) {
                    is_first = !is_first;
                } else {
                    unixctl_command_reply(fd, ",");
                }
                ipv4_addr_tostring(virt_srv->vip, ipbuf, sizeof(ipbuf));
                unixctl_command_reply(
                    fd, output_json_fmt, ipbuf,
                    rte_be_to_cpu_16(virt_srv->vport),
                    l4proto_format(virt_srv->proto_type), virt_srv->sched->name,
                    rte_atomic32_read(&virt_srv->refcnt), virt_srv->max_conns,
                    rte_atomic32_read(&virt_srv->active_conns));
            }
            unixctl_command_reply(fd, "]\n");
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[0]);
            return;
        }
    } else {
        struct lb_virt_service *virt_srv;
        const void *key;
        uint32_t next = 0;
        char ipbuf[32];

        unixctl_command_reply(fd, "IP               Port   Type   Sched       "
                                  "Refcnt      Max_conns   Active_conns\n");
        while (rte_hash_iterate(service_table->virt_services, &key,
                                (void **)&virt_srv, &next) >= 0) {
            ipv4_addr_tostring(virt_srv->vip, ipbuf, sizeof(ipbuf));
            unixctl_command_reply(
                fd, "%-15s  %-5u  %-5s  %-10s  %-10d  %-10d  %-10d\n", ipbuf,
                rte_be_to_cpu_16(virt_srv->vport),
                l4proto_format(virt_srv->proto_type), virt_srv->sched->name,
                rte_atomic32_read(&virt_srv->refcnt), virt_srv->max_conns,
                rte_atomic32_read(&virt_srv->active_conns));
        }
    }
}

static void
virt_service_max_conn_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t val;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc == 2) {
        unixctl_command_reply(fd, "max-conns: %u\n", virt_srv->max_conns);
        return;
    }
    if (parser_read_uint32(&val, argv[2]) < 0) {
        unixctl_command_reply_error(fd, "Invalid value: %s.\n", argv[2]);
        return;
    }
    thread_write_lock();
    virt_srv->max_conns = val;
    thread_write_unlock();
}

static void
virt_service_conn_expire_time_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t val;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc == 2) {
        unixctl_command_reply(fd, "conn-expire-time: %u\n",
                              virt_srv->conn_expire_period / rte_get_tsc_hz());
        return;
    }
    if (parser_read_uint32(&val, argv[2]) < 0) {
        unixctl_command_reply_error(fd, "Invalid value: %s.\n", argv[2]);
        return;
    }
    thread_write_lock();
    virt_srv->conn_expire_period = val * rte_get_tsc_hz();
    thread_write_unlock();
}

static void
virt_service_source_ipv4_passthrough_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_virt_service *virt_srv;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc == 2) {
        unixctl_command_reply(fd, "source-ipv4-address-passthrough: %s\n",
                              virt_srv->source_ip_transport ? "enable"
                                                            : "disable");
        return;
    }
    if (strcmp(argv[2], "enable") == 0) {
        thread_write_lock();
        virt_srv->source_ip_transport = 1;
        thread_write_unlock();
    } else if (strcmp(argv[2], "disable") == 0) {
        thread_write_lock();
        virt_srv->source_ip_transport = 0;
        thread_write_unlock();
    } else {
        unixctl_command_reply_error(fd, "Invalid value: %s.\n", argv[2]);
    }
}

static void
virt_service_schedule_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_virt_service *virt_srv;
    const struct lb_scheduler *sched;
    struct lb_real_service *real_srv;
    void *old_sched_data, *new_sched_data;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc == 2) {
        unixctl_command_reply(fd, "schedule-algorithm: %s\n",
                              virt_srv->sched->name);
        return;
    }

    sched = lb_scheduler_lookup_by_name(argv[2]);
    if (!sched) {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
        return;
    }

    if (sched == virt_srv->sched) {
        return;
    }

    thread_write_lock();
    old_sched_data = virt_srv->sched_data;
    if (sched->construct && sched->construct(virt_srv) < 0) {
        thread_write_unlock();
        unixctl_command_reply_error(
            fd, "Cannot alloc schedule due to the lack of memory\n");
        return;
    }
    new_sched_data = virt_srv->sched_data;
    virt_srv->sched_data = old_sched_data;

    LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
        if (real_srv->online) {
            virt_srv->sched->del(virt_srv, real_srv);
            /* 保存rs状态 */
            real_srv->online = 1;
        }
    }

    if (virt_srv->sched->destruct) {
        virt_srv->sched->destruct(virt_srv);
    }

    virt_srv->sched = sched;
    virt_srv->sched_data = new_sched_data;

    LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
        if (real_srv->online) {
            /* 恢复rs状态 */
            real_srv->online = 0;
            virt_srv->sched->add(virt_srv, real_srv);
        }
    }
    thread_write_unlock();
}

static void
virt_service_cql_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t size;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }

    if (argc < 3) {
        /* 查询CQL信息 */
        if (virt_srv->cql) {
            unixctl_command_reply(fd, "CQL is on, size is %u\n",
                                  lb_cql_size(virt_srv->cql));
        } else {
            unixctl_command_reply(fd, "CQL is off\n");
        }
        return;
    }

    if (argc > 3) {
        /* 自定义CQL  表SIZE */
        if (parser_read_uint32(&size, argv[3]) < 0) {
            return;
        }
    } else {
        size = lb_cfg->srv.cql_size;
    }

    if (strcasecmp(argv[2], "on") == 0) {
        struct lb_cql *cql;
        char cql_name[RTE_HASH_NAMESIZE];

        if (virt_srv->cql) {
            return;
        }
        snprintf(cql_name, RTE_HASH_NAMESIZE, "cql%p", virt_srv);
        cql = lb_cql_create(cql_name, size);
        if (!cql) {
            unixctl_command_reply_error(
                fd, "Create CQL failed due to the lack of memory\n");
            return;
        }
        thread_write_lock();
        virt_srv->cql = cql;
        thread_write_unlock();
    } else if (strcasecmp(argv[2], "off") == 0) {
        if (!virt_srv->cql) {
            return;
        }
        thread_write_lock();
        lb_cql_destory(virt_srv->cql);
        virt_srv->cql = NULL;
        thread_write_unlock();
    } else {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
    }
}

static void
virt_service_cql_list_cmd_cb(int fd, char *argv[],
                             __attribute((unused)) int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t ip, qps;
    uint32_t n = 0;
    char ipbuf[32];

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (!virt_srv->cql) {
        return;
    }
    while (lb_cql_rule_iterate(virt_srv->cql, &ip, &qps, &n) >= 0) {
        ipv4_addr_tostring(ip, ipbuf, sizeof(ipbuf));
        unixctl_command_reply(fd, "ip: %-15s,qps: %u\n", ipbuf, qps);
    }
}

static void
virt_service_cql_add_cmd_cb(int fd, char *argv[],
                            __attribute((unused)) int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t ip, qps;
    int ret;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (!virt_srv->cql) {
        unixctl_command_reply_error(fd, "CQL is off\n");
        return;
    }
    if (parse_ipv4_addr(argv[2], (struct in_addr *)&ip) < 0) {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
        return;
    }
    if (parser_read_uint32(&qps, argv[3]) < 0) {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[3]);
        return;
    }
    thread_write_lock();
    ret = lb_cql_rule_add(virt_srv->cql, ip, qps);
    thread_write_unlock();
    if (ret < 0) {
        unixctl_command_reply_error(fd, "Cannot add CQL rule\n");
    }
}

static void
virt_service_cql_del_cmd_cb(int fd, char *argv[],
                            __attribute((unused)) int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t ip;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (!virt_srv->cql) {
        unixctl_command_reply_error(fd, "CQL is off\n");
        return;
    }
    if (parse_ipv4_addr(argv[2], (struct in_addr *)&ip) < 0) {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
        return;
    }
    thread_write_lock();
    lb_cql_rule_del(virt_srv->cql, ip);
    thread_write_unlock();
}

#ifdef __CONN_REPORT_CMD__
static void
__addrs_dump(int fd, uint32_t *addrs, uint32_t size) {
    struct rte_hash_parameters params = {0};
    char hashname[RTE_HASH_NAMESIZE];
    struct rte_hash *h;

    snprintf(hashname, RTE_HASH_NAMESIZE, "addrdump%p", addrs);
    params.name = hashname;
    params.entries = size;
    params.key_len = sizeof(uint32_t);
    params.hash_func = rte_hash_crc;
    params.socket_id = rte_socket_id();
    h = rte_hash_create(&params);
    if (!h) {
        unixctl_command_reply_error(fd, "Cannot create hash for addrs dump\n");
        return;
    }

    {
        uint32_t count;
        void *data;
        uint32_t i;

        for (i = 0; i < size; i++) {
            count = rte_hash_lookup_data(h, (const void *)&addrs[i], &data) >= 0
                        ? (uint32_t)(uintptr_t)data + 1
                        : 1;
            rte_hash_add_key_data(h, (const void *)&addrs[i],
                                  (void *)(uintptr_t)count);
        }
    }

    {
        const uint32_t *ip;
        void *data;
        uint32_t next = 0;
        uint32_t count;
        char ipbuf[32];

        while (rte_hash_iterate(h, (const void **)&ip, (void **)&data, &next) >=
               0) {
            count = (uint32_t)(uintptr_t)data;
            ipv4_addr_tostring(*ip, ipbuf, sizeof(ipbuf));
            unixctl_command_reply(fd, "ip: %-15s ,count: %u\n", ipbuf, count);
        }
    }
    rte_hash_free(h);
}

static void
__virt_service_conn_report(int fd, struct lb_connection_table *tbl,
                           const struct lb_virt_service *vs,
                           uint64_t duration) {
    struct lb_connection *conn;
    uint32_t lcore_id;
    uint64_t now_cycles, used_ms;
    uint32_t *addrs;
    uint32_t count = 0, i = 0;

    thread_write_lock();
    RTE_LCORE_FOREACH_SLAVE(lcore_id) { count += tbl->count[lcore_id]; }
    thread_write_unlock();

    if (count == 0) {
        return;
    }

    addrs = rte_calloc(NULL, count, sizeof(uint32_t), 0);
    if (!addrs) {
        unixctl_command_reply_error(
            fd,
            "Cannot report connection infomation due to the lack of memory\n");
        return;
    }

    now_cycles = rte_get_tsc_cycles();
    thread_write_lock();
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        TAILQ_FOREACH(conn, &tbl->conn_expire_tbl_percore[lcore_id], next) {
            if (conn->real_service->virt_service != vs) {
                continue;
            }
            if (conn->recent_use_time + duration < now_cycles) {
                continue;
            }
            if (i >= count) {
                break;
            }
            addrs[i++] = conn->c4tuple.sip;
        }
    }
    thread_write_unlock();
    used_ms = (rte_get_tsc_cycles() - now_cycles) / (rte_get_tsc_hz() / 1000);
    unixctl_command_reply(fd, "Results(%" PRIu64 "ms):\n", used_ms);
    __addrs_dump(fd, addrs, i);
    rte_free(addrs);
}

static void
virt_service_conn_report_cmd_cb(int fd, char *argv[],
                                __attribute((unused)) int argc) {
    struct lb_virt_service *virt_srv;
    uint32_t sec;
    struct lb_connection_table *t;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (parser_read_uint32(&sec, argv[2]) < 0) {
        unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
        return;
    }
    t = virt_srv->proto_type == IPPROTO_TCP ? lb_tcp_connection_table_get()
                                            : lb_udp_connection_table_get();
    __virt_service_conn_report(fd, t, virt_srv, sec * rte_get_tsc_hz());
    return;
}
#endif

static void
real_service_add_cmd_cb(int fd, char *argv[], __attribute((unused)) int argc) {
    uint32_t rip;
    uint16_t rport;
    struct lb_virt_service *virt_srv;
    struct lb_real_service *real_srv;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    /* parse args */
    if (parse_ipv4_port(argv[2], &rip, &rport) < 0) {
        unixctl_command_reply_error(fd, "Invalid IPv4 address: %s.\n", argv[2]);
        return;
    }
    if (real_service_find(virt_srv, rip, rport) != NULL) {
        unixctl_command_reply_error(fd, "Real service is exist.\n");
        return;
    }
    /* create real_srv */
    if (!(real_srv = real_service_create(rip, rport, virt_srv))) {
        unixctl_command_reply_error(fd, "Cannot create real service.\n");
        return;
    }
    thread_write_lock();
    if (__real_srv_enable_schedule(real_srv) < 0) {
        thread_write_unlock();
        lb_real_service_destory(real_srv);
        unixctl_command_reply_error(fd,
                                    "Enable real service schedule failed.\n");
        return;
    }
    LIST_INSERT_HEAD(&virt_srv->real_services, real_srv, next);
    thread_write_unlock();
}

static inline int
__real_service_get_by_args(int fd, char *argv[],
                           struct lb_real_service **real_srv) {
    struct lb_virt_service *virt_srv;
    uint32_t rip;
    uint16_t rport;

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return -1;
    }
    if (parse_ipv4_port(argv[2], &rip, &rport) < 0) {
        unixctl_command_reply_error(fd, "Invalid IPv4 address: %s.\n", argv[2]);
        return -1;
    }
    if (!(*real_srv = real_service_find(virt_srv, rip, rport))) {
        unixctl_command_reply_error(fd, "Cannot find Real service.\n");
        return -1;
    }
    return 0;
}

static void
real_service_del_cmd_cb(int fd, char *argv[], __attribute((unused)) int argc) {
    struct lb_real_service *real_srv;

    if (__real_service_get_by_args(fd, argv, &real_srv) < 0) {
        return;
    }
    /* delete real service */
    thread_write_lock();
    LIST_REMOVE(real_srv, next);
    __real_srv_disable_schedule(real_srv);
    lb_real_service_destory(real_srv);
    thread_write_unlock();
}

static void
real_service_list_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}"
#define _(K, V, S) "\"" K "\":" V S
    static const char *output_json_fmt = _JSON_FMT(
        _("IP", "\"%s\"", ",") _("Port", "%u", ",") _("Type", "\"%s\"", ",")
            _("Status", "\"%s\"", ",") _("Refcnt", "%d", ""));
#undef _
#undef _JSON_FMT

    struct lb_virt_service *virt_srv;
    struct lb_real_service *real_srv;
    char ipbuf[32];

    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc > 2) {
        uint8_t is_first = 1;

        if (strcmp(argv[2], "--json") == 0) {
            unixctl_command_reply(fd, "[");
            LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
                if (is_first) {
                    is_first = !is_first;
                } else {
                    unixctl_command_reply(fd, ",");
                }
                ipv4_addr_tostring(real_srv->rip, ipbuf, sizeof(ipbuf));
                unixctl_command_reply(fd, output_json_fmt, ipbuf,
                                      rte_be_to_cpu_16(real_srv->rport),
                                      l4proto_format(real_srv->proto_type),
                                      real_srv->online ? "up" : "down",
                                      rte_atomic32_read(&real_srv->refcnt));
            }
            unixctl_command_reply(fd, "]\n");
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
            return;
        }
    } else {
        unixctl_command_reply(
            fd, "IP               Port   Type  Status      Refcnt\n");
        LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
            ipv4_addr_tostring(real_srv->rip, ipbuf, sizeof(ipbuf));
            unixctl_command_reply(fd, "%-15s  %-5u  %-4s  %-10s  %d\n", ipbuf,
                                  rte_be_to_cpu_16(real_srv->rport),
                                  l4proto_format(real_srv->proto_type),
                                  real_srv->online ? "up" : "down",
                                  rte_atomic32_read(&real_srv->refcnt));
        }
    }
}

static void
real_service_status_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_real_service *real_srv;

    if (__real_service_get_by_args(fd, argv, &real_srv) < 0) {
        return;
    }
    if (argc == 3) {
        unixctl_command_reply(fd, "status: %s\n",
                              real_srv->online ? "UP" : "DOWN");
        return;
    }
    if (strcasecmp(argv[3], "up") == 0) {
        thread_write_lock();
        __real_srv_enable_schedule(real_srv);
        thread_write_unlock();
    } else if (strcasecmp(argv[3], "down") == 0) {
        thread_write_lock();
        __real_srv_disable_schedule(real_srv);
        thread_write_unlock();
    } else {
        unixctl_command_reply_error(fd, "Unkonw option: %s\n", argv[3]);
    }
}

static void
virt_service_stats_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}\n"
#define _(K, S) "\"" K "\":%" PRIu64 S
    static const char *output_json_fmt = _JSON_FMT(
        _("active-conns", ",") _("history-conns", ",")
            _("[c-to-vs]packets", ",") _("[c-to-vs]bytes", ",")
                _("[c-to-vs]drops", ",") _("[rs-to-vs]packets", ",")
                    _("[rs-to-vs]bytes", ",") _("[rs-to-vs]drops", ",")
                        _("[vs-to-rs]packets", ",") _("[vs-to-rs]bytes", ",")
                            _("[vs-to-c]packets", ",") _("[vs-to-c]bytes", ""));
#undef _
#undef _JSON_FMT

#define _NORM_FMT(O) O
#define _(K, S) K ": %-20" PRIu64 "\n"
    static const char *output_norm_fmt = _NORM_FMT(
        _("active-conns", ",") _("history-conns", ",")
            _("[c-to-vs]packets", ",") _("[c-to-vs]bytes", ",")
                _("[c-to-vs]drops", ",") _("[rs-to-vs]packets", ",")
                    _("[rs-to-vs]bytes", ",") _("[rs-to-vs]drops", ",")
                        _("[vs-to-rs]packets", ",") _("[vs-to-rs]bytes", ",")
                            _("[vs-to-c]packets", ",") _("[vs-to-c]bytes", ""));
#undef _
#undef _NORM_FMT

    struct lb_virt_service *virt_srv;
    uint32_t lcore_id;
    uint64_t rx_packets[2] = {0}, rx_bytes[2] = {0}, rx_drops[2] = {0};
    uint64_t tx_packets[2] = {0}, tx_bytes[2] = {0};
    uint64_t history_conns = 0;
    struct lb_real_service *real_srv;
    const char *output_fmt;

    /* parse args */
    if (__virt_service_get_by_args(fd, argv, &virt_srv) < 0) {
        return;
    }
    if (argc > 2) {
        if (strcmp(argv[2], "--json") == 0) {
            output_fmt = output_json_fmt;
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[2]);
            return;
        }
    } else {
        output_fmt = output_norm_fmt;
    }
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rx_packets[0] += virt_srv->stats[lcore_id][0].packets;
        rx_packets[1] += virt_srv->stats[lcore_id][1].packets;
        rx_bytes[0] += virt_srv->stats[lcore_id][0].bytes;
        rx_bytes[1] += virt_srv->stats[lcore_id][1].bytes;
        rx_drops[0] += virt_srv->stats[lcore_id][0].drops;
        rx_drops[1] += virt_srv->stats[lcore_id][1].drops;
        history_conns += virt_srv->history_conns[lcore_id];
    }
    LIST_FOREACH(real_srv, &virt_srv->real_services, next) {
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            tx_packets[0] += real_srv->stats[lcore_id][0].packets;
            tx_packets[1] += real_srv->stats[lcore_id][1].packets;
            tx_bytes[0] += real_srv->stats[lcore_id][0].bytes;
            tx_bytes[1] += real_srv->stats[lcore_id][1].bytes;
        }
    }
    unixctl_command_reply(
        fd, output_fmt, (uint64_t)rte_atomic32_read(&virt_srv->active_conns),
        history_conns, rx_packets[0], rx_bytes[0], rx_drops[0], rx_packets[1],
        rx_bytes[1], rx_drops[1], tx_packets[0], tx_bytes[0], tx_packets[1],
        tx_bytes[1]);
}

static void
real_service_stats_cmd_cb(int fd, char *argv[],
                          __attribute((unused)) int argc) {
    struct lb_real_service *real_srv;
    uint32_t lcore_id;
    uint64_t packets[2] = {0}, bytes[2] = {0};
    uint64_t conns = 0;

    if (__real_service_get_by_args(fd, argv, &real_srv) < 0) {
        return;
    }
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        packets[0] += real_srv->stats[lcore_id][0].packets;
        packets[1] += real_srv->stats[lcore_id][1].packets;
        bytes[0] += real_srv->stats[lcore_id][0].bytes;
        bytes[1] += real_srv->stats[lcore_id][1].bytes;
        conns += real_srv->history_conns[lcore_id];
    }
    unixctl_command_reply(fd, "active-conns: %-20" PRIu32 "\n"
                              "history-conns: %-20" PRIu64 "\n"
                              "[vs-to-rs]packets: %-20" PRIu64 "\n"
                              "[vs-to-rs]bytes: %-20" PRIu64 "\n"
                              "[rs-to-vs]packets: %-20" PRIu64 "\n"
                              "[rs-to-vs]bytes: %-20" PRIu64 "\n",
                          rte_atomic32_read(&real_srv->active_conns), conns,
                          packets[0], bytes[0], packets[1], bytes[1]);
}

static inline struct rte_hash *
hash_table_create(const char *name, uint32_t table_size, uint32_t key_len) {
    struct rte_hash_parameters params = {0};

    params.name = name;
    params.entries = table_size;
    params.key_len = key_len;
    params.hash_func = rte_hash_crc;
    params.socket_id = rte_socket_id();
    return rte_hash_create(&params);
}

void
lb_service_table_init(void) {
    struct service_config *cfg = &lb_cfg->srv;

    service_table = rte_zmalloc(NULL, sizeof(struct lb_service_table), 0);
    if (!service_table)
        rte_exit(EXIT_FAILURE, "Alloc memory for lb service table failed.\n");
    service_table->table_size = cfg->vs_max_num;
    service_table->virt_services = hash_table_create(
        "virt-services", service_table->table_size, sizeof(uint64_t));
    service_table->vips =
        hash_table_create("vips", service_table->table_size, sizeof(uint32_t));
    if (!service_table->virt_services || !service_table->vips)
        rte_exit(EXIT_FAILURE, "Create hash table for lb service failed.\n");

    service_table->tcp_conn_expire_period =
        lb_cfg->tcp.conn_expire_period * rte_get_tsc_hz();
    service_table->udp_conn_expire_period =
        lb_cfg->udp.conn_expire_period * rte_get_tsc_hz();

    unixctl_command_register(
        "vs/add", "VIP:VPORT tcp|udp [ipport|iponly|rr|lc].",
        "Add virtual service.", 2, 3, virt_service_add_cmd_cb);
    unixctl_command_register("vs/del", "VIP:VPORT tcp|udp.",
                             "Delete virtual service.", 2, 2,
                             virt_service_del_cmd_cb);
    unixctl_command_register("vs/list", "[--json].",
                             "List all virtual services.", 0, 1,
                             virt_service_list_cmd_cb);
    unixctl_command_register("vs/stats", "VIP:VPORT tcp|udp [--json].",
                             "Show packet statistics of virtual service.", 2, 3,
                             virt_service_stats_cmd_cb);
    unixctl_command_register(
        "vs/max-conns", "VIP:VPORT tcp|udp [VALUE].",
        "Show or set max number of connection to virtual service.", 2, 3,
        virt_service_max_conn_cmd_cb);
    unixctl_command_register("vs/conn-expire-time",
                             "VIP:VPORT tcp|udp [VALUE].",
                             "Show or set connection expiration time.", 2, 3,
                             virt_service_conn_expire_time_cmd_cb);
    unixctl_command_register(
        "vs/source-ipv4-passthrough", "VIP:VPORT tcp|udp [enabel|disable].",
        "Show or set whether to pass client addres to real service.", 2, 3,
        virt_service_source_ipv4_passthrough_cmd_cb);
    unixctl_command_register("vs/schedule",
                             "VIP:VPORT tcp|udp [ipport|iponly|rr|lc].",
                             "Show or set scheduling algorithm.", 2, 3,
                             virt_service_schedule_cmd_cb);
    unixctl_command_register(
        "vs/cql", "VIP:VPORT tcp|udp [on|off] [SIZE].",
        "Show or set whether to use CQL(client query limit).", 2, 4,
        virt_service_cql_cmd_cb);
    unixctl_command_register("vs/cql/list", "VIP:VPORT tcp|udp.",
                             "List all CQL rules.", 2, 2,
                             virt_service_cql_list_cmd_cb);
    unixctl_command_register("vs/cql/add", "VIP:VPORT tcp|udp IP QPS.",
                             "Add CQL rules.", 4, 4,
                             virt_service_cql_add_cmd_cb);
    unixctl_command_register("vs/cql/del", "VIP:VPORT tcp|udp IP.",
                             "Delete CQL rules", 3, 3,
                             virt_service_cql_del_cmd_cb);
#ifdef __CONN_REPORT_CMD__
    unixctl_command_register(
        "vs/conn-report", "VIP:VPORT tcp|udp COND_SEC.",
        "Report number of client queries in the past time.", 3, 3,
        virt_service_conn_report_cmd_cb);
#endif

    unixctl_command_register("rs/add", "VIP:VPORT tcp|udp RIP:RPORT.",
                             "Add real service.", 3, 3,
                             real_service_add_cmd_cb);
    unixctl_command_register("rs/del", "VIP:VPORT tcp|udp RIP:RPORT.",
                             "Delete real service.", 3, 3,
                             real_service_del_cmd_cb);
    unixctl_command_register("rs/list", "VIP:VPORT tcp|udp [--json].",
                             "List all real services.", 2, 3,
                             real_service_list_cmd_cb);
    unixctl_command_register("rs/status",
                             "VIP:VPORT tcp|udp RIP:RPORT [up|down].",
                             "Show or set real service status down or up.", 3,
                             4, real_service_status_cmd_cb);
    unixctl_command_register("rs/stats", "VIP:VPORT tcp|udp RIP:RPORT",
                             "Show packet statistics of real service.", 3, 3,
                             real_service_stats_cmd_cb);
}

