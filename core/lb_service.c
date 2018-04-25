/* Copyright (c) 2018. TIG developer. */

#include <sys/queue.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>

#include <unixctl_command.h>

#include "lb_clock.h"
#include "lb_device.h"
#include "lb_format.h"
#include "lb_parser.h"
#include "lb_scheduler.h"
#include "lb_service.h"

#define virt_service_key(ip, port, proto)                                      \
    (((uint64_t)(ip) << 32) | ((uint64_t)(port) << 16) | (uint64_t)(proto))

struct lb_vs_table {
    struct rte_hash *vs_htbl;
    struct rte_hash *vip_htbl;
    rte_rwlock_t rwlock;
} __rte_cache_aligned;

#define LB_VS_TBL_WLOCK(t) rte_rwlock_write_lock(&(t)->rwlock)
#define LB_VS_TBL_WUNLOCK(t) rte_rwlock_write_unlock(&(t)->rwlock)
#define LB_VS_TBL_RLOCK(t) rte_rwlock_read_lock(&(t)->rwlock)
#define LB_VS_TBL_RUNLOCK(t) rte_rwlock_read_unlock(&(t)->rwlock)

#define LB_VS_WLOCK(t) rte_rwlock_write_lock(&(t)->rwlock)
#define LB_VS_WUNLOCK(t) rte_rwlock_write_unlock(&(t)->rwlock)
#define LB_VS_RLOCK(t) rte_rwlock_read_lock(&(t)->rwlock)
#define LB_VS_RUNLOCK(t) rte_rwlock_read_unlock(&(t)->rwlock)

static struct lb_vs_table *lb_vs_tbls[RTE_MAX_NUMA_NODES];

static inline uint32_t
vs_tbl_get_next(int sid) {
    sid++;
    while (sid < RTE_MAX_NUMA_NODES) {
        if (lb_vs_tbls[sid] == NULL) {
            sid++;
            continue;
        }
        break;
    }
    return sid;
}

#define VS_TBL_FOREACH_SOCKET(socket_id)                                       \
    for (socket_id = vs_tbl_get_next(-1); socket_id < RTE_MAX_NUMA_NODES;      \
         socket_id = vs_tbl_get_next(socket_id))

int
lb_service_init(void) {
    uint32_t port_id, nb_ports;
    uint32_t socket_id;
    char name[RTE_HASH_NAMESIZE];
    struct rte_hash_parameters param;
    struct lb_vs_table *t;

    nb_ports = rte_eth_dev_count();
    for (port_id = 0; port_id < nb_ports; port_id++) {
        socket_id = rte_eth_dev_socket_id(port_id);

        if (lb_vs_tbls[socket_id] != NULL)
            continue;
        t = rte_zmalloc_socket("lb_vs_table", sizeof(*t), RTE_CACHE_LINE_SIZE,
                               socket_id);
        if (t == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Not enough memory.", __func__);
            return -1;
        }

        memset(&param, 0, sizeof(param));
        snprintf(name, sizeof(name), "vs_htbl%u", socket_id);
        param.name = name;
        param.entries = LB_MAX_VS;
        param.key_len = sizeof(uint64_t);
        param.socket_id = socket_id;
        param.hash_func = rte_hash_crc;

        t->vs_htbl = rte_hash_create(&param);
        if (t->vs_htbl == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Create hash table %s failed, %s.",
                    __func__, name, rte_strerror(rte_errno));
            return -1;
        }

        memset(&param, 0, sizeof(param));
        snprintf(name, sizeof(name), "vip_htbl%u", socket_id);
        param.name = name;
        param.entries = LB_MAX_VS;
        param.key_len = sizeof(uint32_t);
        param.socket_id = socket_id;
        param.hash_func = rte_hash_crc;

        t->vip_htbl = rte_hash_create(&param);
        if (t->vip_htbl == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Create hash table %s failed, %s.",
                    __func__, name, rte_strerror(rte_errno));
            return -1;
        }

        rte_rwlock_init(&t->rwlock);

        lb_vs_tbls[socket_id] = t;
    }

    return 0;
}

int
lb_is_vip_exist(uint32_t vip) {
    struct lb_vs_table *t;

    t = lb_vs_tbls[rte_socket_id()];
    return rte_hash_lookup(t->vip_htbl, &vip) >= 0;
}

static struct lb_virt_service *
vs_tbl_find(struct lb_vs_table *t, uint32_t vip, uint16_t vport,
            uint8_t proto) {
    struct lb_virt_service *vs = NULL;
    uint64_t key;

    key = virt_service_key(vip, vport, proto);
    rte_hash_lookup_data(t->vs_htbl, &key, (void **)&vs);

    return vs;
}

static int
vs_tbl_add(struct lb_vs_table *t, struct lb_virt_service *vs) {
    uint64_t key;
    int rc;
    void *p;
    uint32_t count = 0;

    key = virt_service_key(vs->vip, vs->vport, vs->proto);
    rc = rte_hash_add_key_data(t->vs_htbl, &key, vs);
    if (rc < 0) {
        return rc;
    }

    rc = rte_hash_lookup_data(t->vip_htbl, &vs->vip, &p);
    if (rc == 0) {
        count = (uint32_t)(uintptr_t)p;
    }
    count += 1;

    rc = rte_hash_add_key_data(t->vip_htbl, &vs->vip, (void *)(uintptr_t)count);
    if (unlikely(rc < 0)) {
        rte_hash_del_key(t->vs_htbl, &key);
    }

    return rc;
}

static void
vs_tbl_del(struct lb_vs_table *t, struct lb_virt_service *vs) {
    uint64_t key;
    int rc;
    void *p;
    uint32_t count;

    key = virt_service_key(vs->vip, vs->vport, vs->proto);
    rc = rte_hash_del_key(t->vs_htbl, &key);
    if (rc < 0) {
        return;
    }

    rc = rte_hash_lookup_data(t->vip_htbl, &vs->vip, &p);
    if (unlikely(rc < 0)) {
        return;
    }

    count = (uint32_t)(uintptr_t)p;
    count -= 1;
    if (count == 0) {
        rte_hash_del_key(t->vs_htbl, &key);
    } else {
        rte_hash_add_key_data(t->vip_htbl, &vs->vip, (void *)(uintptr_t)count);
    }
}

static struct lb_real_service *
vs_find_rs(struct lb_virt_service *vs, uint32_t rip, uint16_t rport) {
    struct lb_real_service *rs;

    LIST_FOREACH(rs, &vs->real_services, next) {
        if (rs->rip == rip && rs->rport == rport)
            return rs;
    }
    return NULL;
}

static void
lb_rs_list_insert_by_weight(struct lb_virt_service *vs,
                            struct lb_real_service *rs) {
    struct lb_real_service *real_service;

    if (LIST_EMPTY(&vs->real_services)) {
        LIST_INSERT_HEAD(&vs->real_services, rs, next);
        return;
    }

    LIST_FOREACH(real_service, &vs->real_services, next) {
        if (LIST_NEXT(real_service, next) == NULL)
            break;
        if (real_service->weight <= rs->weight)
            break;
    }

    if (real_service->weight <= rs->weight)
        LIST_INSERT_BEFORE(real_service, rs, next);
    else
        LIST_INSERT_AFTER(real_service, rs, next);
}

static void
lb_rs_list_update_by_weight(struct lb_virt_service *vs,
                            struct lb_real_service *rs) {
    LIST_REMOVE(rs, next);
    lb_rs_list_insert_by_weight(vs, rs);
}

struct lb_virt_service *
lb_vs_get(uint32_t vip, uint16_t vport, uint8_t proto) {
    uint32_t socket_id = rte_socket_id();
    struct lb_virt_service *vs;

    LB_VS_TBL_RLOCK(lb_vs_tbls[socket_id]);
    vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
    if (vs != NULL) {
        rte_atomic32_add(&vs->refcnt, 1);
    }
    LB_VS_TBL_RUNLOCK(lb_vs_tbls[socket_id]);

    return vs;
}

void
lb_vs_put(struct lb_virt_service *vs) {
    lb_vs_free(vs);
}

struct lb_real_service *
lb_vs_get_rs(struct lb_virt_service *vs, uint32_t cip, uint16_t cport) {
    struct lb_real_service *rs;

    LB_VS_RLOCK(vs);
    rs = vs->sched->dispatch(vs, cip, cport);
    if (rs != NULL) {
        rte_atomic32_add(&rs->refcnt, 1);
    }
    LB_VS_RUNLOCK(vs);

    return rs;
}

void
lb_vs_put_rs(struct lb_real_service *rs) {
    lb_rs_free(rs);
}

static struct lb_virt_service *
lb_vs_alloc(uint32_t vip, uint16_t vport, uint8_t proto,
            const struct lb_scheduler *sched, uint32_t socket_id) {
    struct lb_virt_service *vs;

    vs = rte_zmalloc_socket("vs", sizeof(*vs), RTE_CACHE_LINE_SIZE, socket_id);
    if (vs == NULL)
        return NULL;

    if (sched->init && sched->init(vs) < 0) {
        rte_free(vs);
        return NULL;
    }

    vs->vip = vip;
    vs->vport = vport;
    vs->proto = proto;
    vs->sched = sched;
    vs->max_conns = INT32_MAX;
    vs->socket_id = socket_id;
    rte_atomic32_set(&vs->refcnt, 1);

    return vs;
}

void
lb_vs_free(struct lb_virt_service *vs) {
    if (vs == NULL)
        return;

    if (rte_atomic32_add_return(&vs->refcnt, -1) != 0)
        return;
    if (vs->sched->fini)
        vs->sched->fini(vs);
    rte_free(vs);
}

static struct lb_real_service *
lb_rs_alloc(uint32_t rip, uint32_t rport, int weight,
            struct lb_virt_service *vs) {
    struct lb_real_service *rs;

    rs = rte_zmalloc_socket("rs", sizeof(*rs), RTE_CACHE_LINE_SIZE,
                            vs->socket_id);
    if (rs == NULL)
        return NULL;

    rs->rip = rip;
    rs->rport = rport;
    rs->proto = vs->proto;
    rs->weight = weight;
    rs->virt_service = vs;
    rte_atomic32_add(&vs->refcnt, 1);
    rte_atomic32_set(&rs->refcnt, 1);

    return rs;
}

void
lb_rs_free(struct lb_real_service *rs) {
    if (rs == NULL)
        return;
    if (rte_atomic32_add_return(&rs->refcnt, -1) != 0)
        return;
    lb_vs_free(rs->virt_service);
    rte_free(rs);
}

static void
vs_del_all_rs(struct lb_virt_service *vs) {
    struct lb_real_service *rs;

    while ((rs = LIST_FIRST(&vs->real_services)) != NULL) {
        LIST_REMOVE(rs, next);
        vs->sched->del(vs, rs);
        lb_rs_free(rs);
    }
}

/* UNIXCTL COMMAND */

static int
vs_add_arg_parse(char *argv[], __attribute((unused)) int argc, uint32_t *vip,
                 uint16_t *vport, uint8_t *proto,
                 const struct lb_scheduler **sched) {
    int i = 0;
    int rc;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    /* scheduler */
    rc = lb_scheduler_lookup_by_name(argv[i++], sched);
    if (rc < 0) {
        return i - 1;
    }

    return i;
}

static void
vs_add_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    const struct lb_scheduler *sched;
    int rc;
    struct lb_virt_service *vss[RTE_MAX_NUMA_NODES] = {0};
    uint32_t socket_id;

    memset(vss, 0, sizeof(vss));

    rc = vs_add_arg_parse(argv, argc, &vip, &vport, &proto, &sched);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        if (vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto) != NULL) {
            unixctl_command_reply_error(fd, "Virt service already exists.\n");
            goto free_vss;
        }

        vss[socket_id] = lb_vs_alloc(vip, vport, proto, sched, socket_id);
        if (vss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Not enough memory.\n");
            goto free_vss;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        LB_VS_TBL_WLOCK(lb_vs_tbls[socket_id]);
        rc = vs_tbl_add(lb_vs_tbls[socket_id], vss[socket_id]);
        LB_VS_TBL_WUNLOCK(lb_vs_tbls[socket_id]);
        if (rc < 0) {
            unixctl_command_reply_error(fd, "No space in the table.\n");
            goto del_vss;
        }
    }

    return;

del_vss:
    VS_TBL_FOREACH_SOCKET(socket_id) {
        LB_VS_TBL_WLOCK(lb_vs_tbls[socket_id]);
        vs_tbl_del(lb_vs_tbls[socket_id], vss[socket_id]);
        LB_VS_TBL_WUNLOCK(lb_vs_tbls[socket_id]);
    }

free_vss:
    VS_TBL_FOREACH_SOCKET(socket_id) { lb_vs_free(vss[socket_id]); }
}

UNIXCTL_CMD_REGISTER("vs/add", "VIP:VPORT tcp|udp ipport|iponly|rr|wrr.",
                     "Add virtual service.", 3, 3, vs_add_cmd_cb);

static int
vs_del_arg_parse(char *argv[], __attribute((unused)) int argc, uint32_t *vip,
                 uint16_t *vport, uint8_t *proto) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    return i;
}

static void
vs_del_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vs;

    rc = vs_del_arg_parse(argv, argc, &vip, &vport, &proto);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs != NULL) {
            LB_VS_WLOCK(vs);
            vs_del_all_rs(vs);
            LB_VS_WUNLOCK(vs);

            LB_VS_TBL_WLOCK(lb_vs_tbls[socket_id]);
            vs_tbl_del(lb_vs_tbls[socket_id], vs);
            LB_VS_TBL_WUNLOCK(lb_vs_tbls[socket_id]);

            lb_vs_free(vs);
        }
    }
}

UNIXCTL_CMD_REGISTER("vs/del", "VIP:VPORT tcp|udp.", "Delete virtual service.",
                     2, 2, vs_del_cmd_cb);

static inline const char *
l4proto_format(uint8_t l4proto) {
    if (l4proto == IPPROTO_TCP)
        return "tcp";
    if (l4proto == IPPROTO_UDP)
        return "udp";
    return "oth";
}

static int
vs_list_arg_parse(char *argv[], int argc, int *json_fmt) {
    int i = 0;
    int rc;

    if (i < argc) {
        rc = strcmp(argv[i++], "--json");
        if (rc != 0)
            return i - 1;
        *json_fmt = 1;
    } else {
        *json_fmt = 0;
    }

    return i;
}

static void
vs_list_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt, json_first_obj = 1;
    int rc;
    uint32_t socket_id;
    struct lb_vs_table *t = NULL;
    const void *key;
    uint32_t next = 0;
    struct lb_virt_service *vs;
    char buf[32];

    rc = vs_list_arg_parse(argv, argc, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        t = lb_vs_tbls[socket_id];

        unixctl_command_reply(fd, json_fmt ? "["
                                           : "IP               Port   "
                                             "Type   Sched       Max_conns\n");
        while (rte_hash_iterate(t->vs_htbl, &key, (void **)&vs, &next) >= 0) {
            ipv4_addr_tostring(vs->vip, buf, sizeof(buf));

            if (json_fmt) {
                unixctl_command_reply(fd, json_first_obj ? "{" : ",{");
                json_first_obj = 0;
                unixctl_command_reply(fd, JSON_KV_S_FMT("ip", ","), buf);
                unixctl_command_reply(fd, JSON_KV_32_FMT("port", ","),
                                      rte_be_to_cpu_16(vs->vport));
                unixctl_command_reply(fd, JSON_KV_S_FMT("type", ","),
                                      l4proto_format(vs->proto));
                unixctl_command_reply(fd, JSON_KV_S_FMT("sched", ","),
                                      vs->sched->name);
                unixctl_command_reply(fd, JSON_KV_32_FMT("max_conns", "}"),
                                      vs->max_conns);
            } else {
                unixctl_command_reply(fd, "%-15s  %-5u  %-5s  %-10s  %d\n", buf,
                                      rte_be_to_cpu_16(vs->vport),
                                      l4proto_format(vs->proto),
                                      vs->sched->name, vs->max_conns);
            }
        }
        if (json_fmt)
            unixctl_command_reply(fd, "]\n");

        break;
    }
}
UNIXCTL_CMD_REGISTER("vs/list", "[--json].", "List all virtual services.", 0, 1,
                     vs_list_cmd_cb);

static int
vs_synproxy_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                      uint8_t *proto, uint8_t *echo, uint8_t *op) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0 || *proto != IPPROTO_TCP)
        return i - 1;

    if (i < argc) {
        *echo = 0;
        rc = parser_read_uint8(op, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
vs_synproxy_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint8_t echo = 0;
    uint8_t op;
    int rc;
    struct lb_virt_service *vs;
    uint32_t socket_id;

    rc = vs_synproxy_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%u\n", !!(vs->flags & LB_VS_F_SYNPROXY));
            return;
        }

        if (op) {
            vs->flags |= LB_VS_F_SYNPROXY;
        } else {
            vs->flags &= ~LB_VS_F_SYNPROXY;
        }
    }

    return;
}

UNIXCTL_CMD_REGISTER("vs/synproxy", "VIP:VPORT tcp [0|1].",
                     "Show or set synproxy.", 2, 3, vs_synproxy_cmd_cb);

static int
vs_toa_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                 uint8_t *proto, uint8_t *echo, uint8_t *op) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0 || *proto != IPPROTO_TCP)
        return i - 1;

    if (i < argc) {
        *echo = 0;
        rc = parser_read_uint8(op, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
vs_toa_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint8_t echo = 0;
    uint8_t op;
    int rc;
    struct lb_virt_service *vs;
    uint32_t socket_id;

    rc = vs_toa_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%u\n", !!(vs->flags & LB_VS_F_TOA));
            return;
        }

        if (op) {
            vs->flags |= LB_VS_F_TOA;
        } else {
            vs->flags &= ~LB_VS_F_TOA;
        }
    }

    return;
}

UNIXCTL_CMD_REGISTER("vs/toa", "VIP:VPORT tcp [0|1].", "Show or set toa.", 2, 3,
                     vs_toa_cmd_cb);

static int
vs_max_conn_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                      uint8_t *proto, uint8_t *echo, int *max) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0)
        return i - 1;

    if (i < argc) {
        *echo = 0;
        rc = parser_read_int32(max, argv[i++]);
        if (rc < 0 || *max < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
vs_max_conn_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint8_t echo = 0;
    int max;
    int rc;
    struct lb_virt_service *vs;
    uint32_t socket_id;

    rc = vs_max_conn_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &max);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%d\n", vs->max_conns);
            return;
        }

        vs->max_conns = max;
    }

    return;
}

UNIXCTL_CMD_REGISTER("vs/max_conns", "VIP:VPORT tcp [0|1].",
                     "Show or set max_conns.", 2, 3, vs_max_conn_cmd_cb);

static int
vs_est_timeout_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                         uint8_t *proto, uint8_t *echo, uint32_t *timeout) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0)
        return i - 1;

    if (i < argc) {
        *echo = 0;
        rc = parser_read_uint32(timeout, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
vs_est_timeout_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint8_t echo = 0;
    uint32_t timeout;
    int rc;
    struct lb_virt_service *vs;
    uint32_t socket_id;

    rc = vs_est_timeout_arg_parse(argv, argc, &vip, &vport, &proto, &echo,
                                  &timeout);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%u\n", LB_CLOCK_TO_SEC(vs->est_timeout));
            return;
        }
        vs->est_timeout = SEC_TO_LB_CLOCK(timeout);
    }
}

UNIXCTL_CMD_REGISTER("vs/est_timeout", "VIP:VPORT tcp|udp [SEC].",
                     "Show or set TCP established timeout.", 2, 3,
                     vs_est_timeout_cmd_cb);

static int
vs_scheduler_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                       uint8_t *proto, uint8_t *echo,
                       const struct lb_scheduler **sched) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0)
        return i - 1;

    if (i < argc) {
        *echo = 0;
        rc = lb_scheduler_lookup_by_name(argv[i++], sched);
        if (rc < 0) {
            return i - 1;
        }
    } else {
        *echo = 1;
    }

    return i;
}

static void
vs_scheduler_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint8_t echo = 0;
    const struct lb_scheduler *sched;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;
    uint32_t socket_id;

    rc =
        vs_scheduler_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &sched);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%s\n", vs->sched->name);
            return;
        }

        if (sched == vs->sched)
            break;

        LB_VS_WLOCK(vs);
        LIST_FOREACH(rs, &vs->real_services, next) {
            if (rs->flags & LB_RS_F_AVAILABLE)
                vs->sched->del(vs, rs);
        }
        if (vs->sched->fini)
            vs->sched->fini(vs);

        vs->sched = sched;
        if (vs->sched->init && vs->sched->init(vs) < 0) {
            LIST_FOREACH(rs, &vs->real_services, next) {
                rs->flags &= ~LB_RS_F_AVAILABLE;
            }
            LB_VS_WUNLOCK(vs);
            unixctl_command_reply_error(fd, "Cannot init scheduler %s.\n",
                                        sched->name);
            return;
        }

        LIST_FOREACH(rs, &vs->real_services, next) {
            if ((rs->flags & LB_RS_F_AVAILABLE) && vs->sched->add(vs, rs) < 0) {
                rs->flags &= ~LB_RS_F_AVAILABLE;
            }
        }
        LB_VS_WUNLOCK(vs);
    }
}

UNIXCTL_CMD_REGISTER("vs/scheduler",
                     "VIP:VPORT tcp|udp [iponly|ipport|rr|wrr].",
                     "Show or set scheduler.", 2, 3, vs_scheduler_cmd_cb);

static int
vs_stats_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                   uint8_t *proto, int *json_fmt) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0)
        return i - 1;

    if (i < argc) {
        *json_fmt = 1;
        rc = strcmp(argv[i++], "--json");
        if (rc != 0)
            return i - 1;
    } else {
        *json_fmt = 0;
    }

    return i;
}

static void
vs_stats_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    int json_fmt = 0;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;
    uint32_t socket_id, lcore_id;
    uint64_t rx_packets[2] = {0}, rx_bytes[2] = {0}, rx_drops[2] = {0};
    uint64_t tx_packets[2] = {0}, tx_bytes[2] = {0};
    uint64_t active_conns = 0, history_conns = 0, max_conns = 0;

    rc = vs_stats_arg_parse(argv, argc, &vip, &vport, &proto, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }

        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            rx_packets[0] += vs->stats[lcore_id].packets[0];
            rx_packets[1] += vs->stats[lcore_id].packets[1];
            rx_bytes[0] += vs->stats[lcore_id].bytes[0];
            rx_bytes[1] += vs->stats[lcore_id].bytes[1];
            rx_drops[0] += vs->stats[lcore_id].drops[0];
            rx_drops[1] += vs->stats[lcore_id].drops[1];
            history_conns += vs->stats[lcore_id].conns;
        }
        active_conns += (uint64_t)rte_atomic32_read(&vs->active_conns);
        LIST_FOREACH(rs, &vs->real_services, next) {
            RTE_LCORE_FOREACH_SLAVE(lcore_id) {
                tx_packets[0] += rs->stats[lcore_id].packets[0];
                tx_packets[1] += rs->stats[lcore_id].packets[1];
                tx_bytes[0] += rs->stats[lcore_id].bytes[0];
                tx_bytes[1] += rs->stats[lcore_id].bytes[1];
            }
        }

        max_conns = vs->max_conns;
    }

    if (json_fmt)
        unixctl_command_reply(fd, "{");

    /* Just make it easy for agent to collect data. */
    if (json_fmt)
        unixctl_command_reply(fd, JSON_KV_64_FMT("max-conns", ","), max_conns);

    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("active-conns", ",")
                                   : NORM_KV_64_FMT("active-conns", "\n"),
                          active_conns);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("history-conns", ",")
                                   : NORM_KV_64_FMT("history-conns", "\n"),
                          history_conns);

    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[c2v]packets", ",")
                                   : NORM_KV_64_FMT("[c2v]packets", "\n"),
                          rx_packets[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[c2v]bytes", ",")
                                   : NORM_KV_64_FMT("[c2v]bytes", "\n"),
                          rx_bytes[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[c2v]drops", ",")
                                   : NORM_KV_64_FMT("[c2v]drops", "\n"),
                          rx_drops[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[r2v]packets", ",")
                                   : NORM_KV_64_FMT("[r2v]packets", "\n"),
                          rx_packets[1]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[r2v]bytes", ",")
                                   : NORM_KV_64_FMT("[r2v]bytes", "\n"),
                          rx_bytes[1]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[r2v]drops", "")
                                   : NORM_KV_64_FMT("[r2v]drops", "\n"),
                          rx_drops[1]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[v2r]packets", ",")
                                   : NORM_KV_64_FMT("[v2r]packets", "\n"),
                          tx_packets[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[v2r]bytes", ",")
                                   : NORM_KV_64_FMT("[v2r]bytes", "\n"),
                          tx_bytes[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[v2c]packets", ",")
                                   : NORM_KV_64_FMT("[v2c]packets", "\n"),
                          tx_packets[1]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_64_FMT("[v2c]bytes", "")
                                   : NORM_KV_64_FMT("[v2c]bytes", "\n"),
                          tx_bytes[1]);

    if (json_fmt)
        unixctl_command_reply(fd, "}\n");
}

UNIXCTL_CMD_REGISTER("vs/stats", "VIP:VPORT tcp|udp [--json].",
                     "Show packet statistics of virtual service.", 2, 3,
                     vs_stats_cmd_cb);

static int
rs_add_arg_parse(char *argv[], __attribute((unused)) int argc, uint32_t *vip,
                 uint16_t *vport, uint8_t *proto, uint32_t *rip,
                 uint16_t *rport, int *weight) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    rc = parse_ipv4_port(argv[i++], rip, rport);
    if (rc < 0) {
        return i - 1;
    }

    if (i < argc) {
        rc = parser_read_uint16((uint16_t *)weight, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *weight = 0;
    }

    return i;
}

static void
rs_add_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint32_t rip;
    uint16_t rport;
    int weight;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vss[RTE_MAX_NUMA_NODES] = {0};
    struct lb_real_service *rss[RTE_MAX_NUMA_NODES] = {0};

    rc = rs_add_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                          &weight);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vss[socket_id] = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        if (vs_find_rs(vss[socket_id], rip, rport) != NULL) {
            unixctl_command_reply_error(fd, "Real service is exist.\n");
            return;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        rss[socket_id] = lb_rs_alloc(rip, rport, weight, vss[socket_id]);
        if (rss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Not enough memory.\n");
            goto free_rss;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        LB_VS_WLOCK(vss[socket_id]);
        lb_rs_list_insert_by_weight(vss[socket_id], rss[socket_id]);
        rss[socket_id]->flags |= LB_RS_F_AVAILABLE;
        rc = vss[socket_id]->sched->add(vss[socket_id], rss[socket_id]);
        if (rc < 0) {
            rss[socket_id]->flags &= ~LB_RS_F_AVAILABLE;
            LIST_REMOVE(rss[socket_id], next);
            LB_VS_WUNLOCK(vss[socket_id]);
            unixctl_command_reply_error(fd, "Not enough memory.\n");
            goto del_sched;
        }
        LB_VS_WUNLOCK(vss[socket_id]);
    }

    return;

del_sched:
    VS_TBL_FOREACH_SOCKET(socket_id) {
        LB_VS_WLOCK(vss[socket_id]);
        if (rss[socket_id]->flags & LB_RS_F_AVAILABLE) {
            vss[socket_id]->sched->del(vss[socket_id], rss[socket_id]);
            LIST_REMOVE(rss[socket_id], next);
        }
        LB_VS_WUNLOCK(vss[socket_id]);
    }

free_rss:
    VS_TBL_FOREACH_SOCKET(socket_id) { lb_rs_free(rss[socket_id]); }
}

UNIXCTL_CMD_REGISTER("rs/add", "VIP:VPORT tcp|udp RIP:RPORT [WEIGHT].",
                     "Add real service.", 3, 4, rs_add_cmd_cb);

static int
rs_del_arg_parse(char *argv[], __attribute((unused)) int argc, uint32_t *vip,
                 uint16_t *vport, uint8_t *proto, uint32_t *rip,
                 uint16_t *rport) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    rc = parse_ipv4_port(argv[i++], rip, rport);
    if (rc < 0) {
        return i - 1;
    }

    return i;
}

static void
rs_del_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint32_t rip;
    uint16_t rport;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vss[RTE_MAX_NUMA_NODES] = {0};
    struct lb_real_service *rs;

    rc = rs_del_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vss[socket_id] = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        rs = vs_find_rs(vss[socket_id], rip, rport);
        if (rs == NULL)
            continue;

        LB_VS_WLOCK(vss[socket_id]);
        if (rs->flags & LB_RS_F_AVAILABLE) {
            rs->flags &= ~LB_RS_F_AVAILABLE;
            vss[socket_id]->sched->del(vss[socket_id], rs);
        }
        LIST_REMOVE(rs, next);
        LB_VS_WUNLOCK(vss[socket_id]);

        lb_rs_free(rs);
    }
}

UNIXCTL_CMD_REGISTER("rs/del", "VIP:VPORT tcp|udp RIP:RPORT.",
                     "Del real service.", 3, 3, rs_del_cmd_cb);

static int
rs_list_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                  uint8_t *proto, int *json_fmt) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0)
        return i - 1;

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0)
        return i - 1;

    if (i < argc) {
        *json_fmt = 1;
        rc = strcmp(argv[i++], "--json");
        if (rc != 0)
            return i - 1;
    } else {
        *json_fmt = 0;
    }

    return i;
}

static void
rs_list_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    int json_fmt = 0, json_first_obj = 1;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vs = NULL;
    struct lb_real_service *rs;
    char buf[32];

    rc = rs_list_arg_parse(argv, argc, &vip, &vport, &proto, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
        if (json_fmt)
            unixctl_command_reply(fd, "[");
        else
            unixctl_command_reply(
                fd, "IP              Port   Type  Status  Weight\n");
        LIST_FOREACH(rs, &vs->real_services, next) {
            ipv4_addr_tostring(rs->rip, buf, sizeof(buf));
            if (json_fmt) {
                unixctl_command_reply(fd, json_first_obj ? "{" : ",{");
                json_first_obj = 0;
                unixctl_command_reply(fd, JSON_KV_S_FMT("ip", ","), buf);
                unixctl_command_reply(fd, JSON_KV_32_FMT("port", ","),
                                      rte_be_to_cpu_16(rs->rport));
                unixctl_command_reply(fd, JSON_KV_S_FMT("type", ","),
                                      l4proto_format(rs->proto));
                unixctl_command_reply(fd, JSON_KV_S_FMT("status", ","),
                                      rs->flags & LB_RS_F_AVAILABLE ? "up"
                                                                    : "down");
                unixctl_command_reply(fd, JSON_KV_32_FMT("weight", "}"),
                                      (uint32_t)rs->weight);
            } else {
                unixctl_command_reply(
                    fd, "%-15s  %-5u  %-4s  %-6s  %-10d\n", buf,
                    rte_be_to_cpu_16(rs->rport), l4proto_format(rs->proto),
                    rs->flags & LB_RS_F_AVAILABLE ? "up" : "down", rs->weight);
            }
        }
        if (json_fmt)
            unixctl_command_reply(fd, "]\n");

        break;
    }
}

UNIXCTL_CMD_REGISTER("rs/list", "VIP:VPORT tcp|udp [--json].",
                     "List all real services.", 2, 3, rs_list_cmd_cb);

static int
rs_status_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                    uint8_t *proto, uint32_t *rip, uint16_t *rport,
                    uint8_t *echo, uint8_t *op) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    rc = parse_ipv4_port(argv[i++], rip, rport);
    if (rc < 0) {
        return i - 1;
    }

    if (i < argc) {
        *echo = 0;
        rc = parser_read_uint8(op, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
rs_status_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip, rip;
    uint16_t vport, rport;
    uint8_t proto;
    uint8_t echo = 0;
    uint8_t op;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vss[RTE_MAX_NUMA_NODES] = {0};
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = rs_status_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                             &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vss[socket_id] = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vss[socket_id];
        rs = vs_find_rs(vs, rip, rport);
        if (rs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find real service.\n");
            return;
        }

        if (echo) {
            unixctl_command_reply(fd, "%u\n", rs->flags & LB_RS_F_AVAILABLE);
            return;
        }

        if (rs->flags & LB_RS_F_AVAILABLE && !op) {
            LB_VS_WLOCK(vs);
            rs->flags &= ~LB_RS_F_AVAILABLE;
            vs->sched->del(vs, rs);
            LB_VS_WUNLOCK(vs);
        } else if (!(rs->flags & LB_RS_F_AVAILABLE) && op) {
            LB_VS_WLOCK(vs);
            rs->flags |= LB_RS_F_AVAILABLE;
            if (vs->sched->add(vs, rs) < 0) {
                rs->flags &= ~LB_RS_F_AVAILABLE;
                LB_VS_WUNLOCK(vs);
                goto failed;
            }
            LB_VS_WUNLOCK(vs);
        }
    }
    return;

failed:
    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vss[socket_id];
        if (rs->flags & LB_RS_F_AVAILABLE) {
            LB_VS_WLOCK(vs);
            rs->flags &= ~LB_RS_F_AVAILABLE;
            vs->sched->del(vs, rs);
            LB_VS_WUNLOCK(vs);
        }
    }
}

UNIXCTL_CMD_REGISTER("rs/status", "VIP:VPORT tcp|udp RIP:RPORT [0|1].",
                     "Show or set the status of real services.", 3, 4,
                     rs_status_cmd_cb);

static int
rs_weight_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                    uint8_t *proto, uint32_t *rip, uint16_t *rport,
                    uint8_t *echo, int *weight) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    rc = parse_ipv4_port(argv[i++], rip, rport);
    if (rc < 0) {
        return i - 1;
    }

    if (i < argc) {
        *echo = 0;
        rc = parser_read_uint16((uint16_t *)weight, argv[i++]);
        if (rc < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
rs_weight_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip, rip;
    uint16_t vport, rport;
    uint8_t proto;
    uint8_t echo = 0;
    int weight;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vss[RTE_MAX_NUMA_NODES] = {0};
    struct lb_real_service *rs;

    rc = rs_weight_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                             &echo, &weight);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vss[socket_id] = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vss[socket_id] == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        rs = vs_find_rs(vss[socket_id], rip, rport);
        if (rs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find real service.\n");
            return;
        }
        if (echo) {
            unixctl_command_reply(fd, "%d\n", rs->weight);
            return;
        }

        LB_VS_WLOCK(vss[socket_id]);
        rs->weight = weight;
        lb_rs_list_update_by_weight(vss[socket_id], rs);
        vss[socket_id]->sched->update(vss[socket_id], rs);
        LB_VS_WUNLOCK(vss[socket_id]);
    }
}

UNIXCTL_CMD_REGISTER("rs/weight", "VIP:VPORT tcp|udp RIP:RPORT [WEIGHT].",
                     "Show or set the weight of real services.", 3, 4,
                     rs_weight_cmd_cb);

static int
rs_stats_arg_parse(char *argv[], int argc, uint32_t *vip, uint16_t *vport,
                   uint8_t *proto, uint32_t *rip, uint16_t *rport,
                   int *json_fmt) {
    int rc;
    int i = 0;

    /* ip:port */
    rc = parse_ipv4_port(argv[i++], vip, vport);
    if (rc < 0) {
        return i - 1;
    }

    /*  proto */
    rc = parse_l4_proto(argv[i++], proto);
    if (rc < 0) {
        return i - 1;
    }

    rc = parse_ipv4_port(argv[i++], rip, rport);
    if (rc < 0) {
        return i - 1;
    }

    if (i < argc) {
        *json_fmt = 1;
        rc = strcmp(argv[i++], "--json");
        if (rc != 0)
            return i - 1;
    } else {
        *json_fmt = 0;
    }

    return i;
}

static void
rs_stats_cmd_cb(int fd, char *argv[], int argc) {
    uint32_t vip;
    uint16_t vport;
    uint8_t proto;
    uint32_t rip;
    uint16_t rport;
    int json_fmt = 0;
    int rc;
    uint32_t socket_id;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;
    uint32_t lcore_id;
    uint64_t packets[2] = {0}, bytes[2] = {0};
    uint64_t active_conns = 0, history_conns = 0;

    rc = rs_stats_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                            &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    VS_TBL_FOREACH_SOCKET(socket_id) {
        vs = vs_tbl_find(lb_vs_tbls[socket_id], vip, vport, proto);
        if (vs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find virt service.\n");
            return;
        }

        rs = vs_find_rs(vs, rip, rport);
        if (rs == NULL) {
            unixctl_command_reply_error(fd, "Cannot find real service.\n");
            return;
        }

        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            packets[0] += rs->stats[lcore_id].packets[0];
            packets[1] += rs->stats[lcore_id].packets[1];
            bytes[0] += rs->stats[lcore_id].bytes[0];
            bytes[1] += rs->stats[lcore_id].bytes[1];
            history_conns += rs->stats[lcore_id].conns;
            active_conns += (uint64_t)rte_atomic32_read(&rs->active_conns);
        }
    }

    if (json_fmt)
        unixctl_command_reply(fd, "{");
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("active-conns", ",")
                                   : NORM_KV_32_FMT("active-conns", "\n"),
                          active_conns);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("history-conns", ",")
                                   : NORM_KV_32_FMT("history-conns", "\n"),
                          history_conns);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("[v2r]packets", ",")
                                   : NORM_KV_32_FMT("[v2r]packets", "\n"),
                          packets[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("[v2r]bytes", ",")
                                   : NORM_KV_32_FMT("[v2r]bytes", "\n"),
                          bytes[0]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("[r2v]packets", ",")
                                   : NORM_KV_32_FMT("[r2v]packets", "\n"),
                          packets[1]);
    unixctl_command_reply(fd,
                          json_fmt ? JSON_KV_32_FMT("[r2v]bytes", "")
                                   : NORM_KV_32_FMT("[r2v]bytes", "\n"),
                          bytes[1]);
    if (json_fmt)
        unixctl_command_reply(fd, "}\n");
}

UNIXCTL_CMD_REGISTER("rs/stats", "VIP:VPORT tcp|udp RIP:RPORT.",
                     "Show the packet stats of real services.", 3, 4,
                     rs_stats_cmd_cb);
