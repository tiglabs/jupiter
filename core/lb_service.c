/* Copyright (c) 2018. TIG developer. */

#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>

#include <cjson.h>
#include <unixctl_command.h>

#include "lb.h"
#include "lb_device.h"
#include "lb_ip_address.h"
#include "lb_parser.h"
#include "lb_service.h"

#define LB_MAX_VS (64 << 10)

typedef struct {
    uint64_t as_u64[3];
} hash_key_24_t;

struct lb_service_main {
    struct rte_hash *vs_hash;
    rte_rwlock_t rwlock;
};

static struct lb_service_main lb_sm;

static inline void
make_hash_key_24(hash_key_24_t *k, ip46_address_t *ip46, uint16_t port,
                 lb_proto_t proto) {
    k->as_u64[0] = ip46->as_u64[0];
    k->as_u64[1] = ip46->as_u64[1];
    k->as_u64[2] = (uint64_t)proto << 32 | (uint64_t)port;
}

int
lb_service_module_init(void) {
    struct lb_service_main *m = &lb_sm;
    struct rte_hash_parameters param;

    rte_rwlock_init(&m->rwlock);

    memset(&param, 0, sizeof(param));
    param.name = "VS_HASH";
    param.entries = LB_MAX_VS;
    param.key_len = sizeof(hash_key_24_t);
    param.socket_id = SOCKET_ID_ANY;
    param.hash_func = rte_hash_crc;
    if (!(m->vs_hash = rte_hash_create(&param))) {
        log_err("%s(): Create vs hash table failed, %s\n", __func__,
                rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

static struct lb_virt_service *
lb_vs_create(ip46_address_t *vaddr, uint16_t vport, lb_proto_t proto,
             const char *sched_name) {
    struct lb_virt_service *vs;

    if (!(vs = rte_malloc(NULL, sizeof(struct lb_virt_service), 0))) {
        log_warning("Get vs from mempool failed: %s.", rte_strerror(rte_errno));
        return NULL;
    }
    if (lb_scheduler_init(&vs->sched, sched_name) < 0) {
        rte_free(vs);
        return NULL;
    }
    ip46_address_copy(&vs->vaddr, vaddr);
    vs->vport = vport;
    vs->proto = proto;
    vs->flags = 0;
    rte_atomic32_set(&vs->refcnt, 1);
    rte_atomic32_set(&vs->active_conns, 0);
    rte_rwlock_init(&vs->rwlock);
    LIST_INIT(&vs->real_services);
    vs->est_timeout = 0;
    vs->max_conns = INT32_MAX;
    return vs;
}

static void
lb_sched_node_init(struct lb_sched_node *node, ip46_address_t *raddr,
                   uint16_t rport, int weight) {
    char ident[LB_SCHED_NODE_IDEN_MAX];

    node->weight = weight;
    if (ip46_address_is_ip4(raddr))
        snprintf(ident, LB_SCHED_NODE_IDEN_MAX, IPv4_BYTES_FMT "%d",
                 IPv4_BYTES(raddr->ip4.as_u32), rport);
    else
        snprintf(ident, LB_SCHED_NODE_IDEN_MAX, IPv6_BYTES_FMT "%d",
                 IPv6_BYTES(raddr->ip6.as_u8), rport);
    strncpy(node->ident, ident, LB_SCHED_NODE_IDEN_MAX);
}

static struct lb_real_service *
lb_rs_create(ip46_address_t *raddr, uint16_t rport, int weight,
             struct lb_virt_service *vs) {
    struct lb_real_service *rs;

    if (!(rs = rte_malloc(NULL, sizeof(struct lb_real_service), 0))) {
        log_warning("alloc real service failed: %s.", rte_strerror(rte_errno));
        return NULL;
    }
    lb_sched_node_init(&rs->sched_node, raddr, rport, weight);
    ip46_address_copy(&rs->raddr, raddr);
    rs->rport = rport;
    rs->virt_service = vs;
    rs->flags = 0;
    rte_atomic32_set(&vs->refcnt, 1);
    rte_atomic32_set(&vs->active_conns, 0);
    return rs;
}

static inline struct lb_virt_service *
lb_vs_table_lookup_inline(ip46_address_t *vaddr, uint16_t vport,
                          lb_proto_t proto) {
    struct lb_service_main *m = &lb_sm;
    hash_key_24_t _k, *k = &_k;
    struct lb_virt_service *vs;

    make_hash_key_24(k, vaddr, vport, proto);
    if (rte_hash_lookup_data(m->vs_hash, k, (void **)&vs) < 0)
        return NULL;
    return vs;
}

static inline int
lb_vs_table_add_inline(struct lb_virt_service *vs) {
    struct lb_service_main *m = &lb_sm;
    hash_key_24_t _k, *k = &_k;

    make_hash_key_24(k, &vs->vaddr, vs->vport, vs->proto);
    rte_rwlock_write_lock(&m->rwlock);
    if (rte_hash_add_key_data(m->vs_hash, k, vs) < 0) {
        rte_rwlock_write_unlock(&m->rwlock);
        return -1;
    }
    rte_rwlock_write_unlock(&m->rwlock);
    return 0;
}

static inline void
lb_vs_table_del_inline(struct lb_virt_service *vs) {
    struct lb_service_main *m = &lb_sm;
    hash_key_24_t _k, *k = &_k;

    make_hash_key_24(k, &vs->vaddr, vs->vport, vs->proto);
    rte_rwlock_write_lock(&m->rwlock);
    rte_hash_del_key(m->vs_hash, k);
    rte_rwlock_write_unlock(&m->rwlock);
}

struct lb_virt_service *
lb_vs_get(void *ip, uint16_t vport, lb_proto_t proto, uint8_t is_ip4) {
    ip46_address_t ip46;
    hash_key_24_t _k, *k = &_k;
    struct lb_service_main *m = &lb_sm;
    struct lb_virt_service *vs;

    if (is_ip4)
        ip46_address_set_ip4(&ip46, (ip4_address_t *)ip);
    else
        ip46_address_set_ip6(&ip46, (ip6_address_t *)ip);
    make_hash_key_24(k, &ip46, vport, proto);

    rte_rwlock_read_lock(&m->rwlock);
    if (rte_hash_lookup_data(m->vs_hash, k, (void **)&vs) < 0) {
        rte_rwlock_read_unlock(&m->rwlock);
        return NULL;
    }
    if (rte_atomic32_read(&vs->active_conns) >= vs->max_conns) {
        rte_rwlock_read_unlock(&m->rwlock);
        return NULL;
    }
    rte_atomic32_inc(&vs->refcnt);
    rte_rwlock_read_unlock(&m->rwlock);
    return vs;
}

void
lb_vs_put(struct lb_virt_service *vs) {
    if (vs && rte_atomic32_add_return(&vs->refcnt, -1) == 0) {
        lb_scheduler_uninit(&vs->sched);
        rte_free(vs);
    }
}

static inline struct lb_real_service *
lb_rs_table_lookup_inline(struct lb_virt_service *vs, ip46_address_t *raddr,
                          uint16_t rport) {
    struct lb_real_service *rs;

    LIST_FOREACH(rs, &vs->real_services, next) {
        if ((rs->rport == rport) && (ip46_address_cmp(&rs->raddr, raddr) == 0))
            return rs;
    }
    return NULL;
}

static inline void
lb_rs_table_del_inline(struct lb_virt_service *vs, struct lb_real_service *rs) {
    (void)vs;
    LIST_REMOVE(rs, next);
}

static inline void
lb_rs_table_add_inline(struct lb_virt_service *vs, struct lb_real_service *rs) {
    LIST_INSERT_HEAD(&vs->real_services, rs, next);
}

struct lb_real_service *
lb_vs_get_rs(struct lb_virt_service *vs, void *caddr, uint16_t cport,
             uint8_t is_ip4) {
    struct lb_sched_node *node;

    rte_rwlock_read_lock(&vs->rwlock);
    node = lb_scheduler_dispatch(&vs->sched, caddr, cport, is_ip4);
    if (!node) {
        rte_rwlock_read_unlock(&vs->rwlock);
        return NULL;
    }
    rte_rwlock_read_unlock(&vs->rwlock);
    return (struct lb_real_service *)node;
}

void
lb_rs_put(struct lb_real_service *rs) {
    if (rs && rte_atomic32_add_return(&rs->refcnt, -1) == 0) {
        lb_vs_put(rs->virt_service);
        rte_free(rs);
    }
}

static int
lb_rs_sched_enable(struct lb_real_service *rs, uint8_t is_enable) {
    struct lb_virt_service *vs = rs->virt_service;

    if (is_enable) {
        if (rs->flags & LB_RS_F_AVAILABLE)
            return 0;
        rte_rwlock_write_lock(&vs->rwlock);
        if (lb_scheduler_add_node(&vs->sched, &rs->sched_node) < 0) {
            rte_rwlock_write_unlock(&vs->rwlock);
            return -1;
        }
        rs->flags |= LB_RS_F_AVAILABLE;
        rte_rwlock_write_unlock(&vs->rwlock);
    } else {
        if (!(rs->flags & LB_RS_F_AVAILABLE))
            return 0;
        rte_rwlock_write_lock(&vs->rwlock);
        if (lb_scheduler_del_node(&vs->sched, &rs->sched_node) < 0) {
            rte_rwlock_write_unlock(&vs->rwlock);
            return -1;
        }
        rs->flags &= ~LB_RS_F_AVAILABLE;
        rte_rwlock_write_unlock(&vs->rwlock);
    }
    return 0;
}

static void
lb_rs_update_weight(struct lb_real_service *rs, int weight) {
    struct lb_virt_service *vs = rs->virt_service;

    if (!(rs->flags & LB_RS_F_AVAILABLE)) {
        rs->sched_node.weight = weight;
    } else {
        rte_rwlock_write_lock(&vs->rwlock);
        rs->sched_node.weight = weight;
        lb_scheduler_del_node(&vs->sched, &rs->sched_node);
        if (lb_scheduler_add_node(&vs->sched, &rs->sched_node) < 0) {
            rs->flags &= ~LB_RS_F_AVAILABLE;
        }
        rte_rwlock_write_unlock(&vs->rwlock);
    }
}

static int
lb_vs_update_sched(struct lb_virt_service *vs, const char *new_sched_name) {
    char old_sched_name[LB_SCHED_NAMESIZE];
    struct lb_real_service *rs;

    strcpy(old_sched_name, vs->sched.name);
    if (strcmp(old_sched_name, new_sched_name) == 0)
        return 0;
    rte_rwlock_write_lock(&vs->rwlock);
    LIST_FOREACH(rs, &vs->real_services, next) {
        if (rs->flags & LB_RS_F_AVAILABLE)
            lb_scheduler_del_node(&vs->sched, &rs->sched_node);
    }
    lb_scheduler_uninit(&vs->sched);
    if (lb_scheduler_init(&vs->sched, new_sched_name) < 0) {
        goto recovery;
    }
    LIST_FOREACH(rs, &vs->real_services, next) {
        if ((rs->flags & LB_RS_F_AVAILABLE) &&
            lb_scheduler_add_node(&vs->sched, &rs->sched_node) < 0) {
            rs->flags &= ~LB_RS_F_AVAILABLE;
        }
    }
    rte_rwlock_write_unlock(&vs->rwlock);
    return 0;

recovery:
    if (lb_scheduler_init(&vs->sched, old_sched_name) < 0) {
        LIST_FOREACH(rs, &vs->real_services, next) {
            rs->flags &= ~LB_RS_F_AVAILABLE;
        }
        rte_rwlock_write_unlock(&vs->rwlock);
        return -1;
    }
    LIST_FOREACH(rs, &vs->real_services, next) {
        if ((rs->flags & LB_RS_F_AVAILABLE) &&
            lb_scheduler_add_node(&vs->sched, &rs->sched_node) < 0) {
            rs->flags &= ~LB_RS_F_AVAILABLE;
        }
    }
    rte_rwlock_write_unlock(&vs->rwlock);
    return 0;
}

/* unixctl commands */

static inline int
parse_l4_proto(const char *token, lb_proto_t *proto) {
    if (strcasecmp(token, "tcp") == 0) {
        *proto = LB_PROTO_TCP;
        return 0;
    }
    if (strcasecmp(token, "udp") == 0) {
        *proto = LB_PROTO_UDP;
        return 0;
    }
    *proto = LB_PROTO_MAX;
    return -1;
}

static int
parse_ip46_address(const char *token, ip46_address_t *ip46) {
    struct in_addr in;
    struct in6_addr in6;

    if (parse_ipv4_addr(token, &in) == 0) {
        ip46_address_set_ip4(ip46, (ip4_address_t *)&in);
        return 0;
    }
    if (parse_ipv6_addr(token, &in6) == 0) {
        ip46_address_set_ip6(ip46, (ip6_address_t *)&in6);
        return 0;
    }
    return -1;
}

static int
parse_l4_port(const char *token, uint16_t *port) {
    if (parser_read_uint16(port, token) < 0) {
        return -1;
    }
    *port = htons(*port);
    return 0;
}

static int
parse_sched_name(const char *token, char sched_name[]) {
    if ((strcasecmp(token, "ipport") == 0) ||
        (strcasecmp(token, "iponly") == 0) || (strcasecmp(token, "rr") == 0) ||
        (strcasecmp(token, "wrr") == 0)) {
        snprintf(sched_name, LB_SCHED_NAMESIZE, "%s", token);
        return 0;
    }
    return -1;
}

static int
vs_add_arg_parse(char *argv[], __attribute((unused)) int argc,
                 ip46_address_t *vip, uint16_t *vport, lb_proto_t *proto,
                 char sched_name[]) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_sched_name(argv[i++], sched_name) < 0) {
        return i - 1;
    }
    return i;
}

static void
vs_add_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vaddr;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    char sched_name[LB_SCHED_NAMESIZE];
    struct lb_virt_service *vs;
    int rc;

    rc = vs_add_arg_parse(argv, argc, &vaddr, &vport, &proto, sched_name);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (lb_vs_table_lookup_inline(&vaddr, vport, proto)) {
        unixctl_command_reply_error(fd, "virt service is exised.");
        return;
    }
    if (!(vs = lb_vs_create(&vaddr, vport, proto, sched_name))) {
        unixctl_command_reply_error(fd, "Cannot create virt service.");
        return;
    }
    if (lb_vs_table_add_inline(vs) < 0) {
        lb_vs_put(vs);
        unixctl_command_reply_error(
            fd, "Insert virt service to hash table failed.");
        return;
    }
    if (lb_device_add_vip_lip(lb_device_get_outbound(), &vaddr) < 0) {
        lb_vs_table_del_inline(vs);
        lb_vs_put(vs);
        unixctl_command_reply_error(fd, "Insert vip to hash table failed.");
    }
}

UNIXCTL_CMD_REGISTER("vs/add", "VIP VPORT tcp|udp ipport|iponly|rr|wrr.",
                     "Add virtual service.", 4, 4, vs_add_cmd_cb);

static int
vs_del_arg_parse(char *argv[], __attribute((unused)) int argc,
                 ip46_address_t *vip, uint16_t *vport, lb_proto_t *proto) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    return i;
}

static void
vs_del_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = vs_del_arg_parse(argv, argc, &vip, &vport, &proto);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.");
        return;
    }
    while ((rs = LIST_FIRST(&vs->real_services)) != NULL) {
        LIST_REMOVE(rs, next);
        lb_rs_sched_enable(rs, 0);
        lb_rs_put(rs);
    }
    lb_vs_table_del_inline(vs);
    lb_vs_put(vs);
    lb_device_del_vip_lip(lb_device_get_inbound(), &vip);
}

UNIXCTL_CMD_REGISTER("vs/del", "VIP VPORT tcp|udp.", "Delete virtual service.",
                     3, 3, vs_del_cmd_cb);

static int
vs_list_arg_parse(char *argv[], int argc, int *json_fmt) {
    int i = 0;

    if (i == argc) {
        *json_fmt = 0;
        return i;
    }
    if (strcmp(argv[i++], "--json") == 0) {
        *json_fmt = 1;
        return i;
    } else {
        return i - 1;
    }
}

static inline const char *
l4proto_format(lb_proto_t proto) {
    if (proto == LB_PROTO_TCP)
        return "tcp";
    if (proto == LB_PROTO_UDP)
        return "udp";
    return "oth";
}

static void
vs_list_cmd_cb(int fd, char *argv[], int argc) {
    struct lb_service_main *m = &lb_sm;
    int json_fmt;
    int rc;
    const void *key;
    uint32_t next = 0;
    struct lb_virt_service *vs;
    char buf[INET6_ADDRSTRLEN];

    rc = vs_list_arg_parse(argv, argc, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (json_fmt) {
        cJSON *array = cJSON_CreateArray();
        if (!array)
            return;
        while (rte_hash_iterate(m->vs_hash, &key, (void **)&vs, &next) >= 0) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "ip",
                                    ip46_address_format(&vs->vaddr, buf));
            cJSON_AddNumberToObject(obj, "port", rte_be_to_cpu_16(vs->vport));
            cJSON_AddStringToObject(obj, "type", l4proto_format(vs->proto));
            cJSON_AddStringToObject(obj, "sched", vs->sched.name);
            cJSON_AddNumberToObject(obj, "max_conns", vs->max_conns);
            cJSON_AddNumberToObject(obj, "synproxy",
                                    !!(vs->flags & LB_VS_F_SYNPROXY));
            cJSON_AddNumberToObject(obj, "toa", !!(vs->flags & LB_VS_F_TOA));
            cJSON_AddNumberToObject(obj, "est_timeout", vs->est_timeout);
            cJSON_AddNumberToObject(obj, "refcnt",
                                    rte_atomic32_read(&vs->refcnt));
            cJSON_AddNumberToObject(obj, "active_conns",
                                    rte_atomic32_read(&vs->active_conns));
            cJSON_AddItemToArray(array, obj);
        }
        char *str = cJSON_PrintUnformatted(array);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(array);
    } else {
        unixctl_command_reply(
            fd, "%-45s  %-5s  %-5s  %-10s  %-10s  %-8s  %-3s  %-10s\n", "IP",
            "Port", "Type", "Sched", "Max_conns", "Synproxy", "Toa",
            "Conn_timeout");
        while (rte_hash_iterate(m->vs_hash, &key, (void **)&vs, &next) >= 0) {
            unixctl_command_reply(
                fd, "%-45s  %-5u  %-5s  %-10s  %-10d  %-8u  %-3u  %-10u\n",
                ip46_address_format(&vs->vaddr, buf),
                rte_be_to_cpu_16(vs->vport), l4proto_format(vs->proto),
                vs->sched.name, vs->max_conns, !!(vs->flags & LB_VS_F_SYNPROXY),
                !!(vs->flags & LB_VS_F_TOA), vs->est_timeout);
        }
    }
}
UNIXCTL_CMD_REGISTER("vs/list", "[--json].", "List all virtual services.", 0, 1,
                     vs_list_cmd_cb);

static int
vs_flags_arg_parse(char *argv[], int argc, ip46_address_t *vip, uint16_t *vport,
                   lb_proto_t *proto, uint8_t *echo, uint8_t *op) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0 || *proto != LB_PROTO_TCP) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (parser_read_uint8(op, argv[i++]) < 0) {
            return i - 1;
        }
    } else {
        *echo = 1;
        *op = 0;
    }

    return i;
}

static void
vs_synproxy_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    uint8_t op;
    int rc;
    struct lb_virt_service *vs;

    rc = vs_flags_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%u\n", !!(vs->flags & LB_VS_F_SYNPROXY));
    } else {
        if (op) {
            vs->flags |= LB_VS_F_SYNPROXY;
        } else {
            vs->flags &= ~LB_VS_F_SYNPROXY;
        }
    }
}

UNIXCTL_CMD_REGISTER("vs/synproxy", "VIP VPORT tcp [0|1].",
                     "Show or set synproxy.", 3, 4, vs_synproxy_cmd_cb);

static void
vs_toa_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    uint8_t op;
    int rc;
    struct lb_virt_service *vs;

    rc = vs_flags_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%u\n", !!(vs->flags & LB_VS_F_TOA));
    } else {
        if (op) {
            vs->flags |= LB_VS_F_TOA;
        } else {
            vs->flags &= ~LB_VS_F_TOA;
        }
    }
}

UNIXCTL_CMD_REGISTER("vs/toa", "VIP VPORT tcp [0|1].", "Show or set toa.", 3, 4,
                     vs_toa_cmd_cb);

static int
vs_max_conn_arg_parse(char *argv[], int argc, ip46_address_t *vip,
                      uint16_t *vport, lb_proto_t *proto, uint8_t *echo,
                      int *max) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (parser_read_int32(max, argv[i++]) < 0 || *max < 0) {
            return i - 1;
        }
    } else {
        *echo = 1;
        *max = 0;
    }
    return i;
}

static void
vs_max_conn_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    int max;
    int rc;
    struct lb_virt_service *vs;

    rc = vs_max_conn_arg_parse(argv, argc, &vip, &vport, &proto, &echo, &max);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%d\n", vs->max_conns);
    } else {
        vs->max_conns = max;
    }
}

UNIXCTL_CMD_REGISTER("vs/max_conns", "VIP VPORT tcp [0|1].",
                     "Show or set max_conns.", 3, 4, vs_max_conn_cmd_cb);

static int
vs_conn_timeout_arg_parse(char *argv[], int argc, ip46_address_t *vip,
                          uint16_t *vport, lb_proto_t *proto, uint8_t *echo,
                          uint32_t *timeout) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (parser_read_uint32(timeout, argv[i++]) < 0) {
            return i - 1;
        }
    } else {
        *echo = 1;
        *timeout = 0;
    }
    return i;
}

static void
vs_conn_timeout_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    uint32_t timeout;
    int rc;
    struct lb_virt_service *vs;

    rc = vs_conn_timeout_arg_parse(argv, argc, &vip, &vport, &proto, &echo,
                                   &timeout);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%u\n", vs->est_timeout / MS_PER_S);
    } else {
        vs->est_timeout = timeout * MS_PER_S;
    }
}

UNIXCTL_CMD_REGISTER("vs/est_timeout", "VIP VPORT tcp|udp [SEC].",
                     "Show or set connection timeout.", 3, 4,
                     vs_conn_timeout_cmd_cb);

static int
vs_scheduler_arg_parse(char *argv[], int argc, ip46_address_t *vip,
                       uint16_t *vport, lb_proto_t *proto, uint8_t *echo,
                       char sched_name[]) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (parse_sched_name(argv[i++], sched_name) < 0) {
            return i - 1;
        }
    } else {
        *echo = 1;
    }
    return i;
}

static void
vs_scheduler_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    char sched_name[LB_SCHED_NAMESIZE];
    int rc;
    struct lb_virt_service *vs;

    rc = vs_scheduler_arg_parse(argv, argc, &vip, &vport, &proto, &echo,
                                sched_name);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%s\n", vs->sched.name);
        return;
    }

    if (lb_vs_update_sched(vs, sched_name) < 0) {
        unixctl_command_reply_error(fd, "update scheduler to %s failed.\n",
                                    sched_name);
    }
}

UNIXCTL_CMD_REGISTER("vs/scheduler",
                     "VIP VPORT tcp|udp [iponly|ipport|rr|wrr].",
                     "Show or set scheduler.", 3, 4, vs_scheduler_cmd_cb);

static int
vs_stats_arg_parse(char *argv[], int argc, ip46_address_t *vip, uint16_t *vport,
                   lb_proto_t *proto, int *json_fmt) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (i == argc) {
        *json_fmt = 0;
        return i;
    }
    if (strcmp(argv[i++], "--json") == 0) {
        *json_fmt = 1;
        return i;
    } else {
        return i - 1;
    }
}

static void
vs_stats_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    int json_fmt = 0;
    int rc;
    struct lb_virt_service *vs;
    uint32_t lcore_id;
    uint64_t rx_packets[2] = {0}, rx_bytes[2] = {0}, rx_drops[2] = {0};
    uint64_t tx_packets[2] = {0}, tx_bytes[2] = {0};
    uint64_t active_conns = 0, history_conns = 0, max_conns = 0;
    struct lb_real_service *rs;

    rc = vs_stats_arg_parse(argv, argc, &vip, &vport, &proto, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
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
    active_conns = (uint64_t)rte_atomic32_read(&vs->active_conns);
    LIST_FOREACH(rs, &vs->real_services, next) {
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            tx_packets[0] += rs->stats[lcore_id].packets[0];
            tx_packets[1] += rs->stats[lcore_id].packets[1];
            tx_bytes[0] += rs->stats[lcore_id].bytes[0];
            tx_bytes[1] += rs->stats[lcore_id].bytes[1];
        }
    }
    max_conns = vs->max_conns;
    if (json_fmt) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "max-conns", max_conns);
        cJSON_AddNumberToObject(obj, "active-conns", active_conns);
        cJSON_AddNumberToObject(obj, "history-conns", history_conns);
        cJSON_AddNumberToObject(obj, "[c2v]packets", rx_packets[0]);
        cJSON_AddNumberToObject(obj, "[c2v]bytes", rx_bytes[0]);
        cJSON_AddNumberToObject(obj, "[c2v]drops", rx_drops[0]);
        cJSON_AddNumberToObject(obj, "[r2v]packets", rx_packets[1]);
        cJSON_AddNumberToObject(obj, "[r2v]bytes", rx_bytes[1]);
        cJSON_AddNumberToObject(obj, "[r2v]drops", rx_drops[1]);
        cJSON_AddNumberToObject(obj, "[v2r]packets", tx_packets[0]);
        cJSON_AddNumberToObject(obj, "[v2r]bytes", tx_bytes[0]);
        cJSON_AddNumberToObject(obj, "[v2c]packets", tx_packets[1]);
        cJSON_AddNumberToObject(obj, "[v2c]bytes", tx_bytes[1]);
        char *str = cJSON_PrintUnformatted(obj);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(obj);
    } else {
        unixctl_command_reply(fd, "active-conns: %" PRIu64 "\n", active_conns);
        unixctl_command_reply(fd, "history-conns: %" PRIu64 "\n",
                              history_conns);
        unixctl_command_reply(fd, "[c2v]packets: %" PRIu64 "\n", rx_packets[0]);
        unixctl_command_reply(fd, "[c2v]bytes: %" PRIu64 "\n", rx_bytes[0]);
        unixctl_command_reply(fd, "[c2v]drops: %" PRIu64 "\n", rx_drops[0]);
        unixctl_command_reply(fd, "[r2v]packets: %" PRIu64 "\n", rx_packets[1]);
        unixctl_command_reply(fd, "[r2v]bytes: %" PRIu64 "\n", rx_bytes[1]);
        unixctl_command_reply(fd, "[r2v]drops: %" PRIu64 "\n", rx_drops[1]);
        unixctl_command_reply(fd, "[v2r]packets: %" PRIu64 "\n", tx_packets[0]);
        unixctl_command_reply(fd, "[v2r]bytes: %" PRIu64 "\n", tx_bytes[0]);
        unixctl_command_reply(fd, "[v2c]packets: %" PRIu64 "\n", tx_packets[1]);
        unixctl_command_reply(fd, "[v2c]bytes: %" PRIu64 "\n", tx_bytes[1]);
    }
}

UNIXCTL_CMD_REGISTER("vs/stats", "VIP VPORT tcp|udp [--json].",
                     "Show packet statistics of virtual service.", 3, 4,
                     vs_stats_cmd_cb);

static int
rs_add_arg_parse(char *argv[], int argc, ip46_address_t *vip, uint16_t *vport,
                 lb_proto_t *proto, ip46_address_t *rip, uint16_t *rport,
                 int *weight) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_ip46_address(argv[i++], rip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], rport) < 0) {
        return i - 1;
    }
    if (i < argc) {
        if (parser_read_uint16((uint16_t *)weight, argv[i++]) < 0) {
            return i - 1;
        }
    } else {
        *weight = 0;
    }

    return i;
}

static void
rs_add_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    ip46_address_t rip;
    uint16_t rport;
    int weight;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = rs_add_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                          &weight);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if ((rs = lb_rs_table_lookup_inline(vs, &rip, rport)) != NULL) {
        unixctl_command_reply_error(fd, "Real service is exist.\n");
        return;
    }
    if (!(rs = lb_rs_create(&rip, rport, weight, vs))) {
        unixctl_command_reply_error(fd, "Create real service failed.\n");
        return;
    }
    if (lb_rs_sched_enable(rs, 1) < 0) {
        lb_rs_put(rs);
        unixctl_command_reply_error(fd, "Cannot enable real service sched.");
        return;
    }
    lb_rs_table_add_inline(vs, rs);
}

UNIXCTL_CMD_REGISTER("rs/add", "VIP VPORT tcp|udp RIP RPORT [WEIGHT].",
                     "Add real service.", 5, 6, rs_add_cmd_cb);

static int
rs_del_arg_parse(char *argv[], __attribute((unused)) int argc,
                 ip46_address_t *vip, uint16_t *vport, lb_proto_t *proto,
                 ip46_address_t *rip, uint16_t *rport) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_ip46_address(argv[i++], rip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], rport) < 0) {
        return i - 1;
    }
    return i;
}

static void
rs_del_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    ip46_address_t rip;
    uint16_t rport;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = rs_del_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (!(rs = lb_rs_table_lookup_inline(vs, &rip, rport))) {
        return;
    }
    lb_rs_sched_enable(rs, 0);
    lb_rs_table_del_inline(vs, rs);
    lb_rs_put(rs);
}

UNIXCTL_CMD_REGISTER("rs/del", "VIP VPORT tcp|udp RIP RPORT.",
                     "Del real service.", 5, 5, rs_del_cmd_cb);

static int
rs_list_arg_parse(char *argv[], int argc, ip46_address_t *vip, uint16_t *vport,
                  lb_proto_t *proto, int *json_fmt) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (i == argc) {
        *json_fmt = 0;
        return i;
    }
    if (strcmp(argv[i++], "--json") == 0) {
        *json_fmt = 1;
        return i;
    } else {
        return i - 1;
    }
}

static void
rs_list_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    int json_fmt = 0;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;
    char ipbuf[INET6_ADDRSTRLEN];

    rc = rs_list_arg_parse(argv, argc, &vip, &vport, &proto, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (json_fmt) {
        cJSON *array = cJSON_CreateArray();
        if (!array)
            return;
        LIST_FOREACH(rs, &vs->real_services, next) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "ip",
                                    ip46_address_format(&rs->raddr, ipbuf));
            cJSON_AddNumberToObject(obj, "port", rte_be_to_cpu_16(rs->rport));
            cJSON_AddStringToObject(obj, "type",
                                    l4proto_format(rs->virt_service->proto));
            cJSON_AddStringToObject(
                obj, "status", rs->flags & LB_RS_F_AVAILABLE ? "up" : "down");
            cJSON_AddNumberToObject(obj, "weight", rs->sched_node.weight);
            cJSON_AddItemToArray(array, obj);
        }
        char *str = cJSON_PrintUnformatted(array);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(array);
    } else {
        unixctl_command_reply(fd, "%-45s  %-5s  %-4s  %-6s  %-10s\n", "IP",
                              "Port", "Type", "Status", "Weight");
        LIST_FOREACH(rs, &vs->real_services, next) {
            unixctl_command_reply(fd, "%-45s  %-5u  %-4s  %-6s  %-10d\n",
                                  ip46_address_format(&rs->raddr, ipbuf),
                                  rte_be_to_cpu_16(rs->rport),
                                  l4proto_format(rs->virt_service->proto),
                                  rs->flags & LB_RS_F_AVAILABLE ? "up" : "down",
                                  rs->sched_node.weight);
        }
    }
}

UNIXCTL_CMD_REGISTER("rs/list", "VIP VPORT tcp|udp [--json].",
                     "List all real services.", 3, 4, rs_list_cmd_cb);

static int
rs_status_arg_parse(char *argv[], int argc, ip46_address_t *vip,
                    uint16_t *vport, lb_proto_t *proto, ip46_address_t *rip,
                    uint16_t *rport, uint8_t *echo, uint8_t *op) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_ip46_address(argv[i++], rip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], rport) < 0) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (strcmp("up", argv[i]) == 0) {
            *op = 1;
        } else if (strcmp("down", argv[i]) == 0) {
            *op = 0;
        } else {
            return i;
        }
        i++;
    } else {
        *echo = 1;
    }
    return i;
}

static void
rs_status_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip, rip;
    uint16_t vport, rport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    uint8_t op = 0;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = rs_status_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                             &echo, &op);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (!(rs = lb_rs_table_lookup_inline(vs, &rip, rport))) {
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%s\n",
                              rs->flags & LB_RS_F_AVAILABLE ? "up" : "down");
    } else {
        lb_rs_sched_enable(rs, op);
    }
}

UNIXCTL_CMD_REGISTER("rs/status", "VIP VPORT tcp|udp RIP RPORT [down|up].",
                     "Show or set the status of real services.", 5, 6,
                     rs_status_cmd_cb);

static int
rs_weight_arg_parse(char *argv[], int argc, ip46_address_t *vip,
                    uint16_t *vport, lb_proto_t *proto, ip46_address_t *rip,
                    uint16_t *rport, uint8_t *echo, int *weight) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_ip46_address(argv[i++], rip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], rport) < 0) {
        return i - 1;
    }
    if (i < argc) {
        *echo = 0;
        if (parser_read_uint16((uint16_t *)weight, argv[i++]) < 0)
            return i - 1;
    } else {
        *echo = 1;
    }

    return i;
}

static void
rs_weight_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip, rip;
    uint16_t vport, rport;
    lb_proto_t proto = LB_PROTO_MAX;
    uint8_t echo = 0;
    int weight;
    int rc;
    struct lb_virt_service *vs;
    struct lb_real_service *rs;

    rc = rs_weight_arg_parse(argv, argc, &vip, &vport, &proto, &rip, &rport,
                             &echo, &weight);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (!(rs = lb_rs_table_lookup_inline(vs, &rip, rport))) {
        return;
    }
    if (echo) {
        unixctl_command_reply(fd, "%d\n", rs->sched_node.weight);
    } else {
        lb_rs_update_weight(rs, weight);
    }
}

UNIXCTL_CMD_REGISTER("rs/weight", "VIP VPORT tcp|udp RIP RPORT [WEIGHT].",
                     "Show or set the weight of real services.", 5, 6,
                     rs_weight_cmd_cb);

static int
rs_stats_arg_parse(char *argv[], int argc, ip46_address_t *vip, uint16_t *vport,
                   lb_proto_t *proto, ip46_address_t *rip, uint16_t *rport,
                   int *json_fmt) {
    int i = 0;

    if (parse_ip46_address(argv[i++], vip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], vport) < 0) {
        return i - 1;
    }
    if (parse_l4_proto(argv[i++], proto) < 0) {
        return i - 1;
    }
    if (parse_ip46_address(argv[i++], rip) < 0) {
        return i - 1;
    }
    if (parse_l4_port(argv[i++], rport) < 0) {
        return i - 1;
    }
    if (i == argc) {
        *json_fmt = 0;
        return i;
    }
    if (strcmp(argv[i++], "--json") == 0) {
        *json_fmt = 1;
        return i;
    } else {
        return i - 1;
    }
}

static void
rs_stats_cmd_cb(int fd, char *argv[], int argc) {
    ip46_address_t vip;
    uint16_t vport;
    lb_proto_t proto = LB_PROTO_MAX;
    ip46_address_t rip;
    uint16_t rport;
    int json_fmt = 0;
    int rc;
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
    if (!(vs = lb_vs_table_lookup_inline(&vip, vport, proto))) {
        unixctl_command_reply_error(fd, "Cannot find virt service.\n");
        return;
    }
    if (!(rs = lb_rs_table_lookup_inline(vs, &rip, rport))) {
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
    if (json_fmt) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "active-conns", active_conns);
        cJSON_AddNumberToObject(obj, "history-conns", active_conns);
        cJSON_AddNumberToObject(obj, "[v2r]packets", active_conns);
        cJSON_AddNumberToObject(obj, "[v2r]bytes", active_conns);
        cJSON_AddNumberToObject(obj, "[r2v]packets", active_conns);
        cJSON_AddNumberToObject(obj, "[r2v]bytes", active_conns);
        char *str = cJSON_PrintUnformatted(obj);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(obj);
    } else {
        unixctl_command_reply(fd, "active-conns: %u\n", active_conns);
        unixctl_command_reply(fd, "history-conns: %u\n", history_conns);
        unixctl_command_reply(fd, "[v2r]packets: %u\n", packets[0]);
        unixctl_command_reply(fd, "[v2r]bytes: %u\n", bytes[0]);
        unixctl_command_reply(fd, "[r2v]packets: %u\n", packets[1]);
        unixctl_command_reply(fd, "[r2v]bytes: %u\n", bytes[1]);
    }
}

UNIXCTL_CMD_REGISTER("rs/stats", "VIP VPORT tcp|udp RIP RPORT.",
                     "Show the packet stats of real services.", 5, 6,
                     rs_stats_cmd_cb);
