/* Copyright (c) 2018. TIG developer. */

#include <sys/queue.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <cjson.h>
#include <unixctl_command.h>

#include "lb.h"
#include "lb_fnat_laddr.h"
#include "lb_ip_address.h"

#define LB_FNAT_LADDR_MIN_PORT (1024)
#define LB_FNAT_LADDR_MAX_PORT (65535)

struct lb_fnat_laddr_stats {
    struct {
        uint32_t avail;
        uint32_t inuse;
    } tcp, udp;
};

LIST_HEAD(lb_fnat_laddr_list, lb_fnat_laddr);

static struct lb_fnat_laddr_list fnat_laddr_ip4_list[RTE_MAX_LCORE];
static struct lb_fnat_laddr_list fnat_laddr_ip6_list[RTE_MAX_LCORE];

int lb_fnat_laddrs_num;

static struct rte_ring *
laddr_ports_alloc_init(const char *name, uint32_t socket_id) {
    struct rte_ring *r;
    uint16_t p;

    r = rte_ring_create(name, UINT16_MAX + 1, socket_id,
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (r == NULL) {
        log_err("%s(): Create ports ring %s failed, %s.\n", __func__, name,
                rte_strerror(rte_errno));
        return NULL;
    }
    for (p = LB_FNAT_LADDR_MIN_PORT; p != LB_FNAT_LADDR_MAX_PORT; p++) {
        rte_ring_sp_enqueue(r, (void *)(uintptr_t)rte_cpu_to_be_16(p));
    }
    return r;
}

static struct lb_fnat_laddr *
lb_fnat_laddr_create(ip46_address_t *ip46) {
    struct lb_fnat_laddr *fnat_laddr;
    char name[RTE_RING_NAMESIZE];

    fnat_laddr = rte_malloc(NULL, sizeof(*fnat_laddr), 0);
    if (!fnat_laddr)
        return NULL;

    ip46_address_copy(&fnat_laddr->ip46, ip46);

    snprintf(name, sizeof(name), "TCPPORT%p", fnat_laddr);
    fnat_laddr->ports[LB_PROTO_TCP] =
        laddr_ports_alloc_init(name, SOCKET_ID_ANY);
    if (!fnat_laddr->ports[LB_PROTO_TCP]) {
        log_err("%s(): alloc laddr tcp ports failed.\n", __func__);
        rte_free(fnat_laddr);
        return NULL;
    }
    snprintf(name, sizeof(name), "UDPPORT%p", fnat_laddr);
    fnat_laddr->ports[LB_PROTO_UDP] =
        laddr_ports_alloc_init(name, SOCKET_ID_ANY);
    if (!fnat_laddr->ports[LB_PROTO_UDP]) {
        log_err("%s(): alloc laddr udp ports failed.\n", __func__);
        rte_ring_free(fnat_laddr->ports[LB_PROTO_UDP]);
        rte_free(fnat_laddr);
        return NULL;
    }
    return fnat_laddr;
}

int
lb_fnat_laddr_add_ip4(ip4_address_t *ip4) {
    static unsigned lcore_id = -1;
    struct lb_fnat_laddr *fnat_laddr;
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    fnat_laddr = lb_fnat_laddr_create(&ip46);
    if (!fnat_laddr) {
        return -1;
    }
    lcore_id = rte_get_next_lcore(lcore_id, 1 /*skip_master*/, 1 /*wrap*/);
    LIST_INSERT_HEAD(&fnat_laddr_ip4_list[lcore_id], fnat_laddr, next);
    lb_fnat_laddrs_num++;
    return lcore_id;
}

int
lb_fnat_laddr_add_ip6(ip6_address_t *ip6) {
    static unsigned lcore_id = -1;
    struct lb_fnat_laddr *fnat_laddr;
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    fnat_laddr = lb_fnat_laddr_create(&ip46);
    if (!fnat_laddr) {
        return -1;
    }
    lcore_id = rte_get_next_lcore(lcore_id, 1 /*skip_master*/, 1 /*wrap*/);
    LIST_INSERT_HEAD(&fnat_laddr_ip6_list[lcore_id], fnat_laddr, next);
    lb_fnat_laddrs_num++;
    return lcore_id;
}

int
lb_fnat_laddr_and_port_get(lb_proto_t proto, int is_ip4,
                           struct lb_fnat_laddr **fnat_laddr, uint16_t *port) {
    struct lb_fnat_laddr_list *fnat_laddr_list;
    uint32_t lcore_id = rte_lcore_id();
    struct lb_fnat_laddr *laddr;
    void *p = NULL;

    if (is_ip4)
        fnat_laddr_list = &fnat_laddr_ip4_list[lcore_id];
    else
        fnat_laddr_list = &fnat_laddr_ip6_list[lcore_id];

    LIST_FOREACH(laddr, fnat_laddr_list, next) {
        if (rte_ring_sc_dequeue(laddr->ports[proto], (void **)&p) < 0) {
            continue;
        }
        *fnat_laddr = laddr;
        *port = (uint16_t)(uintptr_t)p;
        return 0;
    }
    return -1;
}

void
lb_fnat_laddr_and_port_put(lb_proto_t proto, struct lb_fnat_laddr *fnat_laddr,
                           uint16_t port) {
    rte_ring_sp_enqueue(fnat_laddr->ports[proto], (void *)(uintptr_t)port);
}

static void
lb_fnat_laddr_stats_get(struct lb_fnat_laddr_list *list,
                        struct lb_fnat_laddr_stats *stats) {
    struct lb_fnat_laddr *laddr;
    uint32_t avail;

    memset(stats, 0, sizeof(*stats));
    LIST_FOREACH(laddr, list, next) {
        avail = rte_ring_count(laddr->ports[LB_PROTO_TCP]);
        stats->tcp.avail += avail;
        stats->tcp.inuse +=
            LB_FNAT_LADDR_MAX_PORT - LB_FNAT_LADDR_MIN_PORT - avail;
        avail = rte_ring_count(laddr->ports[LB_PROTO_UDP]);
        stats->udp.avail += avail;
        stats->udp.inuse +=
            LB_FNAT_LADDR_MAX_PORT - LB_FNAT_LADDR_MIN_PORT - avail;
    }
}

static void
laddr_stats_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt;
    uint32_t lcore_id;
    struct lb_fnat_laddr_stats ip4_stats[RTE_MAX_LCORE];
    struct lb_fnat_laddr_stats ip6_stats[RTE_MAX_LCORE];

    if (argc > 0 && strcmp(argv[0], "--json") == 0) {
        json_fmt = 1;
    } else {
        json_fmt = 0;
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        lb_fnat_laddr_stats_get(&fnat_laddr_ip4_list[lcore_id],
                                &ip4_stats[lcore_id]);
        lb_fnat_laddr_stats_get(&fnat_laddr_ip6_list[lcore_id],
                                &ip6_stats[lcore_id]);
    }

    if (json_fmt) {
        cJSON *array = cJSON_CreateArray();
        if (!array)
            return;
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(obj, "lcore", lcore_id);
            cJSON_AddNumberToObject(obj, "tcp4-avail",
                                    ip4_stats[lcore_id].tcp.avail);
            cJSON_AddNumberToObject(obj, "tcp4-inuse",
                                    ip4_stats[lcore_id].tcp.inuse);
            cJSON_AddNumberToObject(obj, "udp4-avail",
                                    ip4_stats[lcore_id].udp.avail);
            cJSON_AddNumberToObject(obj, "udp4-inuse",
                                    ip4_stats[lcore_id].udp.inuse);
            cJSON_AddNumberToObject(obj, "tcp6-avail",
                                    ip6_stats[lcore_id].tcp.avail);
            cJSON_AddNumberToObject(obj, "tcp6-inuse",
                                    ip6_stats[lcore_id].tcp.inuse);
            cJSON_AddNumberToObject(obj, "udp6-avail",
                                    ip6_stats[lcore_id].udp.avail);
            cJSON_AddNumberToObject(obj, "udp6-inuse",
                                    ip6_stats[lcore_id].udp.inuse);
            cJSON_AddItemToArray(array, obj);
        }
        char *str = cJSON_PrintUnformatted(array);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(array);
    } else {
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            unixctl_command_reply(fd, "  lcore: %u\n", lcore_id);
            unixctl_command_reply(fd, "    tcp4-avail: %u\n",
                                  ip4_stats[lcore_id].tcp.avail);
            unixctl_command_reply(fd, "    tcp4-inuse: %u\n",
                                  ip4_stats[lcore_id].tcp.inuse);
            unixctl_command_reply(fd, "    udp4-avail: %u\n",
                                  ip4_stats[lcore_id].udp.avail);
            unixctl_command_reply(fd, "    udp4-inuse: %u\n",
                                  ip4_stats[lcore_id].udp.inuse);
            unixctl_command_reply(fd, "    tcp6-avail: %u\n",
                                  ip6_stats[lcore_id].tcp.avail);
            unixctl_command_reply(fd, "    tcp6-inuse: %u\n",
                                  ip6_stats[lcore_id].tcp.inuse);
            unixctl_command_reply(fd, "    udp6-avail: %u\n",
                                  ip6_stats[lcore_id].udp.avail);
            unixctl_command_reply(fd, "    udp6-inuse: %u\n",
                                  ip6_stats[lcore_id].udp.inuse);
        }
    }
}

UNIXCTL_CMD_REGISTER("laddr/stats", "[--json].", "Show local port statistics.",
                     0, 1, laddr_stats_cmd_cb);

static void
laddr_list_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                   __attribute__((unused)) int argc) {
    uint32_t lcore_id;
    struct lb_fnat_laddr *laddr;
    char ip[INET6_ADDRSTRLEN];

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        LIST_FOREACH(laddr, &fnat_laddr_ip4_list[lcore_id], next) {
            unixctl_command_reply(fd, "ip4[c%uq%u]: %s\n", lcore_id,
                                  lb_lcore_index(lcore_id),
                                  ip46_address_format(&laddr->ip46, ip));
        }
    }
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        LIST_FOREACH(laddr, &fnat_laddr_ip6_list[lcore_id], next) {
            unixctl_command_reply(fd, "ip6[c%uq%u]: %s\n", lcore_id,
                                  lb_lcore_index(lcore_id),
                                  ip46_address_format(&laddr->ip46, ip));
        }
    }
}

UNIXCTL_CMD_REGISTER("laddr/list", "", "Show local ip address.", 0, 0,
                     laddr_list_cmd_cb);