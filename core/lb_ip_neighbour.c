/* Copyright (c) 2018. TIG developer. */

#include <sys/queue.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_tailq.h>
#include <rte_timer.h>

#include <unixctl_command.h>

#include "lb.h"
#include "lb_ip_address.h"
#include "lb_ip_neighbour.h"

#define LB_NEIGHBOUR_TABLE_SIZE 4096
#define LB_NEIGHBOUR_TIMEOUT (1800 * LB_CLOCK_HZ)

struct neighbour_entry {
    TAILQ_ENTRY(neighbour_entry) tailq;
    ip46_address_t ip;
    struct ether_addr ha;
    rte_atomic32_t use_time;
    rte_rwlock_t rwlock;
    int used;
};

struct neighbour_table {
    struct rte_hash *hash;
    struct neighbour_entry *entries;
    TAILQ_HEAD(, neighbour_entry) neigh_list;
    struct rte_timer timer;
    uint32_t timeout;
    uint32_t size;
};

static struct neighbour_table nd_tbl;

static inline int
neighbour_is_used(struct neighbour_entry *neigh) {
    return neigh->used;
}

static inline void
neighbour_set_used(struct neighbour_entry *neigh) {
    neigh->used = 1;
}

static inline void
neighbour_set_unused(struct neighbour_entry *neigh) {
    neigh->used = 0;
}

static int
ip46_neighbour_is_exist(ip46_address_t *ip46) {
    struct neighbour_table *table = &nd_tbl;

    RTE_ASSERT(rte_lcore_id() == rte_get_master_lcore());

    return rte_hash_lookup(table->hash, ip46) >= 0 ? 1 : 0;
}

int
lb_ip4_neighbour_is_exist(ip4_address_t *ip4) {
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    return ip46_neighbour_is_exist(&ip46);
}

int
lb_ip6_neighbour_is_exist(ip6_address_t *ip6) {
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    return ip46_neighbour_is_exist(&ip46);
}

#define MAC_ADDR_CMP 0xFFFFFFFFFFFFULL

static inline int
ether_addr_cmp(struct ether_addr *ea, struct ether_addr *eb) {
    return ((*(uint64_t *)ea ^ *(uint64_t *)eb) & MAC_ADDR_CMP) == 0;
}

static int
ip46_neighbour_update(ip46_address_t *ip46, struct ether_addr *ha) {
    struct neighbour_table *table = &nd_tbl;
    struct neighbour_entry *neigh;
    int i;

    RTE_ASSERT(rte_lcore_id() == rte_get_master_lcore());

    // rte_rwlock_write_lock(&table->rwlock);
    if ((i = rte_hash_lookup(table->hash, ip46)) >= 0) {
        neigh = &table->entries[i];
        if (ether_addr_cmp(&neigh->ha, ha))
            return 0;

        rte_rwlock_write_lock(&neigh->rwlock);
        neigh->ha = *ha;
        rte_rwlock_write_unlock(&neigh->rwlock);
        rte_atomic32_set(&neigh->use_time, LB_CLOCK());
        // rte_rwlock_write_unlock(&table->rwlock);
        return 0;
    }
    return -1;
}

int
lb_ip4_neighbour_update(ip4_address_t *ip4, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    return ip46_neighbour_update(&ip46, ha);
}

int
lb_ip6_neighbour_update(ip6_address_t *ip6, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    return ip46_neighbour_update(&ip46, ha);
}

static int
ip46_neighbour_create(ip46_address_t *ip46, struct ether_addr *ha) {
    struct neighbour_table *table = &nd_tbl;

    struct neighbour_entry *neigh;
    int i;

    RTE_ASSERT(rte_lcore_id() == rte_get_master_lcore());

    if ((i = rte_hash_add_key(table->hash, ip46)) >= 0) {
        neigh = &table->entries[i];
        if (neighbour_is_used(neigh)) {
            return -1;
        }
        rte_rwlock_write_lock(&neigh->rwlock);
        neigh->ip = *ip46;
        neigh->ha = *ha;
        rte_rwlock_write_unlock(&neigh->rwlock);
        rte_atomic32_set(&neigh->use_time, LB_CLOCK());
        neighbour_set_used(neigh);
        TAILQ_INSERT_TAIL(&table->neigh_list, neigh, tailq);
        return 0;
    }
    return -1;
}

int
lb_ip4_neighbour_create(ip4_address_t *ip4, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    return ip46_neighbour_create(&ip46, ha);
}

int
lb_ip6_neighbour_create(ip6_address_t *ip6, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    return ip46_neighbour_create(&ip46, ha);
}

static int
ip46_neighbour_lookup_ha(ip46_address_t *ip46, struct ether_addr *ha) {
    struct neighbour_table *table = &nd_tbl;
    struct neighbour_entry *neigh;
    int i;

    if ((i = rte_hash_lookup(table->hash, ip46)) >= 0) {
        neigh = &table->entries[i];
        rte_rwlock_write_lock(&neigh->rwlock);
        ether_addr_copy(&neigh->ha, ha);
        rte_rwlock_write_unlock(&neigh->rwlock);
        rte_atomic32_set(&neigh->use_time, LB_CLOCK());
    }

    return i;
}

int
lb_ip4_neighbour_lookup_ha(ip4_address_t *ip4, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    return ip46_neighbour_lookup_ha(&ip46, ha);
}

int
lb_ip6_neighbour_lookup_ha(ip6_address_t *ip6, struct ether_addr *ha) {
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    return ip46_neighbour_lookup_ha(&ip46, ha);
}

static void
neighbour_table_expire_cb(__rte_unused struct rte_timer *timer,
                          __rte_unused void *arg) {
    struct neighbour_table *table = &nd_tbl;
    struct neighbour_entry *neigh, *tmp;
    uint32_t cur_time = LB_CLOCK();

    RTE_ASSERT(rte_lcore_id() == rte_get_master_lcore());
    TAILQ_FOREACH_SAFE(neigh, &table->neigh_list, tailq, tmp) {
        if (cur_time - rte_atomic32_read(&neigh->use_time) >= table->timeout) {
            rte_hash_del_key(table->hash, &neigh->ip);
            neighbour_set_unused(neigh);
            TAILQ_REMOVE(&table->neigh_list, neigh, tailq);
        }
    }
}

int
lb_ip_neighbour_table_init(void) {
    struct neighbour_table *tbl = &nd_tbl;
    struct rte_hash_parameters params;

    memset(&params, 0, sizeof(params));
    params.name = "neigh_hash";
    params.entries = LB_NEIGHBOUR_TABLE_SIZE;
    params.key_len = sizeof(ip46_address_t);
    params.hash_func = rte_hash_crc;
    params.socket_id = SOCKET_ID_ANY;
    tbl->hash = rte_hash_create(&params);
    if (tbl->hash == NULL) {
        log_err("%s(): Create neighbour hash table failed, %s.\n", __func__,
                rte_strerror(rte_errno));
        return -1;
    }
    tbl->entries = rte_zmalloc_socket(
        NULL, LB_NEIGHBOUR_TABLE_SIZE * sizeof(struct neighbour_entry),
        RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
    if (tbl->entries == NULL) {
        log_err("%s(): Alloc memory for neighbour entries table failed.\n",
                __func__);
        return -1;
    }
    tbl->timeout = LB_NEIGHBOUR_TIMEOUT;
    tbl->size = LB_NEIGHBOUR_TABLE_SIZE;
    TAILQ_INIT(&tbl->neigh_list);
    rte_timer_init(&tbl->timer);
    rte_timer_reset(&tbl->timer, SEC_TO_CYCLES(5), PERIODICAL,
                    rte_get_master_lcore(), neighbour_table_expire_cb, NULL);
    return 0;
}

static void
neighbour_show_cmd_cb(int fd, __rte_unused char *argv[],
                      __rte_unused int argc) {
    struct neighbour_table *tbl = &nd_tbl;
    struct neighbour_entry *neigh;
    char ipbuf[INET6_ADDRSTRLEN], ethbuf[ETHER_ADDR_FMT_SIZE];

    unixctl_command_reply(fd, "%-45s  %-17s\n", "IPAddress", "HWAddress");
    TAILQ_FOREACH(neigh, &tbl->neigh_list, tailq) {
        ip46_address_format(&neigh->ip, ipbuf);
        ether_format_addr(ethbuf, sizeof(ethbuf), &neigh->ha);
        unixctl_command_reply(fd, "%-45s  %-17s\n", ipbuf, ethbuf);
    }
}

UNIXCTL_CMD_REGISTER("ip/neigh", "", "show ARP and NDISC entries.", 0, 0,
                     neighbour_show_cmd_cb);