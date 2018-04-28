/* Copyright (c) 2018. TIG developer. */

#include <errno.h>

#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_timer.h>

#include <unixctl_command.h>

#include "lb_arp.h"
#include "lb_clock.h"
#include "lb_device.h"
#include "lb_parser.h"

#define LB_MAX_ARP 4096

struct arp_entry {
    struct arp_table *tbl;
    struct ether_addr ha;
    uint32_t ip;
    uint32_t timeout;
    uint32_t create_time;
    rte_atomic32_t use_time;
    struct rte_timer timer;
};

struct arp_table {
    struct rte_hash *hash;
    struct arp_entry *entries;
    uint32_t timeout;
    rte_rwlock_t rwlock;
};

static struct arp_table arp_tbls[RTE_MAX_ETHPORTS];
static uint32_t arp_timeout = 1800 * LB_CLOCK_HZ;

#define ARP_TABLE_RWLOCK_RLOCK(t) rte_rwlock_read_lock(&(t)->rwlock)
#define ARP_TABLE_RWLOCK_RUNLOCK(t) rte_rwlock_read_unlock(&(t)->rwlock)
#define ARP_TABLE_RWLOCK_WLOCK(t) rte_rwlock_write_lock(&(t)->rwlock)
#define ARP_TABLE_RWLOCK_WUNLOCK(t) rte_rwlock_write_unlock(&(t)->rwlock)

#define MAC_ADDR_CMP 0xFFFFFFFFFFFFULL

static inline int __attribute__((always_inline))
ether_addr_cmp(struct ether_addr *ea, struct ether_addr *eb) {
    return ((*(uint64_t *)ea ^ *(uint64_t *)eb) & MAC_ADDR_CMP) == 0;
}

static void
arp_expire(struct rte_timer *t, void *arg) {
    struct arp_entry *entry = arg;
    struct arp_table *tbl = entry->tbl;
    uint32_t curr_time, use_time;
    int rc;

    curr_time = LB_CLOCK();
    use_time = rte_atomic32_read(&entry->use_time);
    if (curr_time - use_time >= entry->timeout) {
        ARP_TABLE_RWLOCK_WLOCK(tbl);
        rte_hash_del_key(tbl->hash, &entry->ip);
        ARP_TABLE_RWLOCK_WUNLOCK(tbl);
        rc = rte_timer_stop(t);
        if (rc < 0) {
            RTE_LOG(WARNING, USER1,
                    "%s(): Stop arp timer failed, ip(0x%08x).\n", __func__,
                    rte_be_to_cpu_32(entry->ip));
        }
    }
}

void
lb_arp_input(struct rte_mbuf *pkt, struct lb_device *dev) {
    struct arp_table *tbl;
    struct arp_entry *entry;
    struct arp_hdr *arph;
    uint32_t sip;
    struct ether_addr *sha;
    int i;

    tbl = &arp_tbls[dev->port_id];
    arph = rte_pktmbuf_mtod_offset(pkt, struct arp_hdr *, ETHER_HDR_LEN);
    sip = arph->arp_data.arp_sip;
    sha = &arph->arp_data.arp_sha;
    i = rte_hash_lookup(tbl->hash, &sip);
    if (i < 0) {
        /* add */
        ARP_TABLE_RWLOCK_WLOCK(tbl);
        i = rte_hash_add_key(tbl->hash, &sip);
        if (i < 0) {
            ARP_TABLE_RWLOCK_WUNLOCK(tbl);
            RTE_LOG(WARNING, USER1,
                    "%s(): Add key(0x%08X) to arp table failed, %s.\n",
                    __func__, rte_be_to_cpu_32(sip), strerror(-i));
            return;
        }

        entry = &tbl->entries[i];
        entry->tbl = tbl;
        ether_addr_copy(sha, &entry->ha);
        entry->ip = sip;
        entry->timeout = tbl->timeout;
        entry->create_time = LB_CLOCK();
        rte_atomic32_set(&entry->use_time, entry->create_time);
        rte_timer_init(&entry->timer);
        rte_timer_reset(&entry->timer, SEC_TO_CYCLES(5), PERIODICAL,
                        rte_get_master_lcore(), arp_expire, entry);
        ARP_TABLE_RWLOCK_WUNLOCK(tbl);
    } else {
        /* update */
        entry = &tbl->entries[i];
        if (!ether_addr_cmp(sha, &entry->ha)) {
            ARP_TABLE_RWLOCK_WLOCK(tbl);
            ether_addr_copy(sha, &entry->ha);
            rte_atomic32_set(&entry->use_time, LB_CLOCK());
            ARP_TABLE_RWLOCK_WUNLOCK(tbl);
        }
    }
}

static int
arp_send(uint16_t type, uint32_t dst_ip, uint32_t src_ip,
         struct ether_addr *dst_ha, struct ether_addr *src_ha,
         struct lb_device *dev) {
    static const struct ether_addr bc_ha = {
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct arp_hdr *ah;

    m = lb_device_pktmbuf_alloc(dev);
    if (m == NULL) {
        RTE_LOG(WARNING, USER1, "%s(): Alloc packet mbuf failed.\n", __func__);
        return -1;
    }

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    if (dst_ha != NULL) {
        ether_addr_copy(src_ha, &eth->s_addr);
        ether_addr_copy(dst_ha, &eth->d_addr);
        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    } else {
        ether_addr_copy(src_ha, &eth->s_addr);
        ether_addr_copy(&bc_ha, &eth->d_addr);
        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    }

    ah = rte_pktmbuf_mtod_offset(m, struct arp_hdr *, ETHER_HDR_LEN);
    ah->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
    ah->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ah->arp_hln = 0x6;
    ah->arp_pln = 0x4;
    ah->arp_op = rte_cpu_to_be_16(type);

    ether_addr_copy(src_ha, &ah->arp_data.arp_sha);
    ah->arp_data.arp_sip = src_ip;
    if (dst_ha != NULL)
        ether_addr_copy(dst_ha, &ah->arp_data.arp_tha);
    else
        memset(&ah->arp_data.arp_tha, 0, sizeof(struct ether_addr));
    ah->arp_data.arp_tip = dst_ip;

    m->data_len = ETHER_HDR_LEN + sizeof(*ah);
    m->pkt_len = ETHER_HDR_LEN + sizeof(*ah);

    lb_device_tx_mbuf(m, dev);
    return 0;
}

int
lb_arp_request(uint32_t dip, struct lb_device *dev) {
    return arp_send(ARP_OP_REQUEST, dip, dev->ipv4, NULL, &dev->ha, dev);
}

int
lb_arp_find(uint32_t ip, struct ether_addr *mac, struct lb_device *dev) {
    struct arp_table *tbl;
    int i;

    tbl = &arp_tbls[dev->port_id];
    ARP_TABLE_RWLOCK_RLOCK(tbl);
    i = rte_hash_lookup(tbl->hash, &ip);
    if (i >= 0) {
        ether_addr_copy(&tbl->entries[i].ha, mac);
        rte_atomic32_set(&tbl->entries[i].use_time, LB_CLOCK());
    }
    ARP_TABLE_RWLOCK_RUNLOCK(tbl);

    return i;
}

int
lb_arp_init(void) {
    uint16_t i;
    struct lb_device *dev;
    struct rte_hash_parameters params;
    char name[RTE_HASH_NAMESIZE];
    int socket_id;
    struct arp_table *tbl;

    LB_DEVICE_FOREACH(i, dev) {
        tbl = &arp_tbls[dev->port_id];
        socket_id = dev->socket_id;
        memset(&params, 0, sizeof(params));
        snprintf(name, sizeof(name), "arphash%u", i);
        params.name = name;
        params.entries = LB_MAX_ARP;
        params.key_len = sizeof(uint32_t);
        params.hash_func = rte_hash_crc;
        params.socket_id = socket_id;

        tbl->hash = rte_hash_create(&params);
        if (tbl->hash == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Create arp hash (%s) failed, %s.\n",
                    __func__, name, rte_strerror(rte_errno));
            return -1;
        }

        tbl->entries =
            rte_zmalloc_socket(NULL, LB_MAX_ARP * sizeof(struct arp_entry),
                               RTE_CACHE_LINE_SIZE, socket_id);
        if (tbl->entries == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Alloc memory for arp table failed.\n",
                    __func__);
            return -1;
        }
        rte_rwlock_init(&tbl->rwlock);

        tbl->timeout = arp_timeout;

        RTE_LOG(INFO, USER1,
                "%s(): Create arp table for port(%s) on socket%d.\n", __func__,
                dev->name, socket_id);
    }

    return 0;
}

static void
arp_list_cb(int fd, __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    uint16_t i;
    struct lb_device *dev;
    struct arp_table *tbl;
    const void *key;
    void *data;
    uint32_t next;
    struct arp_entry *entry;
    char ip[32], mac[32];
    uint32_t ctime, sec;
    int rc;

    unixctl_command_reply(
        fd, "IPaddress        HWaddress          Iface       AliveTime\n");

    ctime = LB_CLOCK();

    LB_DEVICE_FOREACH(i, dev) {
        tbl = &arp_tbls[dev->port_id];
        next = 0;
        while ((rc = rte_hash_iterate(tbl->hash, &key, &data, &next)) >= 0) {
            entry = &tbl->entries[rc];
            ipv4_addr_tostring(entry->ip, ip, sizeof(ip));
            mac_addr_tostring(&entry->ha, mac, sizeof(mac));
            sec = LB_CLOCK_TO_SEC(ctime - entry->create_time);
            unixctl_command_reply(fd, "%-15s  %-17s  %-10s  %u\n", ip, mac,
                                  dev->name, sec);
        }
    }
}

UNIXCTL_CMD_REGISTER("arp/list", "", "", 0, 0, arp_list_cb);

static void
arp_timeout_cb(int fd, char *argv[], int argc) {
    uint32_t timeout, echo = 0;
    int rc;
    uint16_t i;
    struct lb_device *dev;
    struct arp_table *tbl;

    if (argc == 0) {
        echo = 1;
    } else {
        rc = parser_read_uint32(&timeout, argv[0]);
        if (rc < 0) {
            unixctl_command_reply_error(fd, "Invalid parameter: %s.\n",
                                        argv[0]);
            return;
        }
        timeout = SEC_TO_LB_CLOCK(timeout);
    }

    LB_DEVICE_FOREACH(i, dev) {
        tbl = &arp_tbls[dev->port_id];
        if (echo) {
            unixctl_command_reply(fd, "%u\n", LB_CLOCK_TO_SEC(tbl->timeout));
            return;
        } else {
            tbl->timeout = timeout;
        }
    }
}

UNIXCTL_CMD_REGISTER("arp/timeout", "[SEC].", "", 0, 1, arp_timeout_cb);
