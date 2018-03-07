/* Copyright (c) 2017. TIG developer. */

#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_timer.h>

#include "lb_arp.h"
#include "lb_config.h"
#include "lb_device.h"
#include "lb_rwlock.h"
#include "lcore_event.h"
#include "parser.h"
#include "unixctl_command.h"

struct arp_entry {
    struct ether_addr ha;
    uint32_t ip;
    uint64_t create_time;
    volatile uint64_t recent_use_time[RTE_MAX_LCORE];
};

struct arp_table {
    struct rte_hash *arp_entries;
    uint32_t table_size; /* Max size of arp table. */
    uint32_t count;      /* number of arp entry in arp table. */
    uint32_t max_expire_num;
    uint64_t arp_expire_period;
    struct rte_timer table_timer;
};

static struct arp_table *arp_tbl;

static struct arp_entry *
arp_entry_create(uint32_t ip, struct ether_addr *ha) {
    struct arp_entry *entry;
    uint32_t lcore_id;

    entry = rte_zmalloc(NULL, sizeof(struct arp_entry), 0);
    if (!entry) {
        return NULL;
    }
    entry->ip = ip;
    ether_addr_copy(ha, &entry->ha);
    entry->create_time = rte_rdtsc();
    RTE_LCORE_FOREACH(lcore_id) {
        entry->recent_use_time[lcore_id] = entry->create_time;
    }
    return entry;
}

static void
arp_entry_destory(struct arp_entry *entry) {
    rte_free(entry);
}

static int
is_arp_table_full(void) {
    return arp_tbl->count < arp_tbl->table_size ? 0 : 1;
}

static struct arp_entry *
arp_table_lookup(uint32_t ip) {
    struct arp_entry *entry;

    return rte_hash_lookup_data(arp_tbl->arp_entries, (const void *)&ip,
                                (void **)&entry) < 0
               ? NULL
               : entry;
}

static int
arp_table_add(struct arp_entry *entry) {
    if (rte_hash_add_key_data(arp_tbl->arp_entries, &entry->ip, entry) < 0)
        return -1;
    arp_tbl->count++;
    return 0;
}

static int
arp_table_del(struct arp_entry *entry) {
    if (rte_hash_del_key(arp_tbl->arp_entries, &entry->ip) < 0)
        return -1;
    arp_tbl->count--;
    return 0;
}

static inline int
__is_arp_expire(struct arp_entry *entry, uint64_t cur_time) {
    uint32_t lcore_id;
    uint32_t is_expire = 1;

    RTE_LCORE_FOREACH(lcore_id) {
        if (entry->recent_use_time[lcore_id] + arp_tbl->arp_expire_period >
            cur_time) {
            is_expire = 0;
            break;
        }
    }
    return is_expire;
}

static void
arp_table_expire(__attribute((unused)) struct rte_timer *timer,
                 __attribute((unused)) void *arg) {
    const void *key;
    struct arp_entry *entry;
    uint32_t next = 0;
    struct arp_entry *entries[arp_tbl->max_expire_num];
    uint32_t count = 0;
    uint64_t cur_time = rte_rdtsc();

    while (rte_hash_iterate(arp_tbl->arp_entries, &key, (void **)&entry,
                            &next) >= 0) {
        if (count == arp_tbl->max_expire_num) {
            break;
        }
        if (__is_arp_expire(entry, cur_time)) {
            entries[count++] = entry;
        }
    }

    if (count > 0) {
        uint32_t i;
        thread_write_lock();
        for (i = 0; i < count; i++) {
            arp_table_del(entries[i]);
        }
        thread_write_unlock();
        for (i = 0; i < count; i++) {
            arp_entry_destory(entries[i]);
        }
    }
}

static const struct ether_addr boardcast_hw = {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static void
arp_send(uint16_t type, uint32_t dst_ip, uint32_t src_ip,
         struct ether_addr *dst_ha, struct ether_addr *src_ha) {
    struct rte_mbuf *mbuf;
    struct ether_hdr *ethh;
    struct arp_hdr *ah;

    if (!(mbuf = rte_pktmbuf_alloc(lb_pktmbuf_pool)))
        return;

    ethh = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    if (dst_ha != NULL) {
        ether_addr_copy(src_ha, &ethh->s_addr);
        ether_addr_copy(dst_ha, &ethh->d_addr);
        ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    } else {
        ether_addr_copy(src_ha, &ethh->s_addr);
        ether_addr_copy(&boardcast_hw, &ethh->d_addr);
        ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);
    }

    ah = (struct arp_hdr *)((char *)ethh + sizeof(*ethh));
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

    mbuf->data_len = sizeof(*ethh) + sizeof(*ah);
    mbuf->pkt_len = sizeof(*ethh) + sizeof(*ah);

    lb_netdev_xmit_now(mbuf);
}

static void
arp_notfind_event_cb(__attribute__((unused)) unsigned snd_lcoreid,
                     void *param) {
    struct rte_mbuf *pkt = param;
    struct ipv4_hdr *iph =
        rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ETHER_HDR_LEN);
    uint32_t rt_ip;

    rt_ip = lb_netdev_ipv4_route(iph->dst_addr);
    arp_send(ARP_OP_REQUEST, rt_ip, lb_netdev->ip, NULL, &lb_netdev->ha);
    rte_pktmbuf_free(pkt);
}

int
lb_arp_find(uint32_t dst_ip, struct ether_addr *dst_ha, struct rte_mbuf *pkt) {
    uint32_t lcore_id = rte_lcore_id();
    struct arp_entry *entry;

    if ((entry = arp_table_lookup(dst_ip)) != NULL) {
        ether_addr_copy(&entry->ha, dst_ha);
        entry->recent_use_time[lcore_id] = rte_rdtsc();
        return 0;
    }
    lcore_event_notify(rte_get_master_lcore(), arp_notfind_event_cb, pkt);
    return -1;
}

static void
arp_new(uint32_t ip, struct ether_addr *ha) {
    struct arp_entry *entry;

    if (is_arp_table_full()) {
        return;
    }
    if ((entry = arp_entry_create(ip, ha)) != NULL) {
        thread_write_lock();
        arp_table_add(entry);
        thread_write_unlock();
    }
}

#define MAC_ADDR_CMP 0xFFFFFFFFFFFFULL

static inline int __attribute__((always_inline))
ether_addr_cmp(struct ether_addr *ea, struct ether_addr *eb) {
    return ((*(uint64_t *)ea ^ *(uint64_t *)eb) & MAC_ADDR_CMP) == 0;
}

static void
arp_update(struct arp_entry *entry, struct ether_addr *ha) {
    uint32_t lcore_id = rte_lcore_id();

    if (!ether_addr_cmp(&entry->ha, ha)) {
        thread_write_lock();
        ether_addr_copy(ha, &entry->ha);
        thread_write_unlock();
    }
    entry->recent_use_time[lcore_id] = rte_rdtsc();
}

void
lb_arp_packet_recv(struct rte_mbuf *mbuf) {
    struct arp_hdr *ah;
    struct arp_entry *entry;

    ah = rte_pktmbuf_mtod_offset(mbuf, struct arp_hdr *,
                                 sizeof(struct ether_hdr));
    /* lb learn arp */
    entry = arp_table_lookup(ah->arp_data.arp_sip);
    if (!entry) {
        arp_new(ah->arp_data.arp_sip, &ah->arp_data.arp_sha);
    } else {
        arp_update(entry, &ah->arp_data.arp_sha);
    }
}

static void
arp_show_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                __attribute__((unused)) int argc) {
    const void *key;
    struct arp_entry *arp;
    uint32_t next = 0;
    char ip[32], mac[32];
    uint64_t cur_time = rte_rdtsc();

    unixctl_command_reply(fd, "IPaddress        HWaddress         AliveTime\n");
    while (rte_hash_iterate(arp_tbl->arp_entries, &key, (void **)&arp, &next) >=
           0) {
        ipv4_addr_tostring(arp->ip, ip, sizeof(ip));
        mac_addr_tostring(&arp->ha, mac, sizeof(mac));
        unixctl_command_reply(fd, "%-15s  %-17s %u\n", ip, mac,
                              (cur_time - arp->create_time) / rte_get_tsc_hz());
    }
}

void
lb_arp_table_init(void) {
    struct arp_config *cfg = &lb_cfg->arp;
    struct rte_hash_parameters params = {
        .name = "arp-hash-table",
        .entries = cfg->arp_max_num,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_hash_crc,
        .socket_id = -1,
    };

    arp_tbl = rte_zmalloc("arp-table", sizeof(struct arp_table), 0);
    if (!arp_tbl) {
        rte_exit(EXIT_FAILURE, "Alloc memory for arp table failed.\n");
    }

    arp_tbl->arp_entries = rte_hash_create(&params);
    if (!arp_tbl->arp_entries) {
        rte_exit(EXIT_FAILURE, "Create arp hash list failed.\n");
    }

    arp_tbl->table_size = cfg->arp_max_num;
    arp_tbl->arp_expire_period = cfg->arp_expire_period * rte_get_tsc_hz();
    arp_tbl->max_expire_num = cfg->arp_expire_max_num;

    rte_timer_init(&arp_tbl->table_timer);
    if (rte_timer_reset(&arp_tbl->table_timer, rte_get_tsc_hz(), PERIODICAL,
                        rte_get_master_lcore(), arp_table_expire, NULL) < 0) {
        rte_exit(EXIT_FAILURE, "Reset arp table timer failed.\n");
    }
    unixctl_command_register("arp", "", "Show arp table information.", 0, 0,
                             arp_show_cmd_cb);
}

