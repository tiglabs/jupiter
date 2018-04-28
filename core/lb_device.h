/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_DEVICE_H__
#define __LB_DEVICE_H__

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_pci.h>
#include <rte_ring.h>

#include "lb_arp.h"
#include "lb_config.h"
#include "lb_proto.h"

#define PKT_MAX_BURST 32

#define LB_MIN_L4_PORT (1024)
#define LB_MAX_L4_PORT (65535)

enum {
    LB_DEV_T_NORM = 0, /* Normal port. */
    LB_DEV_T_BOND,     /* Bond port. */
};

struct lb_laddr {
    uint32_t ipv4;
    uint16_t port_id;
    uint16_t rxq_id;
    struct rte_ring *ports[LB_IPPROTO_MAX];
};

struct lb_laddr_list {
    uint32_t nb;
    struct lb_laddr entries[LB_MAX_LADDR];
};

struct lb_device {
    uint16_t type;

    uint32_t port_id;
    uint32_t socket_id;

    struct ether_addr ha;
    uint16_t mtu;

    uint32_t ipv4;
    uint32_t netmask;
    uint32_t gw;

    uint16_t nb_rxq, nb_txq;
    uint16_t rxq_size, txq_size;

    uint32_t rx_offload;
    uint32_t tx_offload;

    struct {
        uint32_t rxq_enable;
        uint16_t rxq_id;
        uint16_t txq_id;
    } lcore_conf[RTE_MAX_LCORE];

    struct {
        uint64_t rx_dropped;
        uint64_t tx_dropped;
    } lcore_stats[RTE_MAX_LCORE];

    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_LCORE];

    char name[RTE_KNI_NAMESIZE];

    struct rte_kni *kni;

    struct rte_mempool *mp;

    /* master-worker threads communication */
    struct rte_ring *ring;

    struct lb_laddr_list laddr_list[RTE_MAX_LCORE];

    uint32_t nb_slaves;
    uint32_t slave_ports[RTE_MAX_ETHPORTS];
};

extern struct lb_device *lb_devices[RTE_MAX_ETHPORTS];
extern uint16_t lb_device_count;

#define LB_DEVICE_FOREACH(i, dev)                                              \
    for (i = 0; (dev = lb_devices[i]) != NULL; i++)

static inline int
lb_is_laddr_exist(uint32_t lip, struct lb_device *dev) {
    struct lb_laddr_list *list;
    uint32_t lcore_id = rte_lcore_id();
    uint32_t i;

    list = &dev->laddr_list[lcore_id];
    for (i = 0; i < list->nb; i++) {
        if (lip == list->entries[i].ipv4)
            return 1;
    }
    return 0;
}

static inline int
lb_laddr_get(struct lb_device *dev, enum lb_proto_type type,
             struct lb_laddr **laddr, uint16_t *port) {
    struct lb_laddr_list *list;
    struct lb_laddr *addr;
    void *p = NULL;
    uint32_t lcore_id, i;

    lcore_id = rte_lcore_id();
    list = &dev->laddr_list[lcore_id];

    for (i = 0; i < list->nb; i++) {
        addr = &list->entries[i];
        if (rte_ring_sc_dequeue(addr->ports[type], (void **)&p) == 0) {
            *laddr = addr;
            *port = (uint16_t)(uintptr_t)p;
            return 0;
        }
    }
    return -1;
}

static inline void
lb_laddr_put(struct lb_laddr *laddr, uint16_t port, enum lb_proto_type type) {
    rte_ring_sp_enqueue(laddr->ports[type], (void *)(uintptr_t)port);
}

#define IS_SAME_NETWORK(addr1, addr2, netmask)                                 \
    ((addr1 & netmask) == (addr2 & netmask))

static inline int
lb_device_dst_mac_find(uint32_t dip, struct ether_addr *ea,
                       struct lb_device *dev) {
    uint32_t rip;
    int rc;

    if (IS_SAME_NETWORK(dip, dev->ipv4, dev->netmask)) {
        rip = dip;
    } else {
        rip = dev->gw;
    }

    rc = lb_arp_find(rip, ea, dev);
    if (rc < 0) {
        lb_arp_request(rip, dev);
    }

    return rc;
}

static inline void
lb_device_tx_mbuf(struct rte_mbuf *m, struct lb_device *dev) {
    uint32_t lcore_id;
    uint16_t txq_id;
    struct rte_eth_dev_tx_buffer *tx_buffer;

    lcore_id = rte_lcore_id();
    txq_id = dev->lcore_conf[lcore_id].txq_id;
    tx_buffer = dev->tx_buffer[lcore_id];
    rte_eth_tx_buffer(dev->port_id, txq_id, tx_buffer, m);
}

static inline int
lb_device_output(struct rte_mbuf *m, struct ipv4_hdr *iph,
                 struct lb_device *dev) {
    struct ether_hdr *eth;
    int rc;

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    rc = lb_device_dst_mac_find(iph->dst_addr, &eth->d_addr, dev);
    if (rc < 0) {
        rte_pktmbuf_free(m);
        return rc;
    }
    ether_addr_copy(&dev->ha, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    lb_device_tx_mbuf(m, dev);
    return 0;
}

static inline struct rte_mbuf *
lb_device_pktmbuf_alloc(struct lb_device *dev) {
    return rte_pktmbuf_alloc(dev->mp);
}

static inline struct rte_mbuf *
lb_device_pktmbuf_clone(struct rte_mbuf *m, struct lb_device *dev) {
    return rte_pktmbuf_clone(m, dev->mp);
}

int lb_device_init(struct lb_device_conf *configs, uint16_t num);

#endif /* __LB_DEVICE_H__ */
