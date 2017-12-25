/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_NET_DEVICE_H__
#define __LB_NET_DEVICE_H__

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_kni.h>
#include <rte_ring.h>

#define PKT_MAX_BURST 32

enum lb_proto_type {
    LB_PROTO_TCP = 0,
    LB_PROTO_UDP,
    LB_PROTO_MAX,
};

struct lb_local_ipv4_addr {
    uint32_t ip;
    uint16_t rxq_id;
    struct rte_ring *ports[LB_PROTO_MAX];
};

#define LB_TX_OL_IPV4_CKSUM 0x1
#define LB_TX_OL_TCP_CKSUM 0x2
#define LB_TX_OL_UDP_CKSUM 0x4

struct lb_net_device {
    struct ether_addr ha;

	uint16_t phy_portid;
	uint16_t kni_portid;

    /* Kni device IP info */
    uint32_t ip;
    uint32_t netmask;
    uint32_t gw;

    struct lb_local_ipv4_addr *local_ipaddrs_percore[RTE_MAX_LCORE];
    uint32_t local_ipaddr_count_percore[RTE_MAX_LCORE];

    /* Physical net device default config */
    uint16_t mtu; /* MTU */
    uint16_t ntuple_filter_support;
    uint32_t rx_offload_capa; /* Device RX offload capabilities. */
    uint32_t tx_offload_capa; /* Device TX offload capabilities. */
    uint16_t max_rx_queues;   /* Maximum number of RX queues. */
    uint16_t max_tx_queues;   /* Maximum number of TX queues. */
    uint16_t max_rx_desc;
    uint16_t max_tx_desc;

    /* User define */
    uint16_t nb_rx_queues; /* Number of RX queues. */
    uint16_t nb_tx_queues; /* Number of TX queues. */
    uint16_t nb_rx_desc;   /* The number of transmit descriptors to allocate for
                              the rx transmit ring. */
    uint16_t nb_tx_desc;   /* The number of transmit descriptors to allocate for
                                                          the tx transmit ring. */
    uint16_t tx_ol_flags;
    uint16_t link_status;

    /* lcore_id map to rx/tx queue_id */
    uint16_t lcore_to_rxq[RTE_MAX_LCORE];
    uint16_t lcore_to_txq[RTE_MAX_LCORE];

    /* Tx  packet buffer */
    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_LCORE];
    uint64_t tx_dropped[RTE_MAX_LCORE];
    uint64_t rx_dropped[RTE_MAX_LCORE];
};

extern struct rte_mempool *lb_pktmbuf_pool;
extern struct lb_net_device *lb_netdev;

#define IS_MYADDR 1
#define IS_BADADDR 2

static inline int
lb_netdev_chk_ipv4(uint32_t ip) {
    return lb_netdev->ip == ip ? IS_MYADDR : IS_BADADDR;
}

static inline int
ipv4_addr_netcmp(uint32_t addr1, uint32_t addr2, uint32_t netmask) {
    return ((addr1 & netmask) == (addr2 & netmask));
}

static inline int
lb_netdev_ipv4_route(uint32_t dip) {
    return ipv4_addr_netcmp(dip, lb_netdev->ip, lb_netdev->netmask)
               ? dip
               : lb_netdev->gw;
}

static inline int
lb_local_ipv4_addr_get(struct lb_local_ipv4_addr **addr, uint16_t *port,
                       enum lb_proto_type proto_type) {
    uint32_t lcore_id = rte_lcore_id();
    uint16_t num_addrs = lb_netdev->local_ipaddr_count_percore[lcore_id];
    struct lb_local_ipv4_addr *addrs =
        lb_netdev->local_ipaddrs_percore[lcore_id];
    uint16_t i;
    void *_port;
    struct rte_ring *ports;

    if (unlikely(proto_type > LB_PROTO_MAX)) {
        return -1;
    }
    for (i = 0; i < num_addrs; i++) {
        ports = addrs[i].ports[proto_type];
        if (rte_ring_sc_dequeue(ports, (void **)&_port) < 0) {
            continue;
        }
        *addr = &addrs[i];
        *port = (uint16_t)(uintptr_t)_port;
        return 0;
    }
    return -1;
}

static inline void
lb_local_ipv4_addr_put(struct lb_local_ipv4_addr *addr, uint16_t port,
                       enum lb_proto_type proto_type) {
    if (unlikely(proto_type >= LB_PROTO_MAX)) {
        return;
    }
    if (unlikely(!addr)) {
        return;
    }
    rte_ring_sp_enqueue(addr->ports[proto_type], (void *)(uintptr_t)port);
}

static inline void
lb_netdev_xmit_now(struct rte_mbuf *mbuf) {
    uint32_t lcore_id = rte_lcore_id();

    if (rte_eth_tx_buffer(0, lb_netdev->lcore_to_txq[lcore_id],
                          lb_netdev->tx_buffer[lcore_id], mbuf) == 0) {
        rte_eth_tx_buffer_flush(0, lb_netdev->lcore_to_txq[lcore_id],
                                lb_netdev->tx_buffer[lcore_id]);
    }
}

static inline void
lb_netdev_xmit(struct rte_mbuf *mbuf) {
    uint32_t lcore_id = rte_lcore_id();
    rte_eth_tx_buffer(0, lb_netdev->lcore_to_txq[lcore_id],
                      lb_netdev->tx_buffer[lcore_id], mbuf);
}

void lb_net_device_init(void);

#endif

