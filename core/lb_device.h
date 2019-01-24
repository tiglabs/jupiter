/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_DEVICE_H__
#define __LB_DEVICE_H__

#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

#include "lb_config.h"
#include "lb_ip_address.h"

enum {
    LB_DEV_OUTBOUND,
    LB_DEV_INBOUND,
    LB_DEV_NUM,
};

struct lb_device {
    uint16_t port_id;
    ip4_address_t ip4;
    ip4_address_t ip4_gw;
    ip4_address_t ip4_netmask;
    ip6_address_t ip6;
    ip6_address_t ip6_gw;
    ip6_address_t ip6_netmask;

    struct ether_addr ha;

    rte_spinlock_t txq_lock;
    struct rte_eth_dev_tx_buffer *tx_buffers[RTE_MAX_QUEUES_PER_PORT];

    rte_spinlock_t kni_lock;
    struct rte_kni *kni;
    char name[RTE_KNI_NAMESIZE];

    struct rte_ring *pkt_dispatch_queues[RTE_MAX_LCORE];
    struct rte_hash *vip_lip_hash;

    struct {
        uint64_t rx_dropped;
        uint64_t tx_dropped;
    } lcore_stats[RTE_MAX_LCORE];
};

extern struct lb_device *lb_devices[LB_DEV_NUM];
extern struct rte_mempool *pktmbuf_pool;

static inline struct lb_device *
lb_device_get_inbound(void) {
    return lb_devices[LB_DEV_INBOUND];
}

static inline struct lb_device *
lb_device_get_outbound(void) {
    return lb_devices[LB_DEV_OUTBOUND];
}

static inline struct rte_mbuf *
lb_pktmbuf_alloc(void) {
    return rte_pktmbuf_alloc(pktmbuf_pool);
}

static inline void
lb_device_pkt_dispatch_enqueue(struct lb_device *dev, struct rte_mbuf *pkt,
                               uint32_t lcore_id) {
    if (rte_ring_enqueue(dev->pkt_dispatch_queues[lcore_id], pkt) < 0) {
        rte_pktmbuf_free(pkt);
    }
}

static inline uint16_t
lb_device_pkt_dispatch_dequeue(struct lb_device *dev, struct rte_mbuf *pkt[],
                               uint16_t num, uint32_t lcore_id) {
    return rte_ring_dequeue_burst(dev->pkt_dispatch_queues[lcore_id],
                                  (void **)pkt, num, NULL);
}

int lb_device_module_init(struct lb_conf *lb_cfg);

void lb_device_xmit_burst(struct lb_device *dev, struct rte_mbuf **pkts,
                          uint32_t num);
void lb_device_xmit(struct lb_device *dev, struct rte_mbuf *m);
void lb_device_flush(struct lb_device *dev);
uint16_t lb_device_rx_burst(struct lb_device *dev, struct rte_mbuf **pkts,
                            uint16_t num);
void lb_device_kni_rx_handle(struct lb_device *dev);
void lb_device_kni_xmit(struct lb_device *dev, struct rte_mbuf *m);

int lb_device_ip4_output(struct rte_mbuf *m, ip4_address_t *dst_addr,
                         struct lb_device *dev);
int lb_device_ip6_output(struct rte_mbuf *m, ip6_address_t *dst_addr,
                         struct lb_device *dev);

int lb_device_add_vip_lip(struct lb_device *dev, ip46_address_t *ip46);
void lb_device_del_vip_lip(struct lb_device *dev, ip46_address_t *ip46);
int lb_device_vip_lip_is_exist_v4(struct lb_device *dev, ip4_address_t *ip4);
int lb_device_vip_lip_is_exist_v6(struct lb_device *dev, ip6_address_t *ip6);

static inline void
lb_inbound_device_ip4_output(struct rte_mbuf *m, ip4_address_t *dst_addr) {
    lb_device_ip4_output(m, dst_addr, lb_device_get_inbound());
}

static inline void
lb_outbound_device_ip4_output(struct rte_mbuf *m, ip4_address_t *dst_addr) {
    lb_device_ip4_output(m, dst_addr, lb_device_get_outbound());
}

static inline void
lb_inbound_device_ip6_output(struct rte_mbuf *m, ip6_address_t *dst_addr) {
    lb_device_ip6_output(m, dst_addr, lb_device_get_inbound());
}

static inline void
lb_outbound_device_ip6_output(struct rte_mbuf *m, ip6_address_t *dst_addr) {
    lb_device_ip6_output(m, dst_addr, lb_device_get_outbound());
}

#endif