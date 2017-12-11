/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_ARP_H__
#define __LB_ARP_H__

#include <rte_ether.h>
#include <rte_mbuf.h>

#include "lb_device.h"

int lb_arp_find(uint32_t dst_ip, struct ether_addr *dst_ha,
                struct rte_mbuf *pkt);
void lb_arp_packet_recv(struct rte_mbuf *mbuf);
void lb_arp_table_init(void);

static inline int
lb_ether_build_header(struct rte_mbuf *mbuf, struct ether_hdr *ethh,
                      uint32_t dip) {
    uint32_t rt_ip;

    ethh->ether_type = rte_cpu_to_be_16(0x0800);
    ether_addr_copy(&lb_netdev->ha, &ethh->s_addr);
    /* route */
    rt_ip = lb_netdev_ipv4_route(dip);
    if (!rt_ip) {
        rte_pktmbuf_free(mbuf);
        return -1;
    }
    return lb_arp_find(rt_ip, &ethh->d_addr, mbuf);
}

#endif /* __LB_ARP_H__ */

