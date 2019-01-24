/* Copyright (c) 2018. TIG developer. */
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "lb.h"
#include "lb_arp.h"
#include "lb_device.h"
#include "lb_ip_address.h"
#include "lb_ip_neighbour.h"
#include "lb_mib.h"

void
lb_arp_input(struct rte_mbuf *pkt, struct ether_hdr *eth,
             struct lb_device *dev) {
    struct arp_hdr *arph;
    ip4_address_t ip4;

    arph = (struct arp_hdr *)(eth + 1);
    ip4.as_u32 = arph->arp_data.arp_sip;
    if (lb_ip4_neighbour_is_exist(&ip4)) {
        lb_ip4_neighbour_update(&ip4, &arph->arp_data.arp_sha);
    } else {
        lb_ip4_neighbour_create(&ip4, &arph->arp_data.arp_sha);
    }
    lb_device_kni_xmit(dev, pkt);
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

    if (!(m = lb_pktmbuf_alloc())) {
        LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
        return -1;
    }

    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_addr_copy(src_ha, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

    if (dst_ha != NULL)
        ether_addr_copy(dst_ha, &eth->d_addr);
    else
        ether_addr_copy(&bc_ha, &eth->d_addr);

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

    lb_device_xmit(dev, m);
    return 0;
}

int
lb_arp_request(ip4_address_t *dip, struct lb_device *dev) {
    return arp_send(ARP_OP_REQUEST, dip->as_u32, dev->ip4.as_u32, NULL,
                    &dev->ha, dev);
}
