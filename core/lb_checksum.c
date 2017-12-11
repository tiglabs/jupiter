/* Copyright (c) 2017. TIG developer. */

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "lb_checksum.h"
#include "lb_device.h"

#define IPV4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)
#define TCP_HLEN(th) (((th)->data_off & 0xf0) >> 2)

uint16_t
ipv4_cksum(struct ipv4_hdr *iph, struct rte_mbuf *mbuf) {
    if (!(lb_netdev->tx_ol_flags & LB_TX_OL_IPV4_CKSUM)) {
        uint16_t cksum;
        iph->hdr_checksum = 0;
        cksum = rte_raw_cksum(iph, IPV4_HLEN(iph));
        return (cksum == 0xffff) ? cksum : ~cksum;
    } else {
        mbuf->ol_flags |= PKT_TX_IPV4;
        mbuf->ol_flags |= PKT_TX_IP_CKSUM;
        mbuf->l2_len = sizeof(struct ether_hdr);
        mbuf->l3_len = IPV4_HLEN(iph);
        return 0;
    }
}

uint16_t
ipv4_tcp_cksum(struct ipv4_hdr *iph, struct tcp_hdr *th,
               struct rte_mbuf *mbuf) {
    if (!(lb_netdev->tx_ol_flags & LB_TX_OL_TCP_CKSUM)) {
        th->cksum = 0;
        return rte_ipv4_udptcp_cksum(iph, th);
    } else {
        mbuf->ol_flags |= PKT_TX_IPV4;
        mbuf->ol_flags |= PKT_TX_TCP_CKSUM;
        mbuf->l2_len = sizeof(struct ether_hdr);
        mbuf->l3_len = IPV4_HLEN(iph);
        mbuf->l4_len = TCP_HLEN(th);
        return rte_ipv4_phdr_cksum(iph, 0);
    }
}

uint16_t
ipv4_udp_cksum(struct ipv4_hdr *iph, struct udp_hdr *uh,
               struct rte_mbuf *mbuf) {
    if (!(lb_netdev->tx_ol_flags & LB_TX_OL_UDP_CKSUM)) {
        uh->dgram_cksum = 0;
        return rte_ipv4_udptcp_cksum(iph, uh);
    } else {
        mbuf->ol_flags |= PKT_TX_IPV4;
        mbuf->ol_flags |= PKT_TX_UDP_CKSUM;
        mbuf->l2_len = sizeof(struct ether_hdr);
        mbuf->l3_len = IPV4_HLEN(iph);
        mbuf->l4_len = sizeof(struct udp_hdr);
        return rte_ipv4_phdr_cksum(iph, 0);
    }
}

uint16_t
icmp_checksum(void *buffer, size_t len) {
    uint16_t cksum;

    cksum = rte_raw_cksum(buffer, len);
    return (cksum == 0xffff) ? cksum : ~cksum;
}

