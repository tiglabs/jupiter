/* Copyright (c) 2018. TIG developer. */

#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>

#include "lb_device.h"
#include "lb_proto.h"
#include "lb_service.h"

static uint32_t
icmp_cksum(const struct ipv4_hdr *iph, const struct icmp_hdr *icmph) {
    uint16_t cksum;
    size_t len;

    len = rte_be_to_cpu_16(iph->total_length) - sizeof(struct ipv4_hdr);
    cksum = rte_raw_cksum(icmph, len);
    return (cksum == 0xffff) ? cksum : ~cksum;
}

static int
icmp_fullnat_handle(struct rte_mbuf *m, struct ipv4_hdr *iph,
                    struct lb_device *dev) {
    struct icmp_hdr *icmph;
    uint32_t tmpaddr;

    if (rte_ipv4_frag_pkt_is_fragmented(iph)) {
        rte_pktmbuf_free(m);
        return 0;
    }

    if (!lb_is_vip_exist(iph->dst_addr) &&
        !lb_is_laddr_exist(iph->dst_addr, dev)) {
        rte_pktmbuf_free(m);
        return 0;
    }

    icmph = (struct icmp_hdr *)((char *)iph + IPv4_HLEN(iph));
    if (!((icmph->icmp_type == IP_ICMP_ECHO_REQUEST) &&
          (icmph->icmp_code == 0))) {
        rte_pktmbuf_free(m);
        return 0;
    }

    tmpaddr = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = tmpaddr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    icmph->icmp_type = IP_ICMP_ECHO_REPLY;
    icmph->icmp_cksum = 0;
    icmph->icmp_cksum = icmp_cksum(iph, icmph);

    return lb_device_output(m, iph, dev);
}

static int
icmp_init(void) {
    return 0;
}

static struct lb_proto proto_icmp = {
    .id = IPPROTO_ICMP,
    .type = LB_IPPROTO_ICMP,
    .init = icmp_init,
    .fullnat_handle = icmp_fullnat_handle,
};

LB_PROTO_REGISTER(proto_icmp);
