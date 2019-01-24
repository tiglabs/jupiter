/* Copyright (c) 2018. TIG developer. */

#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <unixctl_command.h>

#include "lb_device.h"
#include "lb_icmp.h"
#include "lb_ip_address.h"
#include "lb_mib.h"

static uint32_t
icmp_cksum(const struct ipv4_hdr *iph, const struct icmp_hdr *icmph) {
    uint16_t cksum;
    size_t len;

    len = rte_be_to_cpu_16(iph->total_length) - sizeof(struct ipv4_hdr);
    cksum = rte_raw_cksum(icmph, len);
    return (cksum == 0xffff) ? cksum : ~cksum;
}

void
lb_icmp_input(struct rte_mbuf *m, struct ipv4_hdr *iph, struct lb_device *dev) {
    struct icmp_hdr *icmph;
    uint32_t tmpaddr;

    if (!lb_device_vip_lip_is_exist_v4(dev, (ip4_address_t *)&iph->dst_addr)) {
        LB_MIB_INC_STATS(ICMP_IN_DEST_UNREACHABLE);
        lb_device_kni_xmit(dev, m);
        return;
    }
    icmph = (struct icmp_hdr *)(iph + 1);
    if (!((icmph->icmp_type == IP_ICMP_ECHO_REQUEST) &&
          (icmph->icmp_code == 0))) {
        rte_pktmbuf_free(m);
        LB_MIB_INC_STATS(ICMP_IN_ERRORS);
        return;
    }
    LB_MIB_INC_STATS(ICMP_IN_ECHO_REQUEST);
    tmpaddr = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = tmpaddr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    icmph->icmp_type = IP_ICMP_ECHO_REPLY;
    icmph->icmp_cksum = 0;
    icmph->icmp_cksum = icmp_cksum(iph, icmph);
    if (lb_device_ip4_output(m, (ip4_address_t *)&iph->dst_addr, dev) < 0)
        LB_MIB_INC_STATS(ICMP_OUT_ERRORS);
    else
        LB_MIB_INC_STATS(ICMP_OUT_ECHO_REPLY);
}
