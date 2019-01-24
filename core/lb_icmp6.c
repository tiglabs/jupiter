/* Copyright (c) 2018. TIG developer. */

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "lb.h"
#include "lb_device.h"
#include "lb_icmp6.h"
#include "lb_ip_address.h"
#include "lb_ip_neighbour.h"
#include "lb_mib.h"

struct icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t identifier;
            uint16_t sequence;
        } echo;
        struct {
            uint32_t reserved;
        } neigh_soli;
        struct {
            uint32_t router : 1;
            uint32_t solicited : 1;
            uint32_t override : 1;
            uint32_t reserved : 29;
        } neigh_advt;
    };
} __rte_packed;

#define LB_ICMPV6_ECHO_REQUEST 128
#define LB_ICMPV6_ECHO_REPLY 129

#define LB_ICMPV6_NEIGHBOUR_SOLICITATION 135
#define LB_ICMPV6_NEIGHBOUR_ADVERTISEMENT 136

struct link_layer_addr_opt {
    uint8_t type;
    uint8_t length;
    struct ether_addr addr;
} __rte_packed;

static uint32_t
icmp6_cksum(const struct ipv6_hdr *iph6, const struct icmp6_hdr *icmp6hdr) {
    // uint16_t cksum;

    // cksum = rte_raw_cksum(icmp6hdr, rte_be_to_cpu_16(iph6->payload_len));
    // return ~cksum;
    return rte_ipv6_udptcp_cksum(iph6, icmp6hdr);
}

static void
icmp6_neighbour_solicitation(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                             struct icmp6_hdr *icmp6hdr) {
    uint16_t offset;
    struct link_layer_addr_opt *opt;

    if (icmp6hdr->type != LB_ICMPV6_NEIGHBOUR_SOLICITATION ||
        icmp6hdr->code != 0)
        return;
    offset = sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) +
             sizeof(struct icmp6_hdr) + sizeof(ip6_address_t);
    opt = rte_pktmbuf_mtod_offset(m, struct link_layer_addr_opt *, offset);
    /**
     * RFC4681
     * Type: 1 for Source Link-layer Address, 2 for Target Link-layer Address
     * Length: The length of the option (including the type and length fields)
     * in units of 8 octets
     */
    if (opt->type != 1 && opt->length != 1)
        return;
    if (lb_ip6_neighbour_is_exist((ip6_address_t *)iph6->src_addr)) {
        lb_ip6_neighbour_update((ip6_address_t *)iph6->src_addr, &opt->addr);
    } else {
        lb_ip6_neighbour_create((ip6_address_t *)iph6->src_addr, &opt->addr);
    }
}

static void
icmp6_neighbour_advertisement(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                              struct icmp6_hdr *icmp6hdr) {
    uint16_t offset;
    struct link_layer_addr_opt *opt;

    if (icmp6hdr->type != LB_ICMPV6_NEIGHBOUR_ADVERTISEMENT ||
        icmp6hdr->code != 0)
        return;
    if (!icmp6hdr->neigh_advt.solicited)
        return;
    offset = sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) +
             sizeof(struct icmp6_hdr) + sizeof(ip6_address_t);
    if (rte_pktmbuf_data_len(m) < offset)
        return;
    opt = rte_pktmbuf_mtod_offset(m, struct link_layer_addr_opt *, offset);
    if (opt->type != 2 && opt->length != 1)
        return;
    if (lb_ip6_neighbour_is_exist((ip6_address_t *)iph6->src_addr)) {
        lb_ip6_neighbour_update((ip6_address_t *)iph6->src_addr, &opt->addr);
    } else {
        lb_ip6_neighbour_create((ip6_address_t *)iph6->src_addr, &opt->addr);
    }
}

static void
icmp6_echo_input(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                 struct lb_device *dev) {
    struct icmp6_hdr *icmp6hdr;
    ip6_address_t tmp;

    if (!lb_device_vip_lip_is_exist_v6(dev, (ip6_address_t *)&iph6->dst_addr)) {
        LB_MIB_INC_STATS(ICMP6_IN_DEST_UNREACHABLE);
        lb_device_kni_xmit(dev, m);
        return;
    }

    icmp6hdr = (struct icmp6_hdr *)(iph6 + 1);
    if (icmp6hdr->type != LB_ICMPV6_ECHO_REQUEST || icmp6hdr->code != 0) {
        rte_pktmbuf_free(m);
        LB_MIB_INC_STATS(ICMP6_IN_ERRORS);
        return;
    }
    LB_MIB_INC_STATS(ICMP6_IN_ECHO_REQUEST);
    ip6_address_copy(&tmp, (ip6_address_t *)iph6->src_addr);
    ip6_address_copy((ip6_address_t *)iph6->src_addr,
                     (ip6_address_t *)iph6->dst_addr);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &tmp);
    iph6->hop_limits = 255;
    icmp6hdr->type = LB_ICMPV6_ECHO_REPLY;
    icmp6hdr->checksum = 0;
    icmp6hdr->checksum = icmp6_cksum(iph6, icmp6hdr);
    if (lb_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr, dev) < 0)
        LB_MIB_INC_STATS(ICMP6_OUT_ERRORS);
    else
        LB_MIB_INC_STATS(ICMP6_OUT_ECHO_REPLY);
}

void
lb_icmp6_input(struct rte_mbuf *m, struct ipv6_hdr *iph6,
               struct lb_device *dev) {
    struct icmp6_hdr *icmp6hdr;

    icmp6hdr = (struct icmp6_hdr *)(iph6 + 1);
    switch (icmp6hdr->type) {
    case LB_ICMPV6_NEIGHBOUR_SOLICITATION:
        icmp6_neighbour_solicitation(m, iph6, icmp6hdr);
        lb_device_kni_xmit(dev, m);
        break;
    case LB_ICMPV6_NEIGHBOUR_ADVERTISEMENT:
        icmp6_neighbour_advertisement(m, iph6, icmp6hdr);
        lb_device_kni_xmit(dev, m);
        break;
    case LB_ICMPV6_ECHO_REQUEST:
        icmp6_echo_input(m, iph6, dev);
        break;
    default:
        lb_device_kni_xmit(dev, m);
    }
}

void
lb_icmp6_neigh_request(ip6_address_t *dip, struct lb_device *dev) {
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv6_hdr *iph6;
    struct icmp6_hdr *icmp6hdr;
    ip6_address_t *target_addr;
    struct link_layer_addr_opt *opt;

    if (!(m = lb_pktmbuf_alloc())) {
        LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
        return;
    }

    eth = (struct ether_hdr *)rte_pktmbuf_append(m, sizeof(struct ether_hdr));
    RTE_ASSERT(eth != NULL);
    /* rfc2464 */
    eth->d_addr.addr_bytes[0] = 0x33;
    eth->d_addr.addr_bytes[1] = 0x33;
    eth->d_addr.addr_bytes[2] = 0xff;
    eth->d_addr.addr_bytes[3] = dip->as_u8[13];
    eth->d_addr.addr_bytes[4] = dip->as_u8[14];
    eth->d_addr.addr_bytes[5] = dip->as_u8[15];
    ether_addr_copy(&dev->ha, &eth->s_addr);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

    iph6 = (struct ipv6_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv6_hdr));
    RTE_ASSERT(iph6 != NULL);
    iph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
    iph6->payload_len =
        rte_cpu_to_be_16(sizeof(struct icmp6_hdr) + sizeof(ip6_address_t) +
                         sizeof(struct link_layer_addr_opt));
    iph6->proto = IPPROTO_ICMPV6;
    iph6->hop_limits = 255;
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &dev->ip6);
    /* rfc4291 - Solicited-Node Address */
    iph6->dst_addr[0] = 0xff;
    iph6->dst_addr[1] = 0x02;
    iph6->dst_addr[2] = 0;
    iph6->dst_addr[3] = 0;
    iph6->dst_addr[4] = 0;
    iph6->dst_addr[5] = 0;
    iph6->dst_addr[6] = 0;
    iph6->dst_addr[7] = 0;
    iph6->dst_addr[8] = 0;
    iph6->dst_addr[9] = 0;
    iph6->dst_addr[10] = 0;
    iph6->dst_addr[11] = 0x01;
    iph6->dst_addr[12] = 0xff;
    iph6->dst_addr[13] = dip->as_u8[13];
    iph6->dst_addr[14] = dip->as_u8[14];
    iph6->dst_addr[15] = dip->as_u8[15];

    icmp6hdr =
        (struct icmp6_hdr *)rte_pktmbuf_append(m, sizeof(struct icmp6_hdr));
    RTE_ASSERT(icmp6hdr != NULL);
    icmp6hdr->type = LB_ICMPV6_NEIGHBOUR_SOLICITATION;
    icmp6hdr->code = 0;
    icmp6hdr->neigh_soli.reserved = 0;

    target_addr = (ip6_address_t *)rte_pktmbuf_append(m, sizeof(ip6_address_t));
    RTE_ASSERT(target_addr != NULL);
    ip6_address_copy(target_addr, dip);

    opt = (struct link_layer_addr_opt *)rte_pktmbuf_append(
        m, sizeof(struct link_layer_addr_opt));
    RTE_ASSERT(opt != NULL);
    opt->type = 1;
    opt->length = 1;
    ether_addr_copy(&dev->ha, &opt->addr);

    icmp6hdr->checksum = 0;
    icmp6hdr->checksum = icmp6_cksum(iph6, icmp6hdr);

    lb_device_xmit(dev, m);
}