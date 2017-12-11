/* Copyright (c) 2017. TIG developer. */

#include <stdint.h>
#include <stdio.h>

#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "lb_arp.h"
#include "lb_checksum.h"
#include "lb_device.h"
#include "lb_proto_icmp.h"
#include "lb_service.h"
#include "unixctl_command.h"

struct icmp_stats {
    uint64_t rx;
    uint64_t rx_drop;
    uint64_t tx;
    uint64_t tx_drop;
};

static struct icmp_stats *stats;

#define ICMP_STATS_INC(name)                                                   \
    do {                                                                       \
        stats[rte_lcore_id()].name++;                                          \
    } while (0)

#define IPV4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)

int
lb_icmp_fullnat_handle(struct rte_mbuf *mbuf, struct ipv4_hdr *iph) {
    struct icmp_hdr *icmph;
    uint32_t ip_addr;
    uint16_t l4_len;

    if (rte_ipv4_frag_pkt_is_fragmented(iph)) {
        ICMP_STATS_INC(rx_drop);
        return -1;
    }

    if (!lb_is_vip_exist(iph->dst_addr)) {
        ICMP_STATS_INC(rx_drop);
        return -1;
    }

    /*
    * Check if packet is a ICMP echo request.
    */
    icmph = (struct icmp_hdr *)((char *)iph + IPV4_HLEN(iph));
    if (!((icmph->icmp_type == IP_ICMP_ECHO_REQUEST) &&
          (icmph->icmp_code == 0))) {
        ICMP_STATS_INC(rx_drop);
        return -1;
    }

    ip_addr = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = ip_addr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    icmph->icmp_type = IP_ICMP_ECHO_REPLY;
    l4_len = rte_be_to_cpu_16(iph->total_length) - sizeof(struct ipv4_hdr);
    icmph->icmp_cksum = 0;
    icmph->icmp_cksum = icmp_checksum(icmph, l4_len);

    ICMP_STATS_INC(rx);
    if (lb_ether_build_header(mbuf, rte_pktmbuf_mtod(mbuf, struct ether_hdr *),
                              iph->dst_addr) < 0) {
        ICMP_STATS_INC(tx_drop);
        return -1;
    }
    lb_netdev_xmit(mbuf);
    ICMP_STATS_INC(tx);
    return 0;
}

static void
icmp_stats_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                  __attribute__((unused)) int argc) {
    unsigned lcore_id;
    uint64_t rx = 0, tx = 0, rx_drop = 0, tx_drop = 0;

    RTE_LCORE_FOREACH(lcore_id) {
        rx += stats[lcore_id].rx;
        tx += stats[lcore_id].tx;
        rx_drop += stats[lcore_id].rx_drop;
        tx_drop += stats[lcore_id].tx_drop;
    }
    unixctl_command_reply(fd, "icmp-rx: %" PRIu64 "\n"
                              "icmp-rx-drop: %" PRIu64 "\n"
                              "icmp-tx: %" PRIu64 "\n"
                              "icmp-tx-drop: %" PRIu64 "\n",
                          rx, rx_drop, tx, tx_drop);
}

void
lb_proto_icmp_init(void) {
    stats = rte_calloc(NULL, RTE_MAX_LCORE, sizeof(struct icmp_stats), 0);
    if (stats == NULL)
        rte_panic("Cannot alloc memory for ICMP stats.\n");

    unixctl_command_register("icmp/stats", "", "Show ICMP packet statistics.",
                             0, 0, icmp_stats_cmd_cb);
}

