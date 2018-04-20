/* Copyright (c) 2018. TIG developer. */

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

#include "lb_toa.h"

#define TCPOPT_ADDR 200
#define TCPOLEN_ADDR 8 /* |opcode|size|ip+port| = 1 + 1 + 6 */

struct tcp_opt_toa {
    uint8_t optcode;
    uint8_t optsize;
    uint16_t port;
    uint32_t addr;
} __attribute__((__packed__));

void
tcp_opt_add_toa(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *th,
                uint32_t sip, uint16_t sport) {
    struct tcp_opt_toa *toa;
    uint8_t *p, *q;

    /* tcp header max length */
    if ((60 - (th->data_off >> 2)) < (int)sizeof(struct tcp_opt_toa))
        return;
    p = (uint8_t *)rte_pktmbuf_append(m, sizeof(struct tcp_opt_toa));
    q = p + sizeof(struct tcp_opt_toa);
    while (p >= ((uint8_t *)th + (th->data_off >> 2))) {
        *q = *p;
        q--;
        p--;
    }
    toa = (struct tcp_opt_toa *)((uint8_t *)th + (th->data_off >> 2));
    toa->optcode = TCPOPT_ADDR;
    toa->optsize = TCPOLEN_ADDR;
    toa->port = sport;
    toa->addr = sip;
    th->data_off += (sizeof(struct tcp_opt_toa) / 4) << 4;
    iph->total_length = rte_cpu_to_be_16(rte_be_to_cpu_16(iph->total_length) +
                                         sizeof(struct tcp_opt_toa));
}

