/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_TOA_H__
#define __LB_TOA_H__

void tcp_opt_add_toa(struct rte_mbuf *m, struct ipv4_hdr *iph,
                     struct tcp_hdr *th, uint32_t sip, uint16_t sport);

#endif

