/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_PROTO_ICMP_H__
#define __LB_PROTO_ICMP_H__

int lb_icmp_fullnat_handle(struct rte_mbuf *mbuf, struct ipv4_hdr *iph);
void lb_proto_icmp_init(void);

#endif

