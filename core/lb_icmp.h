/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_ICMP_H__
#define __LB_ICMP_H__

void lb_icmp_input(struct rte_mbuf *m, struct ipv4_hdr *iph, struct lb_device *dev);

#endif