/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_ICMP6_H__
#define __LB_ICMP6_H__

void lb_icmp6_neigh_request(ip6_address_t *dip, struct lb_device *dev);
void lb_icmp6_input(struct rte_mbuf *m, struct ipv6_hdr *iph6, struct lb_device *dev);

#endif