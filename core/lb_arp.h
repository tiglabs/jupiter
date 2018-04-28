/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_ARP_H__
#define __LB_ARP_H__

struct rte_mbuf;
struct lb_device;

int lb_arp_init(void);
int lb_arp_request(uint32_t dip, struct lb_device *dev);
void lb_arp_input(struct rte_mbuf *pkt, struct lb_device *dev);
int lb_arp_find(uint32_t ip, struct ether_addr *mac, struct lb_device *dev);

#endif

