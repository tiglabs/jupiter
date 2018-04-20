/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_ARP_H__
#define __LB_ARP_H__

struct rte_mbuf;

int lb_arp_init(void);
int lb_arp_request(uint32_t dip, uint16_t port_id);
void lb_arp_input(struct rte_mbuf *pkt, uint16_t port_id);
int lb_arp_find(uint32_t ip, struct ether_addr *mac, uint16_t port_id);

#endif

