/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_ARP_H__
#define __LB_ARP_H__

#include "lb_device.h"
#include "lb_ip_address.h"

int lb_arp_request(ip4_address_t *dip, struct lb_device *dev);
void lb_arp_input(struct rte_mbuf *pkt, struct ether_hdr *eth,
                  struct lb_device *dev);

#endif
