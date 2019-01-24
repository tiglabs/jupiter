/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_UDP_H__
#define __LB_UDP_H__

void lb_udp_input(struct rte_mbuf *m, void *iphdr, uint8_t is_ip4);
int lb_udp_module_init(void);

#endif