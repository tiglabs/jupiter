/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_PROTO_UDP_H__
#define __LB_PROTO_UDP_H__

#include "lb_connection.h"

int lb_udp_fullnat_handle(struct rte_mbuf *mbuf, struct ipv4_hdr *iph);
void lb_proto_udp_init(void);
struct lb_connection_table *lb_udp_connection_table_get(void);

#endif

