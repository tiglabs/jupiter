/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_FNAT_LADDR_H__
#define __LB_FNAT_LADDR_H__

#include "lb.h"
#include "lb_ip_address.h"

struct lb_fnat_laddr {
    LIST_ENTRY(lb_fnat_laddr) next;
    ip46_address_t ip46;
    struct rte_ring *ports[LB_PROTO_MAX];
};

extern int lb_fnat_laddrs_num;

int lb_fnat_laddr_and_port_get(lb_proto_t proto, int is_ip4,
                               struct lb_fnat_laddr **fnat_laddr,
                               uint16_t *port);
void lb_fnat_laddr_and_port_put(lb_proto_t proto,
                                struct lb_fnat_laddr *fnat_laddr,
                                uint16_t port);
int lb_fnat_laddr_add_ip4(ip4_address_t *ip4);
int lb_fnat_laddr_add_ip6(ip6_address_t *ip6);

#endif