/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_IP_NEIGHBOUR_H__
#define __LB_IP_NEIGHBOUR_H__

#include "lb_ip_address.h"

int lb_ip4_neighbour_is_exist(ip4_address_t *ip4);
int lb_ip6_neighbour_is_exist(ip6_address_t *ip6);
int lb_ip4_neighbour_update(ip4_address_t *ip4, struct ether_addr *ha);
int lb_ip6_neighbour_update(ip6_address_t *ip6, struct ether_addr *ha);
int lb_ip4_neighbour_create(ip4_address_t *ip4, struct ether_addr *ha);
int lb_ip6_neighbour_create(ip6_address_t *ip6, struct ether_addr *ha);
int lb_ip4_neighbour_lookup_ha(ip4_address_t *ip4, struct ether_addr *ha);
int lb_ip6_neighbour_lookup_ha(ip6_address_t *ip6, struct ether_addr *ha);
int lb_ip_neighbour_table_init(void);

#endif