/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_CONFIG_H__
#define __LB_CONFIG_H__

#include <rte_kni.h>
#include <rte_pci.h>

#include "lb_ip_address.h"

#define LB_MAX_LADDR 256

struct lb_device_conf {
    char name[RTE_KNI_NAMESIZE];
    ip4_address_t ip4;
    ip4_address_t ip4_gw;
    ip4_address_t ip4_netmask;
    uint16_t ip4_prefix;
    ip6_address_t ip6;
    ip6_address_t ip6_gw;
    ip6_address_t ip6_netmask;
    uint16_t ip6_prefix;

    uint32_t nb_fnat_laddr_v4;
    uint32_t nb_fnat_laddr_v6;
    ip4_address_t fnat_laddrs_v4[LB_MAX_LADDR];
    ip6_address_t fnat_laddrs_v6[LB_MAX_LADDR];
    uint16_t nb_pcis;
    struct rte_pci_addr pcis[RTE_MAX_ETHPORTS];
};

#define LB_MAX_DPDK_ARGS 128

struct lb_dpdk_conf {
    char *argv[LB_MAX_DPDK_ARGS];
    int argc;
};

struct lb_conf {
    struct lb_device_conf inbound;
    struct lb_device_conf outbound;
    struct lb_dpdk_conf dpdk;
};

extern struct lb_conf *lb_cfg;

int lb_config_file_load(const char *cfgfile_path);
void lb_config_print(void);

#endif
