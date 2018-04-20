/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_CONFIG_H__
#define __LB_CONFIG_H__

#include <rte_kni.h>
#include <rte_pci.h>

#define LB_MAX_LADDR 256

struct lb_device_conf {
    char name[RTE_KNI_NAMESIZE];
    uint32_t mode;
    uint32_t ipv4;
    uint32_t netmask;
    uint32_t gw;
    uint16_t rxqsize, txqsize;
    uint16_t mtu;
    uint32_t rxoffload;
    uint32_t txoffload;
    uint32_t nb_lips;
    uint32_t lips[LB_MAX_LADDR];
    uint16_t nb_pcis;
    struct rte_pci_addr pcis[RTE_MAX_ETHPORTS];
};

#define LB_MAX_DPDK_ARGS 128

struct lb_dpdk_conf {
    char *argv[LB_MAX_DPDK_ARGS];
    int argc;
};

struct lb_conf {
    struct lb_device_conf devices[RTE_MAX_ETHPORTS];
    uint16_t nb_decices;
    struct lb_dpdk_conf dpdk;
};

extern struct lb_conf *lb_cfg;

int lb_config_file_load(const char *cfgfile_path);

#endif

