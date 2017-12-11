/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_CONFIG_H__
#define __LB_CONFIG_H__

#include <stdint.h>

#define DPDK_ARG_MAX_NUM 32
#define PATH_LENGTH 256

struct dpdk_config {
    char *argv[DPDK_ARG_MAX_NUM];
    int argc;
};

struct tcp_config {
    uint32_t conn_max_num;
    uint32_t conn_expire_max_num;
    uint32_t conn_expire_period;
    uint32_t conn_timer_period;
};

struct udp_config {
    uint32_t conn_max_num;
    uint32_t conn_expire_max_num;
    uint32_t conn_expire_period;
    uint32_t conn_timer_period;
};

struct arp_config {
    uint32_t arp_max_num;
    uint32_t arp_expire_max_num;
    uint32_t arp_expire_period;
};

#define LOCAL_IP_MAX_COUNT 512

struct netdev_config {
    const char *name_prefix;
    uint8_t enable_tx_offload;
    uint8_t enable_bond;
    uint32_t bond_mode;
    uint16_t mbuf_num;
    uint16_t rxq_desc_num;
    uint16_t txq_desc_num;
    uint16_t l4_port_min;
    uint16_t l4_port_max;
    uint32_t local_ips[LOCAL_IP_MAX_COUNT];
    uint32_t local_ip_count;
    uint32_t kni_ip;
    uint32_t kni_netmask;
    uint32_t kni_gateway;
};

struct service_config {
    uint32_t vs_max_num;
    uint32_t cql_size;
};

struct lb_config {
    struct dpdk_config dpdk;
    struct service_config srv;
    struct tcp_config tcp;
    struct udp_config udp;
    struct arp_config arp;
    struct netdev_config netdev;
};

extern struct lb_config *lb_cfg;

void lb_config_load(const char *cfgfile_path, const char *proc_name);

#endif

