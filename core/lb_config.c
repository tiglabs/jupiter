/* Copyright (c) 2017. TIG developer. */

#include <stdlib.h>
#include <string.h>

#include <rte_cfgfile.h>

#include "lb_config.h"
#include "parser.h"
#include "unixctl_command.h"

struct lb_config *lb_cfg;

static void
tcp_config_reset(struct tcp_config *cfg) {
    cfg->conn_max_num = 2500000;
    cfg->conn_expire_period = 180;
    cfg->conn_timer_period = 1;
    cfg->conn_expire_max_num = 100;
}

static void
tcp_config_init(struct rte_cfgfile *cfgfile, struct tcp_config *cfg) {
    const char *entry;

    /* TCP */
    entry = rte_cfgfile_get_entry(cfgfile, "TCP", "conn-max-num");
    if (entry && parser_read_uint32(&cfg->conn_max_num, entry) < 0) {
        printf("Cannot read option TCP/conn-max-num, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "TCP", "conn-expire-period");
    if (entry && parser_read_uint32(&cfg->conn_expire_period, entry) < 0) {
        printf("Cannot read option TCP/conn-expire-period, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "TCP", "conn-timer-period");
    if (entry && parser_read_uint32(&cfg->conn_timer_period, entry) < 0) {
        printf("Cannot read option TCP/conn-timer-period, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "TCP", "conn-expire-max-num");
    if (entry && parser_read_uint32(&cfg->conn_expire_max_num, entry) < 0) {
        printf("Cannot read option TCP/conn-expire-max-num, %s.\n", entry);
        exit(-1);
    }
}

static void
tcp_config_show(int fd) {
    /* tcp */
    unixctl_command_reply(
        fd, "tcp/conn-max-num: %u\n"
            "tcp/conn-expire-period: %u\n"
            "tcp/conn-timer-period: %u\n"
            "tcp/conn-expire-max-num: %u\n",
        lb_cfg->tcp.conn_max_num, lb_cfg->tcp.conn_expire_period,
        lb_cfg->tcp.conn_timer_period, lb_cfg->tcp.conn_expire_max_num);
}

static void
udp_config_reset(struct udp_config *cfg) {
    cfg->conn_max_num = 2500000;
    cfg->conn_expire_period = 180;
    cfg->conn_timer_period = 1;
    cfg->conn_expire_max_num = 100;
}

static void
udp_config_init(struct rte_cfgfile *cfgfile, struct udp_config *cfg) {
    const char *entry;

    /* TCP */
    entry = rte_cfgfile_get_entry(cfgfile, "UDP", "conn-max-num");
    if (entry && parser_read_uint32(&cfg->conn_max_num, entry) < 0) {
        printf("Cannot read option UDP/conn-max-num, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "UDP", "conn-expire-period");
    if (entry && parser_read_uint32(&cfg->conn_expire_period, entry) < 0) {
        printf("Cannot read option UDP/conn-expire-period, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "UDP", "conn-timer-period");
    if (entry && parser_read_uint32(&cfg->conn_timer_period, entry) < 0) {
        printf("Cannot read option UDP/conn-timer-period, %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "UDP", "conn-expire-max-num");
    if (entry && parser_read_uint32(&cfg->conn_expire_max_num, entry) < 0) {
        printf("Cannot read option UDP/conn-expire-max-num, %s.\n", entry);
        exit(-1);
    }
}

static void
udp_config_show(int fd) {
    /* udp */
    unixctl_command_reply(
        fd, "udp/conn-max-num: %u\n"
            "udp/conn-expire-period: %u\n"
            "udp/conn-timer-period: %u\n"
            "udp/conn-expire-max-num: %u\n",
        lb_cfg->udp.conn_max_num, lb_cfg->udp.conn_expire_period,
        lb_cfg->udp.conn_timer_period, lb_cfg->udp.conn_expire_max_num);
}

static void
dpdk_config_init(struct rte_cfgfile *cfgfile, struct dpdk_config *cfg,
                 const char *proc_name) {
    const char *entry;
    char buffer[128];

    /* proc name */
    cfg->argv[cfg->argc++] = strdup(proc_name);

    /* EAL */
    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "cores");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "-l%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/cores options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "memory");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--socket-mem=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/memory options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "mem-channels");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "-n%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/mem-channels options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "hugefile-prefix");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--file-prefix=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "log-level");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--log-level=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "syslog");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--syslog=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "pci-whitelist");
    if (entry) {
        char *p;
        char *str = strdup(entry);

        p = strtok(str, " ,");
        while (p != NULL) {
            snprintf(buffer, sizeof(buffer), "-w%s", p);
            cfg->argv[cfg->argc++] = strdup(buffer);
            p = strtok(NULL, " ,");
        }
        free(str);
    }
}

static void
dpdk_config_show(int fd) {
    int i;

    /* dpdk args */
    unixctl_command_reply(fd, "dpdk-args: ");
    for (i = 0; i < lb_cfg->dpdk.argc; i++) {
        unixctl_command_reply(fd, "%s ", lb_cfg->dpdk.argv[i]);
    }
    unixctl_command_reply(fd, "\n");
}

static void
netdev_config_reset(struct netdev_config *cfg) {
    cfg->name_prefix = "jupiter";
    cfg->enable_tx_offload = 0;
    cfg->mbuf_num = 0;
    cfg->rxq_desc_num = 2048;
    cfg->txq_desc_num = 4096;
    cfg->l4_port_min = 1024;
    cfg->l4_port_max = 65535;
}

#define IPV4_ADDR(a, b, c, d)                                                  \
    (((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff))

static int
__parse_ip_address_list(const char *addr_list, uint32_t addrs[],
                        uint16_t addr_max_count) {
    char *str;
    char *p, *q;
    uint32_t addr;
    uint16_t count = 0;

    str = strdup(addr_list);
    if (!str) {
        return -1;
    }
    p = strtok(str, " ,");
    while (p != NULL) {
        q = strchr(p, '-');
        if (!q) {
            if (parse_ipv4_addr(p, (struct in_addr *)&addr) < 0) {
                return -1;
            }
            if (count >= addr_max_count) {
                return -1;
            }
            addrs[count++] = addr;
        } else {
            uint8_t addr_a[5];
            uint16_t i;
            uint64_t val;

            for (i = 0; i < sizeof(addr_a); i++) {
                val = strtoul(p, &q, 0);
                if (p == q) {
                    return -1;
                }
                if (val >= 255) {
                    return -1;
                }
                addr_a[i] = val;
                if (q == '\0') {
                    break;
                }
                q++;
                p = q;
            }
            if (i != sizeof(addr_a)) {
                return -1;
            }
            for (; addr_a[3] <= addr_a[4]; addr_a[3]++) {
                addr = IPV4_ADDR(addr_a[0], addr_a[1], addr_a[2], addr_a[3]);
                addr = rte_cpu_to_be_32(addr);
                if (count >= addr_max_count) {
                    return -1;
                }
                addrs[count++] = addr;
            }
        }
        p = strtok(NULL, " ,");
    }
    free(str);
    return count;
}

static void
netdev_config_init(struct rte_cfgfile *cfgfile, struct netdev_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "name-prefix");
    if (entry) {
        cfg->name_prefix = strdup(entry);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "tx-offload");
    if (entry) {
        if (strcasecmp(entry, "true") == 0) {
            cfg->enable_tx_offload = 1;
        } else if (strcasecmp(entry, "false") == 0) {
            cfg->enable_tx_offload = 0;
        } else {
            printf("Cannot read NETDEV/tx-offload = %s\n", entry);
            exit(-1);
        }
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "pre-mbuf-num");
    if (entry && parser_read_uint16(&cfg->mbuf_num, entry) < 0) {
        printf("Cannot read NETDEV/pre-mbuf-num = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "rxqueue-len");
    if (entry && parser_read_uint16(&cfg->rxq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/rxqueue-len = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "txqueue-len");
    if (entry && parser_read_uint16(&cfg->txq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/txqueue-len = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "ip-local-address");
    if (entry) {
        int count;

        count =
            __parse_ip_address_list(entry, cfg->local_ips, LOCAL_IP_MAX_COUNT);
        if (count < 0) {
            printf("Cannot read NETDEV/ip-local-address = %s\n", entry);
            exit(-1);
        }
        cfg->local_ip_count = count;
    } else {
        printf("No NETDEV/local-ipv4 options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "ip-local-port-range");
    if (entry) {
        char *str = strdup(entry);
        const char *p;

        p = strtok(str, " ,");
        if (parser_read_uint16(&cfg->l4_port_min, p) < 0) {
            printf("Cannot read NETDEV/ip-local-port-range = %s.\n", p);
            exit(-1);
        }
        p = strtok(NULL, " ,");
        if (parser_read_uint16(&cfg->l4_port_max, p) < 0) {
            printf("Cannot read NETDEV/ip-local-port-range = %s.\n", p);
            exit(-1);
        }
        free(str);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-ipv4");
    if (entry) {
        if (parse_ipv4_addr(entry, (struct in_addr *)&cfg->kni_ip) < 0) {
            printf("Cannot read NETDEV/kni-ipv4 = %s\n", entry);
            exit(-1);
        }
    } else {
        printf("No NETDEV/kni-ipv4 options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-netmask");
    if (entry) {
        if (parse_ipv4_addr(entry, (struct in_addr *)&cfg->kni_netmask) < 0) {
            printf("Cannot read NETDEV/kni-netmask = %s\n", entry);
            exit(-1);
        }
    } else {
        printf("No NETDEV/kni-netmask options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-gateway");
    if (entry) {
        if (parse_ipv4_addr(entry, (struct in_addr *)&cfg->kni_gateway) < 0) {
            printf("Cannot read NETDEV/kni-gateway = %s\n", entry);
            exit(-1);
        }
    } else {
        printf("No NETDEV/kni-gateway options.\n");
        exit(-1);
    }
}

static void
netdev_config_show(int fd) {
    char buf[3][32];
    /* netdevice */
    unixctl_command_reply(
        fd, "netdev/name_prefix: %s\n"
            "netdev/enable_tx_offload: %u\n"
            "netdev/pre_mbuf_num: %u\n"
            "netdev/rxq_desc_num: %u\n"
            "netdev/txq_desc_num: %u\n"
            "netdev/l4_port_min: %u\n"
            "netdev/l4_port_max: %u\n",
        lb_cfg->netdev.name_prefix, lb_cfg->netdev.enable_tx_offload,
        lb_cfg->netdev.mbuf_num, lb_cfg->netdev.rxq_desc_num,
        lb_cfg->netdev.txq_desc_num, lb_cfg->netdev.l4_port_min,
        lb_cfg->netdev.l4_port_max);
    ipv4_addr_tostring(lb_cfg->netdev.kni_ip, buf[0], sizeof(buf[0]));
    ipv4_addr_tostring(lb_cfg->netdev.kni_netmask, buf[1], sizeof(buf[1]));
    ipv4_addr_tostring(lb_cfg->netdev.kni_gateway, buf[2], sizeof(buf[2]));
    unixctl_command_reply(fd, "netdev/kni-ipv4: %s\n"
                              "netdev/kni-netmask: %s\n"
                              "netdev/kni-gateway: %s\n",
                          buf[0], buf[1], buf[2]);
    {
        uint32_t i;
        char buf[32];
        for (i = 0; i < lb_cfg->netdev.local_ip_count; i++) {
            ipv4_addr_tostring(lb_cfg->netdev.local_ips[i], buf, sizeof(buf));
            unixctl_command_reply(fd, "netdev/local-ip: %s\n", buf);
        }
    }
}

static void
arp_config_reset(struct arp_config *cfg) {
    cfg->arp_max_num = 1500;
    cfg->arp_expire_period = 1800;
    cfg->arp_expire_max_num = 16;
}

static void
arp_config_init(struct rte_cfgfile *cfgfile, struct arp_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "ARP", "arp-max-num");
    if (entry && parser_read_uint32(&cfg->arp_max_num, entry) < 0) {
        printf("Cannot read ARP/arp-max-num = %s\n", entry);
        exit(-1);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "ARP", "arp-expire-period");
    if (entry && parser_read_uint32(&cfg->arp_expire_period, entry) < 0) {
        printf("Cannot read ARP/arp-expire-period = %s\n", entry);
        exit(-1);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "ARP", "arp-expire-max-num");
    if (entry && parser_read_uint32(&cfg->arp_expire_max_num, entry) < 0) {
        printf("Cannot read ARP/arp-expire-max-num = %s\n", entry);
        exit(-1);
    }
}

static void
arp_config_show(int fd) {
    unixctl_command_reply(fd, "arp/max-num: %u\n"
                              "arp/expire-period: %u\n"
                              "arp/expire-max-num: %u\n",
                          lb_cfg->arp.arp_max_num,
                          lb_cfg->arp.arp_expire_period,
                          lb_cfg->arp.arp_expire_max_num);
}

static void
service_config_reset(struct service_config *cfg) {
    cfg->vs_max_num = 150000;
    cfg->cql_size = 10000;
}

static void
service_config_init(struct rte_cfgfile *cfgfile, struct service_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "SERVICE", "vs-max-num");
    if (entry && parser_read_uint32(&cfg->vs_max_num, entry) < 0) {
        printf("Cannot read SERVICE/vs-max-num = %s\n", entry);
        exit(-1);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "SERVICE", "vs-cql-size");
    if (entry && parser_read_uint32(&cfg->cql_size, entry) < 0) {
        printf("Cannot read SERVICE/vs-cql-size = %s\n", entry);
        exit(-1);
    }
}

static void
service_config_show(int fd) {
    unixctl_command_reply(fd, "service/vs-max-num: %u\n"
                              "service/vs-cql-size: %u\n",
                          lb_cfg->srv.vs_max_num, lb_cfg->srv.cql_size);
}

static void
lb_config_show(int fd, __attribute__((unused)) char **argv,
               __attribute__((unused)) int argc) {
    dpdk_config_show(fd);
    tcp_config_show(fd);
    udp_config_show(fd);
    arp_config_show(fd);
    service_config_show(fd);
    netdev_config_show(fd);
}

void
lb_config_load(const char *cfgfile_path, const char *proc_name) {
    struct rte_cfgfile *cfgfile;

    lb_cfg = malloc(sizeof(struct lb_config));
    if (!lb_cfg) {
        printf("Cannot alloc memory for lb config.\n");
        exit(-1);
    }
    memset(lb_cfg, 0, sizeof(struct lb_config));

    tcp_config_reset(&lb_cfg->tcp);
    udp_config_reset(&lb_cfg->udp);
    netdev_config_reset(&lb_cfg->netdev);
    arp_config_reset(&lb_cfg->arp);
    service_config_reset(&lb_cfg->srv);

    cfgfile = rte_cfgfile_load(cfgfile_path, 0);
    if (!cfgfile) {
        printf("Load config file failed: %s\n", cfgfile_path);
        exit(-1);
    }
    dpdk_config_init(cfgfile, &lb_cfg->dpdk, proc_name);
    tcp_config_init(cfgfile, &lb_cfg->tcp);
    udp_config_init(cfgfile, &lb_cfg->udp);
    netdev_config_init(cfgfile, &lb_cfg->netdev);
    arp_config_init(cfgfile, &lb_cfg->arp);
    service_config_init(cfgfile, &lb_cfg->srv);

    unixctl_command_register("config", "", "Show configuration information.", 0,
                             0, lb_config_show);
}

