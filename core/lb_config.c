/* Copyright (c) 2018. TIG developer. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_cfgfile.h>

#include "lb_config.h"
#include "lb_ip_address.h"
#include "lb_parser.h"

struct lb_conf *lb_cfg;

struct conf_entry {
    const char *name;
    int required;
    int (*parse)(const char *, void *);
};

static int
dpdk_entry_parse_argv(const char *token, void *conf) {
    struct lb_dpdk_conf *cfg = conf;
    char *argv_str, *p;
    char **argv;
    int argc = 0;

    argv = cfg->argv;
    argv[argc] = strdup("jupiter-service");
    if (argv[argc] == NULL)
        return -1;
    argc++;

    argv_str = strdup(token);
    if (argv_str == NULL)
        return -1;
    p = strtok(argv_str, " ");
    while (p != NULL) {
        if (argc == LB_MAX_DPDK_ARGS)
            break;
        argv[argc] = strdup(p);
        if (argv[argc] == NULL)
            return -1;
        argc++;
        p = strtok(NULL, " ");
    }
    cfg->argc = argc;
    free(argv_str);
    return 0;
}

static const struct conf_entry dpdk_entries[] = {
    {
        .name = "argv",
        .required = 1,
        .parse = dpdk_entry_parse_argv,
    },
};

static int
device_entry_parse_name(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;
    char *name;

    name = cfg->name;
    snprintf(name, RTE_KNI_NAMESIZE, "%s", token);
    return 0;
}

#define ipv4_prefix_to_mask_le(p) (~0 << (32 - p))
#define ipv4_prefix_to_num(p) (1 << (32 - p))
#define ipv6_prefix_to_num(p) (1 << (128 - p))

static inline void
ipv6_prefix_to_mask_le(uint16_t prefixlen, ip6_address_t *ip6) {
    int i = prefixlen / 32;
    int j = prefixlen % 32;

    switch (i) {
    case 0:
        ip6->as_u32[0] = 0;
        ip6->as_u32[1] = 0;
        ip6->as_u32[2] = 0;
        ip6->as_u32[3] = ipv4_prefix_to_mask_le(j);
        break;
    case 1:
        ip6->as_u32[0] = 0;
        ip6->as_u32[1] = 0;
        ip6->as_u32[2] = ipv4_prefix_to_mask_le(j);
        ip6->as_u32[3] = ~0;
        break;
    case 2:
        ip6->as_u32[0] = 0;
        ip6->as_u32[1] = ipv4_prefix_to_mask_le(j);
        ip6->as_u32[2] = ~0;
        ip6->as_u32[3] = ~0;
        break;
    case 3:
        ip6->as_u32[0] = ipv4_prefix_to_mask_le(j);
        ip6->as_u32[1] = ~0;
        ip6->as_u32[2] = ~0;
        ip6->as_u32[3] = ~0;
        break;
    default:
        ip6->as_u32[0] = ~0;
        ip6->as_u32[1] = ~0;
        ip6->as_u32[2] = ~0;
        ip6->as_u32[3] = ~0;
        break;
    }
}

static int
device_entry_parse_ipv4_addr_prefixlen(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;

    if (parse_ipv4_addr_prefixlen(token, (struct in_addr *)&cfg->ip4,
                                  &cfg->ip4_prefix) < 0) {
        return -1;
    }
    cfg->ip4_netmask.as_u32 = ipv4_prefix_to_mask_le(cfg->ip4_prefix);
    cfg->ip4_netmask.as_u32 = rte_cpu_to_be_32(cfg->ip4_netmask.as_u32);
    return 0;
}

static int
device_entry_parse_ipv4_gw(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;

    return parse_ipv4_addr(token, (struct in_addr *)&cfg->ip4_gw);
}

static int
device_entry_parse_ipv6_addr_prefixlen(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;

    if (parse_ipv6_addr_prefixlen(token, (struct in6_addr *)&cfg->ip6,
                                  &cfg->ip6_prefix) < 0) {
        return -1;
    }
    ipv6_prefix_to_mask_le(cfg->ip6_prefix, &cfg->ip6_netmask);
    ip6_address_bswap(&cfg->ip6_netmask);
    return 0;
}

static int
device_entry_parse_ipv6_gw(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;

    return parse_ipv6_addr(token, (struct in6_addr *)&cfg->ip6_gw);
}

static uint32_t
get_ipv4_host_addrs(struct in_addr *net_addr, uint16_t prefixlen,
                    ip4_address_t ip4_addrs[], uint32_t size) {
    uint32_t netmask;
    uint32_t base_ipv4;
    uint32_t i, num;

    netmask = ipv4_prefix_to_mask_le(prefixlen);
    base_ipv4 = rte_bswap32(net_addr->s_addr) & netmask;
    num = ipv4_prefix_to_num(prefixlen);
    num = RTE_MIN(num, size);
    for (i = 0; i < num; i++) {
        ip4_addrs[i].as_u32 = rte_bswap32(base_ipv4);
        base_ipv4 += 1;
    }
    return num;
}

static int
device_entry_parse_ipv4_fnat_laddr_prefixlen(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;
    char *tmp, *p, *last;
    struct in_addr net_addr;
    uint16_t prefixlen;
    uint32_t num = 0;

    tmp = strdup(token);
    p = strtok_r(tmp, ",", &last);
    while (p != NULL) {
        if (num >= LB_MAX_LADDR)
            break;
        if (parse_ipv4_addr_prefixlen(p, &net_addr, &prefixlen) < 0) {
            free(tmp);
            return -1;
        }
        num +=
            get_ipv4_host_addrs(&net_addr, prefixlen, cfg->fnat_laddrs_v4 + num,
                                LB_MAX_LADDR - num);
        p = strtok_r(NULL, ",", &last);
    }
    cfg->nb_fnat_laddr_v4 = num;
    free(tmp);
    return 0;
}

static inline void
in6_addr_inc(ip6_address_t *ip6) {
    if (++ip6->as_u32[0])
        return;
    if (++ip6->as_u32[1])
        return;
    if (++ip6->as_u32[2])
        return;
    ++ip6->as_u32[3];
}

static uint32_t
get_ipv6_host_addrs(ip6_address_t *ip6_net, uint16_t prefixlen,
                    ip6_address_t ip6_addrs[], uint32_t size) {
    ip6_address_t netmask;
    ip6_address_t ip6;
    uint32_t num_ip6, i;

    ipv6_prefix_to_mask_le(prefixlen, &netmask);
    ip6.as_u32[0] = rte_bswap32(ip6_net->as_u32[3]) & netmask.as_u32[0];
    ip6.as_u32[1] = rte_bswap32(ip6_net->as_u32[2]) & netmask.as_u32[1];
    ip6.as_u32[2] = rte_bswap32(ip6_net->as_u32[1]) & netmask.as_u32[2];
    ip6.as_u32[3] = rte_bswap32(ip6_net->as_u32[0]) & netmask.as_u32[3];
    num_ip6 = ipv6_prefix_to_num(prefixlen);
    num_ip6 = RTE_MIN(num_ip6, size);
    for (i = 0; i < num_ip6; i++) {
        ip6_addrs[i].as_u32[0] = rte_bswap32(ip6.as_u32[3]);
        ip6_addrs[i].as_u32[1] = rte_bswap32(ip6.as_u32[2]);
        ip6_addrs[i].as_u32[2] = rte_bswap32(ip6.as_u32[1]);
        ip6_addrs[i].as_u32[3] = rte_bswap32(ip6.as_u32[0]);
        in6_addr_inc(&ip6);
    }
    return num_ip6;
}

static int
device_entry_parse_ipv6_fnat_laddr_prefixlen(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;
    char *tmp, *p, *last;
    struct in6_addr ip6_net;
    uint16_t prefixlen;
    uint32_t num_ip6 = 0;

    tmp = strdup(token);
    p = strtok_r(tmp, ",", &last);
    while (p != NULL) {
        if (num_ip6 >= LB_MAX_LADDR)
            break;
        if (parse_ipv6_addr_prefixlen(p, &ip6_net, &prefixlen) < 0) {
            free(tmp);
            return -1;
        }
        num_ip6 += get_ipv6_host_addrs((ip6_address_t *)&ip6_net, prefixlen,
                                       cfg->fnat_laddrs_v6 + num_ip6,
                                       LB_MAX_LADDR - num_ip6);
        p = strtok_r(NULL, ",", &last);
    }
    cfg->nb_fnat_laddr_v6 = num_ip6;
    free(tmp);
    return 0;
}

static int
device_entry_parse_pci(const char *token, void *conf) {
    struct lb_device_conf *cfg = conf;
    char *pci_str, *p;
    struct rte_pci_addr *pci_addrs;
    int i = 0;

    pci_addrs = cfg->pcis;
    pci_str = strdup(token);
    if (pci_str == NULL)
        return -1;
    p = strtok(pci_str, " ,");
    while (p != NULL) {
        if (i == RTE_MAX_ETHPORTS)
            break;
        if (rte_pci_addr_parse(p, &pci_addrs[i++]) < 0)
            return -1;
        p = strtok(NULL, " ,");
    }
    cfg->nb_pcis = i;
    free(pci_str);
    return 0;
}

static const struct conf_entry device_entries[] = {
    {
        .name = "name",
        .required = 1,
        .parse = device_entry_parse_name,
    },
    {
        .name = "ipv4-addr",
        .required = 0,
        .parse = device_entry_parse_ipv4_addr_prefixlen,
    },
    {
        .name = "ipv4-gw",
        .required = 0,
        .parse = device_entry_parse_ipv4_gw,
    },
    {
        .name = "ipv6-addr",
        .required = 0,
        .parse = device_entry_parse_ipv6_addr_prefixlen,
    },
    {
        .name = "ipv6-gw",
        .required = 0,
        .parse = device_entry_parse_ipv6_gw,
    },
    {
        .name = "ipv4-fnat-laddr",
        .required = 0,
        .parse = device_entry_parse_ipv4_fnat_laddr_prefixlen,
    },
    {
        .name = "ipv6-fnat-laddr",
        .required = 0,
        .parse = device_entry_parse_ipv6_fnat_laddr_prefixlen,
    },
    {
        .name = "pci",
        .required = 1,
        .parse = device_entry_parse_pci,
    },
};

static int
parse_section(struct rte_cfgfile *cfgfile, const char *section,
              const struct conf_entry entries[], size_t size, void *cfg) {
    const char *val;
    size_t j;

    for (j = 0; j < size; j++) {
        val = rte_cfgfile_get_entry(cfgfile, section, entries[j].name);
        if (val == NULL) {
            if (entries[j].required) {
                printf("%s(): %s is required in section %s.\n", __func__,
                       entries[j].name, section);
                return -1;
            }
        } else {
            if (entries[j].parse(val, cfg) < 0) {
                printf("%s(): Cannot parse %s in section %s.\n", __func__,
                       entries[j].name, section);
                return -1;
            }
        }
    }
    return 0;
}

int
lb_config_file_load(const char *cfgfile_path) {
    struct rte_cfgfile *cfgfile;
    char **sections;
    int num_sections;
    int i;

    cfgfile = rte_cfgfile_load(cfgfile_path, 0);
    if (cfgfile == NULL) {
        printf("%s(): Load config file %s failed.\n", __func__, cfgfile_path);
        return -1;
    }

    num_sections = rte_cfgfile_num_sections(cfgfile, "", 0);
    if (num_sections == 0) {
        printf("%s(): There is no sections in config file.\n", __func__);
        return -1;
    }
    sections = malloc(num_sections * sizeof(char *));
    if (sections == NULL) {
        printf("%s(): Alloc memory failed.\n", __func__);
        return -1;
    }
    for (i = 0; i < num_sections; i++) {
        sections[i] = malloc(CFG_NAME_LEN);
        if (sections[i] == NULL) {
            printf("%s(): Alloc memory failed.\n", __func__);
            return -1;
        }
    }

    lb_cfg = malloc(sizeof(struct lb_conf));
    if (lb_cfg == NULL) {
        printf("%s(): Alloc memory for lb_conf failed.\n", __func__);
        return -1;
    }
    memset(lb_cfg, 0, sizeof(*lb_cfg));

    num_sections = rte_cfgfile_sections(cfgfile, sections, num_sections);
    for (i = 0; i < num_sections; i++) {
        int rc = 0;

        if (strcmp(sections[i], "INBOUND") == 0)
            rc = parse_section(cfgfile, sections[i], device_entries,
                               RTE_DIM(device_entries), &lb_cfg->inbound);
        else if (strcmp(sections[i], "OUTBOUND") == 0)
            rc = parse_section(cfgfile, sections[i], device_entries,
                               RTE_DIM(device_entries), &lb_cfg->outbound);
        else if (strcmp(sections[i], "DPDK") == 0)
            rc = parse_section(cfgfile, sections[i], dpdk_entries,
                               RTE_DIM(dpdk_entries), &lb_cfg->dpdk);
        else
            rc = -1;

        if (rc < 0) {
            printf("%s(): Cannot parse section %s.\n", __func__, sections[i]);
            return -1;
        }
    }

    rte_cfgfile_close(cfgfile);

    lb_config_print();

    return 0;
}

void
lb_config_print(void) {
    int i;
    struct lb_dpdk_conf *dpdk = &lb_cfg->dpdk;
    struct lb_device_conf *inbound = &lb_cfg->inbound;
    struct lb_device_conf *outbound = &lb_cfg->outbound;

    printf("dpdk args:\n");
    for (i = 0; i < dpdk->argc; i++)
        printf(" %s", dpdk->argv[i]);
    printf("\n");

    printf("inbound:\n");
    printf(" name=%s\n", inbound->name);
    printf(" ipv4_addr=" IPv4_BYTES_FMT "/%u\n",
           IPv4_BYTES(inbound->ip4.as_u32), inbound->ip4_prefix);
    printf(" ipv4_gw=" IPv4_BYTES_FMT "\n", IPv4_BYTES(inbound->ip4_gw.as_u32));
    printf(" ipv4_netmask=" IPv4_BYTES_FMT "\n",
           IPv4_BYTES(inbound->ip4_netmask.as_u32));
    printf(" ipv6_addr=" IPv6_BYTES_FMT "/%u\n", IPv6_BYTES(inbound->ip6.as_u8),
           inbound->ip6_prefix);
    printf(" ipv6_gw=" IPv6_BYTES_FMT "\n", IPv6_BYTES(inbound->ip6_gw.as_u8));
    printf(" ipv6_netmask=" IPv6_BYTES_FMT "\n",
           IPv6_BYTES(inbound->ip6_netmask.as_u8));
    printf(" nb_fnat_laddr_v4=%u\n", inbound->nb_fnat_laddr_v4);
    for (i = 0; i < (int)inbound->nb_fnat_laddr_v4; i++)
        printf(" fnat_laddrs_v4[%d]=" IPv4_BYTES_FMT "\n", i,
               IPv4_BYTES(inbound->fnat_laddrs_v4[i].as_u32));
    printf(" nb_fnat_laddr_v6=%u\n", inbound->nb_fnat_laddr_v6);
    for (i = 0; i < (int)inbound->nb_fnat_laddr_v6; i++)
        printf(" fnat_laddrs_v6[%d]=" IPv6_BYTES_FMT "\n", i,
               IPv6_BYTES(inbound->fnat_laddrs_v6[i].as_u8));

    printf("outbound:\n");
    printf(" name=%s\n", outbound->name);
    printf(" ipv4_addr=" IPv4_BYTES_FMT "/%u\n",
           IPv4_BYTES(outbound->ip4.as_u32), outbound->ip4_prefix);
    printf(" ipv4_gw=" IPv4_BYTES_FMT "\n",
           IPv4_BYTES(outbound->ip4_gw.as_u32));
    printf(" ipv4_netmask=" IPv4_BYTES_FMT "\n",
           IPv4_BYTES(outbound->ip4_netmask.as_u32));
    printf(" ipv6_addr=" IPv6_BYTES_FMT "/%u\n",
           IPv6_BYTES(outbound->ip6.as_u8), outbound->ip6_prefix);
    printf(" ipv6_gw=" IPv6_BYTES_FMT "\n", IPv6_BYTES(outbound->ip6_gw.as_u8));
    printf(" ipv6_netmask=" IPv6_BYTES_FMT "\n",
           IPv6_BYTES(outbound->ip6_netmask.as_u8));
}