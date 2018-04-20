/* Copyright (c) 2018. TIG developer. */

#include <stdio.h>
#include <stdlib.h>

#include <rte_cfgfile.h>
#include <rte_eth_bond.h>
#include <rte_ip.h>

#include "lb_config.h"
#include "lb_parser.h"

struct lb_conf *lb_cfg;

struct conf_entry {
    const char *name;
    int required;
    int (*parse)(const char *, void *);
};

static int
dpdk_entry_parse_argv(const char *token, void *_conf) {
    struct lb_dpdk_conf *conf = _conf;
    char *argv_str, *p;
    char **argv;
    int argc = 0;

    argv = conf->argv;
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
    conf->argc = argc;
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
device_entry_parse_name(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    char *name;

    name = conf->name;
    snprintf(name, RTE_KNI_NAMESIZE, "%s", token);
    return 0;
}

static int
device_entry_parse_mode(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t mode;

    if (strcmp(token, "rr") == 0)
        mode = BONDING_MODE_ROUND_ROBIN;
    else if (strcmp(token, "active-backup") == 0)
        mode = BONDING_MODE_ACTIVE_BACKUP;
    else
        return -1;

    conf->mode = mode;
    return 0;
}

static int
device_entry_parse_ipv4(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t addr;

    if (parse_ipv4_addr(token, (struct in_addr *)&addr) < 0)
        return -1;

    conf->ipv4 = addr;
    return 0;
}

static int
device_entry_parse_netmask(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t addr;

    if (parse_ipv4_addr(token, (struct in_addr *)&addr) < 0)
        return -1;

    conf->netmask = addr;
    return 0;
}

static int
device_entry_parse_gw(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t addr;

    if (parse_ipv4_addr(token, (struct in_addr *)&addr) < 0)
        return -1;

    conf->gw = addr;
    return 0;
}

static int
device_entry_parse_rxqsize(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint16_t size;

    if (parser_read_uint16(&size, token) < 0)
        return -1;

    conf->rxqsize = size;
    return 0;
}

static int
device_entry_parse_txqsize(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint16_t size;

    if (parser_read_uint16(&size, token) < 0)
        return -1;

    conf->txqsize = size;
    return 0;
}

static int
device_entry_parse_mtu(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint16_t size;

    if (parser_read_uint16(&size, token) < 0)
        return -1;

    conf->mtu = size;
    return 0;
}

static int
device_entry_parse_rxoffload(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t size;

    if (parser_read_uint32_hex(&size, token) < 0)
        return -1;

    conf->rxoffload = size;
    return 0;
}

static int
device_entry_parse_txoffload(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    uint32_t size;

    if (parser_read_uint32_hex(&size, token) < 0)
        return -1;

    conf->txoffload = size;
    return 0;
}

static int
device_entry_parse_local_ipv4(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    char *addr_str, *p;
    uint32_t *lips;
    int j = 0;
    uint32_t a, b, c, d, e;
    uint32_t i;
    uint32_t addr, netmask, num;

    lips = conf->lips;
    addr_str = strdup(token);
    if (addr_str == NULL)
        return -1;
    p = strtok(addr_str, " ,");
    while (p != NULL) {
        if (sscanf(p, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &e) != 5)
            return -1;
        if (a > 255 || b > 255 || c > 255 || d > 255 || e > 32 || e == 0)
            return -1;
        /* e = 30
         * (1 << 31):
         * 1000 0000 0000 0000 0000 0000 0000 0000
         * (1 << 31) >> (30 - 1):
         * 1111 1111 1111 1111 1111 1111 1111 1100
         */
        netmask = (1 << 31) >> (e - 1);
        addr = IPv4(a, b, c, d) & netmask;
        num = 1 << (32 - e);
        for (i = 0; i < num; i++) {
            if (j == LB_MAX_LADDR)
                goto end;
            lips[j++] = rte_cpu_to_be_32(addr + i);
        }
        p = strtok(NULL, " ,");
    }

end:
    conf->nb_lips = j;
    free(addr_str);
    return 0;
}

static int
device_entry_parse_pci(const char *token, void *_conf) {
    struct lb_device_conf *conf = _conf;
    char *pci_str, *p;
    struct rte_pci_addr *pci_addrs;
    int i = 0;

    pci_addrs = conf->pcis;
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
    conf->nb_pcis = i;
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
        .name = "mode",
        .required = 0,
        .parse = device_entry_parse_mode,
    },
    {
        .name = "ipv4",
        .required = 1,
        .parse = device_entry_parse_ipv4,
    },
    {
        .name = "netmask",
        .required = 1,
        .parse = device_entry_parse_netmask,
    },
    {
        .name = "gw",
        .required = 1,
        .parse = device_entry_parse_gw,
    },
    {
        .name = "rxqsize",
        .required = 1,
        .parse = device_entry_parse_rxqsize,
    },
    {
        .name = "txqsize",
        .required = 1,
        .parse = device_entry_parse_txqsize,
    },
    {
        .name = "mtu",
        .required = 1,
        .parse = device_entry_parse_mtu,
    },
    {
        .name = "rxoffload",
        .required = 0,
        .parse = device_entry_parse_rxoffload,
    },
    {
        .name = "txoffload",
        .required = 0,
        .parse = device_entry_parse_txoffload,
    },
    {
        .name = "local-ipv4",
        .required = 1,
        .parse = device_entry_parse_local_ipv4,
    },
    {
        .name = "pci",
        .required = 1,
        .parse = device_entry_parse_pci,
    },
};

static int
dpdk_section_parse(struct rte_cfgfile *cfgfile, const char *section,
                   struct lb_dpdk_conf *conf) {
    const char *val;
    uint32_t j;

    for (j = 0; j < RTE_DIM(dpdk_entries); j++) {
        val = rte_cfgfile_get_entry(cfgfile, section, dpdk_entries[j].name);
        if (val == NULL) {
            if (dpdk_entries[j].required) {
                printf("%s(): %s is required in section %s.\n", __func__,
                       dpdk_entries[j].name, section);
                return -1;
            }
        } else {
            if (dpdk_entries[j].parse(val, conf) < 0) {
                printf("%s(): Cannot parse %s in section %s.\n", __func__,
                       dpdk_entries[j].name, section);
                return -1;
            }
        }
    }
    return 0;
}

static int
device_section_parse(struct rte_cfgfile *cfgfile, const char *section,
                     struct lb_device_conf *conf) {
    const char *val;
    uint32_t j;

    for (j = 0; j < RTE_DIM(device_entries); j++) {
        val = rte_cfgfile_get_entry(cfgfile, section, device_entries[j].name);
        if (val == NULL) {
            if (device_entries[j].required) {
                printf("%s(): %s is required in section %s.\n", __func__,
                       device_entries[j].name, section);
                return -1;
            }
        } else {
            if (device_entries[j].parse(val, conf) < 0) {
                printf("%s(): Cannot parse %s in section %s.\n", __func__,
                       device_entries[j].name, section);
                return -1;
            }
        }
    }
    return 0;
}

int
lb_config_file_load(const char *cfgfile_path) {
    struct rte_cfgfile *cfgfile;
    int i;
    char **sections;
    int num_sections;

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

        if (strncmp(sections[i], "DEVICE", 6) == 0)
            rc = device_section_parse(cfgfile, sections[i],
                                      &lb_cfg->devices[lb_cfg->nb_decices++]);
        else if (strcmp(sections[i], "DPDK") == 0)
            rc = dpdk_section_parse(cfgfile, sections[i], &lb_cfg->dpdk);

        if (rc < 0) {
            printf("%s(): Cannot parse section %s.\n", __func__, sections[i]);
            return -1;
        }
    }

    rte_cfgfile_close(cfgfile);

    return 0;
}

