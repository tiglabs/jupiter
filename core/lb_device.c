/* Copyright (c) 2018. TIG developer. */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_eth_bond.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#include <rte_ring.h>

#include <unixctl_command.h>

#include "lb_config.h"
#include "lb_device.h"
#include "lb_format.h"
#include "lb_parser.h"

#define LB_PKTMBUF_POOL_DEFAULT_SIZE 4096

struct lb_device *lb_devices[RTE_MAX_ETHPORTS];
uint16_t lb_device_count;

static int
__fdir_filter_input_set(uint16_t port_id, uint32_t flow_type,
                        enum rte_eth_input_set_field filed,
                        enum rte_filter_input_set_op op) {
    struct rte_eth_fdir_filter_info info;

    memset(&info, 0, sizeof(info));
    info.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    info.info.input_set_conf.flow_type = flow_type;
    info.info.input_set_conf.field[0] = filed;
    info.info.input_set_conf.inset_size = 1;
    info.info.input_set_conf.op = op;
    info.info.input_set_conf.op = RTE_ETH_INPUT_SET_ADD;
    return rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                                   RTE_ETH_FILTER_SET, &info);
}

static int
_fdir_filter_input_set(uint16_t port_id) {
    int rc = 0;

    rc += __fdir_filter_input_set(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
                                  RTE_ETH_INPUT_SET_NONE,
                                  RTE_ETH_INPUT_SET_SELECT);
    rc += __fdir_filter_input_set(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_TCP,
                                  RTE_ETH_INPUT_SET_L3_DST_IP4,
                                  RTE_ETH_INPUT_SET_ADD);
    rc += __fdir_filter_input_set(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
                                  RTE_ETH_INPUT_SET_NONE,
                                  RTE_ETH_INPUT_SET_SELECT);
    rc += __fdir_filter_input_set(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_UDP,
                                  RTE_ETH_INPUT_SET_L3_DST_IP4,
                                  RTE_ETH_INPUT_SET_ADD);
    return rc;
}

static int
_fdir_filter_add(uint16_t port_id, uint32_t flow_type, uint32_t dst_ip,
                 uint32_t rxq_id) {
    struct rte_eth_fdir_filter fdir;

    memset(&fdir, 0, sizeof(fdir));
    fdir.input.flow_type = flow_type;
    fdir.input.flow.tcp4_flow.ip.dst_ip = dst_ip;
    fdir.action.rx_queue = rxq_id;
    return rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                                   RTE_ETH_FILTER_ADD, &fdir);
}

static int
dpdk_dev_fdir_filter_add(uint16_t port_id, uint32_t dst_ip, uint32_t rxq_id) {
    static uint8_t input_set_once[RTE_MAX_ETHPORTS] = {0};
    int rc;

    if (!input_set_once[port_id]) {
        rc = _fdir_filter_input_set(port_id);
        if (rc < 0) {
            RTE_LOG(
                WARNING, USER1,
                "%s(): Port%u doesn't support FDIR input set configuration.\n",
                __func__, port_id);
        }
        input_set_once[port_id] = 1;
    }

    rc = _fdir_filter_add(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, dst_ip,
                          rxq_id);
    if (rc < 0) {
        RTE_LOG(ERR, USER1,
                "%s(): Port%u add FDIR fileter failed, "
                "type:NONFRAG_IPV4_TCP, dst-ip:" IPv4_BE_FMT ", rxq:%u\n",
                __func__, port_id, IPv4_BE_ARG(dst_ip), rxq_id);
        return rc;
    }
    rc = _fdir_filter_add(port_id, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, dst_ip,
                          rxq_id);
    if (rc < 0) {
        RTE_LOG(ERR, USER1,
                "%s(): Port%u add FDIR fileter failed, "
                "type:NONFRAG_IPV4_UDP, dst-ip:" IPv4_BE_FMT ", rxq:%u\n",
                __func__, port_id, IPv4_BE_ARG(dst_ip), rxq_id);
        return rc;
    }
    RTE_LOG(INFO, USER1,
            "%s(): Port%u add FDIR filter, "
            "type:NONFRAG_IPV4_TCP|NONFRAG_IPV4_UDP, dst-ip:" IPv4_BE_FMT
            ", rxq:%u\n",
            __func__, port_id, IPv4_BE_ARG(dst_ip), rxq_id);
    return 0;
}

static int
dpdk_dev_5tuple_filter_add(uint16_t port_id, uint32_t dst_ip, uint32_t rxq_id) {
    struct rte_eth_ntuple_filter ntuple;
    int rc;

    memset(&ntuple, 0, sizeof(ntuple));
    ntuple.flags = RTE_5TUPLE_FLAGS;
    ntuple.dst_ip = dst_ip;
    ntuple.dst_ip_mask = UINT32_MAX;
    ntuple.priority = 1;
    ntuple.queue = rxq_id;
    rc = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_NTUPLE,
                                 RTE_ETH_FILTER_ADD, &ntuple);
    if (rc < 0) {
        RTE_LOG(ERR, USER1,
                "%s(): Port%u add 5Tuple filter failed, dst-ip:" IPv4_BE_FMT
                ", rxq:%u.\n",
                __func__, port_id, IPv4_BE_ARG(dst_ip), rxq_id);
        return rc;
    }
    RTE_LOG(INFO, USER1,
            "%s(): Port%u add 5Tuple filter, dst-ip:" IPv4_BE_FMT ", rxq:%u\n",
            __func__, port_id, IPv4_BE_ARG(dst_ip), rxq_id);
    return rc;
}

static int
dpdk_dev_filter_add(uint16_t port_id, uint32_t dst_ip, uint32_t rxq_id) {
    if (rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_NTUPLE) == 0) {
        return dpdk_dev_5tuple_filter_add(port_id, dst_ip, rxq_id);
    }

    RTE_LOG(ERR, USER1, "%s(): Port%u does not support 5Tuple filter.\n",
            __func__, port_id);

    if (rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_FDIR) == 0) {
        return dpdk_dev_fdir_filter_add(port_id, dst_ip, rxq_id);
    }

    RTE_LOG(ERR, USER1, "%s(): Port%u does not support FDIR filter.\n",
            __func__, port_id);

    return -1;
}

static int
kni_get_mac(const char *name, struct ether_addr *ha) {
    int fd;
    struct ifreq req;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        RTE_LOG(ERR, USER1, "%s(): Create SOCK_STREAM socket failed, %s\n",
                __func__, strerror(errno));
        return -1;
    }

    /* Get KNI MAC */
    memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, name, IFNAMSIZ);
    req.ifr_addr.sa_family = AF_INET;

    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
        RTE_LOG(ERR, USER1, "%s(): Set MAC failed, %s\n", __func__,
                strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    memcpy(ha->addr_bytes, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    return 0;
}

static void
tx_buffer_callback(struct rte_mbuf **pkts, uint16_t unsend, void *userdata) {
    uint16_t i;
    struct lb_device *dev = userdata;

    for (i = 0; i < unsend; i++) {
        rte_pktmbuf_free(pkts[i]);
    }
    dev->lcore_stats[rte_lcore_id()].tx_dropped += unsend;
}

static struct rte_ring *
l4_ports_create(const char *name, uint16_t min, uint16_t max,
                uint32_t socket_id) {
    struct rte_ring *r;
    uint16_t p;

    r = rte_ring_create(name, UINT16_MAX + 1, socket_id,
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (r == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create ports ring %s failed, %s.\n",
                __func__, name, rte_strerror(rte_errno));
        return NULL;
    }
    for (p = min; p != max; p++) {
        rte_ring_sp_enqueue(r, (void *)(uintptr_t)rte_cpu_to_be_16(p));
    }
    return r;
}

static int
dpdk_dev_config_and_set_ipfilter(uint16_t port_id, struct lb_device *dev,
                                 uint8_t ipfilter_enabled) {
    struct rte_eth_conf dev_conf;
    int rc;
    uint16_t i;

    memset(&dev_conf, 0, sizeof(dev_conf));
    dev_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    dev_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    dev_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
    dev_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;
    dev_conf.fdir_conf.mask.ipv4_mask.src_ip = 0xFFFFFFFF;
    dev_conf.fdir_conf.mask.ipv4_mask.dst_ip = 0xFFFFFFFF;
    dev_conf.fdir_conf.mask.src_port_mask = 0xFFFF;
    dev_conf.fdir_conf.mask.dst_port_mask = 0xFFFF;
    dev_conf.fdir_conf.drop_queue = 127;

    rc = rte_eth_dev_configure(port_id, dev->nb_rxq, dev->nb_txq, &dev_conf);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): config port%u failed, %s.\n", __func__,
                port_id, strerror(-rc));
        return rc;
    }

    for (i = 0; i < dev->nb_rxq; i++) {
        rc = rte_eth_rx_queue_setup(port_id, i, dev->rxq_size, dev->socket_id,
                                    NULL, dev->mp);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): Setup the rxq%u of port%u failed, %s.\n",
                    __func__, i, port_id, strerror(-rc));
            return rc;
        }
    }

    for (i = 0; i < dev->nb_txq; i++) {
        rc = rte_eth_tx_queue_setup(port_id, i, dev->txq_size, dev->socket_id,
                                    NULL);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): Setup the txq%u of port%u failed, %s.\n",
                    __func__, i, port_id, strerror(-rc));
            return rc;
        }
    }

    rte_eth_promiscuous_enable(port_id);

    if (ipfilter_enabled && dev->nb_rxq > 1) {
        uint32_t lcore_id;

        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            struct lb_laddr_list *laddr_list;
            struct lb_laddr *laddr;
            uint32_t lid;

            laddr_list = &dev->laddr_list[lcore_id];
            for (lid = 0; lid < laddr_list->nb; lid++) {
                laddr = &laddr_list->entries[lid];
                rc = dpdk_dev_filter_add(port_id, laddr->ipv4, laddr->rxq_id);
                if (rc < 0) {
                    RTE_LOG(ERR, USER1, "%s(): dpdk_dev_filter_add failed.\n",
                            __func__);
                    return rc;
                }
            }
        }
    }
    return 0;
}

static int
dpdk_dev_port_id_get_by_pci(struct rte_pci_addr *pci) {
    char pci_name[PCI_PRI_STR_SIZE];
    int rc;
    uint16_t port_id;

    rte_pci_device_name(pci, pci_name, sizeof(pci_name));
    rc = rte_eth_dev_get_port_by_name(pci_name, &port_id);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): Get port id from pci address(%s) failed.\n",
                __func__, pci_name);
        return rc;
    }
    return port_id;
}

static int
dpdk_dev_socket_id_get_by_pci(struct rte_pci_addr *pci) {
    uint16_t port_id;
    int rc;

    /* a) Get the port id by pci address. */
    rc = dpdk_dev_port_id_get_by_pci(pci);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): Get port id failed.\n", __func__);
        return rc;
    }
    port_id = rc;

    /* b) Get the socket id by port id. */
    rc = rte_eth_dev_socket_id(port_id);
    if (rc < 0) {
        RTE_LOG(WARNING, USER1, "%s(): Get the socket id of port%u failed.\n",
                __func__, port_id);
        rc = 0;
    }

    return rc;
}

static int
lb_device_conf_check_and_adjust(struct lb_device_conf configs[], uint16_t num) {
    uint16_t i, j;
    struct lb_device_conf *conf;
    struct rte_eth_dev_info info;
    int port_id;
    uint8_t all_ports[RTE_MAX_ETHPORTS] = {0};

    for (i = 0; i < num; i++) {
        conf = &configs[i];
        for (j = 0; j < conf->nb_pcis; j++) {
            port_id = dpdk_dev_port_id_get_by_pci(&conf->pcis[j]);
            if (port_id < 0) {
                RTE_LOG(ERR, USER1, "%s(): Get port id failed.\n", __func__);
                return -1;
            }

            /* Check duplicate ports. */
            all_ports[port_id]++;
            if (all_ports[port_id] > 1) {
                char pci_name[PCI_PRI_STR_SIZE];
                rte_pci_device_name(&conf->pcis[j], pci_name, sizeof(pci_name));
                RTE_LOG(ERR, USER1, "%s(): Duplicate ports, %s.\n", __func__,
                        pci_name);
                return -1;
            }

            /* Adjust queue_size .*/
            rte_eth_dev_info_get(port_id, &info);
            conf->rxqsize = RTE_MIN(conf->rxqsize, info.rx_desc_lim.nb_max);
            conf->rxqsize = RTE_MAX(conf->rxqsize, info.rx_desc_lim.nb_min);
            conf->txqsize = RTE_MIN(conf->txqsize, info.tx_desc_lim.nb_max);
            conf->txqsize = RTE_MAX(conf->txqsize, info.tx_desc_lim.nb_min);
        }
    }
    return 0;
}

static int
init_mempool(struct lb_device *dev) {
    uint32_t mp_size;
    char mp_name[RTE_MEMPOOL_NAMESIZE];

    mp_size = dev->nb_rxq * dev->rxq_size + dev->nb_txq * dev->txq_size;
    mp_size += LB_PKTMBUF_POOL_DEFAULT_SIZE;
    snprintf(mp_name, sizeof(mp_name), "mp%p", dev);
    dev->mp =
        rte_pktmbuf_pool_create(mp_name, mp_size,
                                /* cache_size */
                                32,
                                /* priv_size */
                                0,
                                /* data_room_size */
                                RTE_MBUF_DEFAULT_BUF_SIZE, dev->socket_id);
    if (dev->mp == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create pktmbuf mempool failed, %s.\n",
                __func__, rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

static int
init_kni(struct lb_device *dev) {
    struct rte_kni_conf kni_conf;
    struct rte_kni_ops kni_ops;
    struct rte_eth_dev_info info;

    memset(&info, 0, sizeof(info));
    rte_eth_dev_info_get(dev->port_id, &info);

    memset(&kni_conf, 0, sizeof(kni_conf));
    memcpy(kni_conf.name, dev->name, RTE_KNI_NAMESIZE);
    kni_conf.core_id = rte_get_master_lcore();
    kni_conf.force_bind = 1;
    kni_conf.group_id = dev->port_id;
    kni_conf.mbuf_size = RTE_MBUF_DEFAULT_DATAROOM;
    if (info.pci_dev) {
        kni_conf.addr = info.pci_dev->addr;
        kni_conf.id = info.pci_dev->id;
    }

    kni_ops.port_id = dev->port_id;
    kni_ops.change_mtu = NULL;
    kni_ops.config_network_if = NULL;

    dev->kni = rte_kni_alloc(dev->mp, &kni_conf, &kni_ops);
    if (dev->kni == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create kni %s failed.\n", __func__,
                dev->name);
        return -1;
    }

    if (kni_get_mac(dev->name, &dev->ha) < 0) {
        RTE_LOG(ERR, USER1, "%s(): kni_set_mac failed.\n", __func__);
        return -1;
    }
    return 0;
}

static int
init_master_worker_ring(struct lb_device *dev) {
    char rname[RTE_RING_NAMESIZE];
    uint32_t size;

    snprintf(rname, sizeof(rname), "ring%p", dev);
    size = PKT_MAX_BURST * dev->nb_rxq;
    dev->ring = rte_ring_create(rname, size, dev->socket_id,
                                RING_F_SC_DEQ | RING_F_EXACT_SZ);
    if (dev->ring == NULL) {
        RTE_LOG(ERR, USER1, "%s(): Create master-worker ring failed.\n",
                __func__);
        return -1;
    }
    return 0;
}

static int
init_tx_buffer(struct lb_device *dev) {
    uint32_t lcore_id, socket_id;

    socket_id = dev->socket_id;
    RTE_LCORE_FOREACH(lcore_id) {
        if (lcore_id != rte_get_master_lcore() &&
            socket_id != rte_lcore_to_socket_id(lcore_id)) {
            continue;
        }
        dev->tx_buffer[lcore_id] = rte_zmalloc_socket(
            "tx-buffer", RTE_ETH_TX_BUFFER_SIZE(PKT_MAX_BURST),
            RTE_CACHE_LINE_SIZE, socket_id);
        if (dev->tx_buffer[lcore_id] == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Create tx pkt buffer failed.\n",
                    __func__);
            return -1;
        }

        rte_eth_tx_buffer_init(dev->tx_buffer[lcore_id], PKT_MAX_BURST);
        rte_eth_tx_buffer_set_err_callback(dev->tx_buffer[lcore_id],
                                           tx_buffer_callback, dev);
    }
    return 0;
}

static uint32_t
rxq_to_lcore_id(struct lb_device *dev, uint16_t rxq_id) {
    uint32_t lcore_id;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (dev->lcore_conf[lcore_id].rxq_enable &&
            (dev->lcore_conf[lcore_id].rxq_id == rxq_id))
            return lcore_id;
    }
    return lcore_id;
}

static int
init_laddr_list(struct lb_device *dev, uint32_t lips[], uint32_t nb_lips) {
    uint32_t i;
    uint16_t rxq_id;
    uint32_t lcore_id;
    struct lb_laddr_list *laddr_list;
    struct lb_laddr *laddr;
    char name[RTE_RING_NAMESIZE];

    if (nb_lips < dev->nb_rxq) {
        RTE_LOG(ERR, USER1,
                "%s(): The number of local IPv4 is less than the number of "
                "RX queue of %s.\n",
                __func__, dev->name);
        return -1;
    }

    for (i = 0; i < nb_lips; i++) {
        rxq_id = i % dev->nb_rxq;
        lcore_id = rxq_to_lcore_id(dev, rxq_id);
        if (lcore_id == RTE_MAX_LCORE) {
            RTE_LOG(ERR, USER1,
                    "%s(): rxq_to_lcore_id failed: dev=%s, rxqid=%u.\n",
                    __func__, dev->name, rxq_id);
            return -1;
        }

        laddr_list = &dev->laddr_list[lcore_id];
        laddr = &laddr_list->entries[laddr_list->nb++];

        laddr->ipv4 = lips[i];
        laddr->port_id = dev->port_id;
        laddr->rxq_id = rxq_id;

        snprintf(name, sizeof(name), "tcpport%p", laddr);
        laddr->ports[LB_IPPROTO_TCP] = l4_ports_create(
            name, LB_MIN_L4_PORT, LB_MAX_L4_PORT, dev->socket_id);

        snprintf(name, sizeof(name), "udpport%p", laddr);
        laddr->ports[LB_IPPROTO_UDP] = l4_ports_create(
            name, LB_MIN_L4_PORT, LB_MAX_L4_PORT, dev->socket_id);

        if (laddr->ports[LB_IPPROTO_TCP] == NULL ||
            laddr->ports[LB_IPPROTO_UDP] == NULL) {
            RTE_LOG(ERR, USER1, "%s(): l4_ports_create failed.\n", __func__);
            return -1;
        }
    }
    return 0;
}

int
lb_device_init(struct lb_device_conf *configs, uint16_t num) {
    uint16_t i, j;
    int rc;
    struct lb_device_conf *conf;
    struct lb_device *dev;
    int socket_id;
    uint32_t lcore_id;
    uint16_t qid;

    rc = lb_device_conf_check_and_adjust(configs, num);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): Check device config failed.\n", __func__);
        return rc;
    }

    rte_kni_init(num);

    for (i = 0; i < num; i++) {
        conf = &configs[i];

        /* Get the socket id by pci. */
        socket_id = -1;
        for (j = 0; j < conf->nb_pcis; j++) {
            int tmp_sid;
            tmp_sid = dpdk_dev_socket_id_get_by_pci(&conf->pcis[j]);
            if (tmp_sid < 0) {
                RTE_LOG(ERR, USER1, "%s(): Get socket id by pci failed.\n",
                        __func__);
                return -1;
            }
            if (socket_id != -1 && socket_id != tmp_sid) {
                RTE_LOG(WARNING, USER1, "%s(): Slave port on different NUMA.\n",
                        __func__);
                continue;
            }
            socket_id = tmp_sid;
        }

        dev = rte_zmalloc_socket("dev", sizeof(*dev), RTE_CACHE_LINE_SIZE,
                                 socket_id);
        if (dev == NULL) {
            RTE_LOG(ERR, USER1, "%s(): Alloc memory for dev failed.\n",
                    __func__);
            return -1;
        }

        lb_devices[i] = dev;
        lb_device_count++;

        dev->socket_id = socket_id;

        if (conf->nb_pcis > 1) {
            char bond_name[32];
            snprintf(bond_name, sizeof(bond_name), "net_bonding%u", i);
            rc = rte_eth_bond_create(bond_name, conf->mode, dev->socket_id);
            if (rc < 0) {
                RTE_LOG(ERR, USER1,
                        "%s(): Create bond device failed: dev_name=%s, "
                        "bond_name=%s, mode=%u, socket_id=%u.\n",
                        __func__, conf->name, bond_name, conf->mode,
                        dev->socket_id);
                return rc;
            }
            dev->type = LB_DEV_T_BOND;
            dev->port_id = rc;
            for (i = 0; i < conf->nb_pcis; i++) {
                dev->slave_ports[dev->nb_slaves++] =
                    dpdk_dev_port_id_get_by_pci(&conf->pcis[i]);
            }
        } else {
            rc = dpdk_dev_port_id_get_by_pci(&conf->pcis[0]);
            if (rc < 0) {
                RTE_LOG(ERR, USER1, "%s(): Get port id from pci failed.\n",
                        __func__);
                return rc;
            }
            dev->type = LB_DEV_T_NORM;
            dev->port_id = rc;
        }

        qid = 0;
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            if (rte_lcore_to_socket_id(lcore_id) == dev->socket_id) {
                dev->lcore_conf[lcore_id].rxq_enable = 1;
                dev->lcore_conf[lcore_id].rxq_id = qid;
                dev->lcore_conf[lcore_id].txq_id = qid;
                qid++;
            }
        }
        lcore_id = rte_get_master_lcore();
        dev->lcore_conf[lcore_id].txq_id = qid;

        dev->nb_rxq = qid;
        dev->nb_txq = qid + 1;

        dev->rxq_size = conf->rxqsize;
        dev->txq_size = conf->txqsize;
        dev->rx_offload = conf->rxoffload;
        dev->tx_offload = conf->txoffload;
        dev->ipv4 = conf->ipv4;
        dev->netmask = conf->netmask;
        dev->gw = conf->gw;
        memcpy(dev->name, conf->name, sizeof(dev->name));

        rc = init_laddr_list(dev, conf->lips, conf->nb_lips);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): init laddr list failed.\n", __func__);
            return rc;
        }

        rc = init_mempool(dev);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): init mempool failed.\n", __func__);
            return rc;
        }

        rc = init_kni(dev);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): init kni failed.\n", __func__);
            return rc;
        }

        rc = init_tx_buffer(dev);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): init tx buffer failed.\n", __func__);
            return rc;
        }

        rc = init_master_worker_ring(dev);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): init master-worker ring failed.\n",
                    __func__);
            return rc;
        }

        rc = dpdk_dev_config_and_set_ipfilter(
            dev->port_id, dev, dev->type == LB_DEV_T_NORM ? 1 : 0);
        if (rc < 0) {
            RTE_LOG(
                ERR, USER1,
                "%s(): config dpdk dev or add ip filter failed, port_id=%u.\n",
                __func__, dev->port_id);
            return rc;
        }

        for (j = 0; j < dev->nb_slaves; j++) {
            rc = dpdk_dev_config_and_set_ipfilter(dev->slave_ports[j], dev, 1);
            if (rc < 0) {
                RTE_LOG(ERR, USER1,
                        "%s(): config dpdk dev or add ip filter failed, "
                        "port_id=%u.\n",
                        __func__, dev->slave_ports[j]);
                return rc;
            }

            rc = rte_eth_bond_slave_add(dev->port_id, dev->slave_ports[j]);
            if (rc < 0) {
                RTE_LOG(ERR, USER1,
                        "%s(): add slave port%u to bond port%u failed.\n",
                        __func__, dev->slave_ports[j], dev->port_id);
                return rc;
            }
        }

        rc = rte_eth_dev_start(dev->port_id);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): start port%u failed.\n", __func__,
                    dev->port_id);
            return rc;
        }
    }

    return 0;
}

/* UNIXCTL COMMANDS */

/*
    Returns:
        throughput = [pps_rx, pps_tx, bps_rx, bps_tx]
*/
static void
netdev_throughput_get(struct rte_eth_stats *stats, uint64_t throughput[]) {
    static uint64_t prev_pkts_rx, prev_bytes_rx;
    static uint64_t prev_pkts_tx, prev_bytes_tx;
    static uint64_t prev_cycles;
    uint64_t diff_pkts_rx, diff_pkts_tx, diff_cycles;
    uint64_t diff_bytes_rx, diff_bytes_tx;

    diff_cycles = prev_cycles;
    prev_cycles = rte_rdtsc();

    if (diff_cycles > 0) {
        diff_cycles = prev_cycles - diff_cycles;
    }

    diff_pkts_rx = stats->ipackets - prev_pkts_rx;
    diff_pkts_tx = stats->opackets - prev_pkts_tx;
    prev_pkts_rx = stats->ipackets;
    prev_pkts_tx = stats->opackets;
    throughput[0] =
        diff_cycles > 0 ? diff_pkts_rx * rte_get_tsc_hz() / diff_cycles : 0;
    throughput[1] =
        diff_cycles > 0 ? diff_pkts_tx * rte_get_tsc_hz() / diff_cycles : 0;

    diff_bytes_rx = stats->ibytes - prev_bytes_rx;
    diff_bytes_tx = stats->obytes - prev_bytes_tx;
    prev_bytes_rx = stats->ibytes;
    prev_bytes_tx = stats->obytes;
    throughput[2] =
        diff_cycles > 0 ? diff_bytes_rx * rte_get_tsc_hz() / diff_cycles : 0;
    throughput[3] =
        diff_cycles > 0 ? diff_bytes_tx * rte_get_tsc_hz() / diff_cycles : 0;
}

static void
netdev_show_stats_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt, json_first_obj = 1;
    uint16_t i;
    struct lb_device *dev;
    struct rte_eth_stats stats;
    uint32_t lcore_id;
    uint64_t tx_dropped;
    uint64_t rx_dropped;
    uint64_t throughput[4];
    uint32_t mbuf_in_use, mbuf_avail;

    if (argc > 0 && strcmp(argv[0], "--json") == 0) {
        json_fmt = 1;
    } else {
        json_fmt = 0;
    }

    if (json_fmt)
        unixctl_command_reply(fd, "[");

    LB_DEVICE_FOREACH(i, dev) {
        tx_dropped = 0;
        rx_dropped = 0;
        memset(throughput, 0, sizeof(throughput));

        rte_eth_stats_get(dev->port_id, &stats);
        RTE_LCORE_FOREACH(lcore_id) {
            tx_dropped += dev->lcore_stats[lcore_id].tx_dropped;
            rx_dropped += dev->lcore_stats[lcore_id].rx_dropped;
        }
        netdev_throughput_get(&stats, throughput);

        mbuf_in_use = rte_mempool_in_use_count(dev->mp);
        mbuf_avail = rte_mempool_avail_count(dev->mp);

        if (json_fmt) {
            unixctl_command_reply(fd, json_first_obj ? "{" : ",{");
            json_first_obj = 0;
        }

        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_S_FMT("dev", ",")
                                       : NORM_KV_S_FMT("dev", "\n"),
                              dev->name);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-packets", ",")
                                       : NORM_KV_64_FMT("  RX-packets", "\n"),
                              stats.ipackets);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-bytes", ",")
                                       : NORM_KV_64_FMT("  RX-bytes", "\n"),
                              stats.ibytes);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-errors", ",")
                                       : NORM_KV_64_FMT("  RX-errors", "\n"),
                              stats.ierrors);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-nombuf", ",")
                                       : NORM_KV_64_FMT("  RX-nombuf", "\n"),
                              stats.rx_nombuf);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-misses", ",")
                                       : NORM_KV_64_FMT("  RX-misses", "\n"),
                              stats.imissed);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("RX-dropped", ",")
                                       : NORM_KV_64_FMT("  RX-dropped", "\n"),
                              rx_dropped);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("TX-packets", ",")
                                       : NORM_KV_64_FMT("  TX-packets", "\n"),
                              stats.opackets);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("TX-bytes", ",")
                                       : NORM_KV_64_FMT("  TX-bytes", "\n"),
                              stats.obytes);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("TX-errors", ",")
                                       : NORM_KV_64_FMT("  TX-errors", "\n"),
                              stats.oerrors);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("TX-dropped", ",")
                                       : NORM_KV_64_FMT("  TX-dropped", "\n"),
                              tx_dropped);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("Rx-pps", ",")
                                       : NORM_KV_64_FMT("  Rx-pps", "\n"),
                              throughput[0]);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("Tx-pps", ",")
                                       : NORM_KV_64_FMT("  Tx-pps", "\n"),
                              throughput[1]);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("Rx-Bps", ",")
                                       : NORM_KV_64_FMT("  Rx-Bps", "\n"),
                              throughput[2]);
        unixctl_command_reply(fd,
                              json_fmt ? JSON_KV_64_FMT("Tx-Bps", ",")
                                       : NORM_KV_64_FMT("  Tx-Bps", "\n"),
                              throughput[3]);
        unixctl_command_reply(fd,
                              json_fmt
                                  ? JSON_KV_32_FMT("pktmbuf-in-use", ",")
                                  : NORM_KV_32_FMT("  pktmbuf-in-use", "\n"),
                              mbuf_in_use);
        unixctl_command_reply(fd,
                              json_fmt
                                  ? JSON_KV_32_FMT("pktmbuf-avail", "}")
                                  : NORM_KV_32_FMT("  pktmbuf-avail", "\n"),
                              mbuf_avail);
    }
    if (json_fmt)
        unixctl_command_reply(fd, "]\n");
}

UNIXCTL_CMD_REGISTER("netdev/stats", "[--json].", "Show NIC packet statistics.",
                     0, 1, netdev_show_stats_cmd_cb);

static void
netdev_reset_stats_cmd_cb(__attribute__((unused)) int fd,
                          __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint16_t i;
    struct lb_device *dev;

    LB_DEVICE_FOREACH(i, dev) {
        rte_eth_stats_reset(dev->port_id);
        memset(dev->lcore_stats, 0, sizeof(dev->lcore_stats));
    }
}

UNIXCTL_CMD_REGISTER("netdev/reset", "", "Reset NIC packet statistics.", 0, 0,
                     netdev_reset_stats_cmd_cb);

static void
netdev_show_ipaddr_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint16_t devid;
    struct lb_device *dev;
    struct lb_laddr_list *laddr_list;
    struct lb_laddr *laddr;
    uint32_t lcore_id;
    uint32_t i;

    LB_DEVICE_FOREACH(devid, dev) {
        unixctl_command_reply(fd, "dev: %s\n", dev->name);
        unixctl_command_reply(fd, "  kni-ip: " IPv4_BE_FMT "\n",
                              IPv4_BE_ARG(dev->ipv4));
        unixctl_command_reply(fd, "  kni-netmask: " IPv4_BE_FMT "\n",
                              IPv4_BE_ARG(dev->netmask));
        unixctl_command_reply(fd, "  kni-gw: " IPv4_BE_FMT "\n",
                              IPv4_BE_ARG(dev->gw));
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            laddr_list = &dev->laddr_list[lcore_id];
            for (i = 0; i < laddr_list->nb; i++) {
                laddr = &laddr_list->entries[i];
                unixctl_command_reply(
                    fd, "  local-ip[c%uq%u]: " IPv4_BE_FMT "\n", lcore_id,
                    laddr->rxq_id, IPv4_BE_ARG(laddr->ipv4));
            }
        }
    }
}

UNIXCTL_CMD_REGISTER("netdev/ipaddr", "", "Show KNI/LOCAL ipv4 address.", 0, 0,
                     netdev_show_ipaddr_cmd_cb);

static void
netdev_show_hwinfo_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint16_t i;
    struct lb_device *dev;
    char mac[32];
    struct rte_eth_link link_params;

    LB_DEVICE_FOREACH(i, dev) {
        unixctl_command_reply(fd, "dev: %s\n", dev->name);
        mac_addr_tostring(&dev->ha, mac, sizeof(mac));
        unixctl_command_reply(fd, "  hw: %s\n", mac);

        unixctl_command_reply(fd, "  rxq-num: %u\n", dev->nb_rxq);
        memset(&link_params, 0, sizeof(link_params));
        rte_eth_link_get_nowait(dev->port_id, &link_params);
        unixctl_command_reply(fd, "  link-status: %s\n",
                              link_params.link_status == ETH_LINK_DOWN ? "DOWN"
                                                                       : "UP");
    }
}

UNIXCTL_CMD_REGISTER("netdev/hwinfo", "", "Show NIC link-status.", 0, 0,
                     netdev_show_hwinfo_cmd_cb);

static char *
flowtype_to_str(uint16_t flow_type) {
    struct flow_type_info {
        char str[32];
        uint16_t ftype;
    };

    uint8_t i;
    static struct flow_type_info flowtype_str_table[] = {
        {"raw", RTE_ETH_FLOW_RAW},
        {"ipv4", RTE_ETH_FLOW_IPV4},
        {"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
        {"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
        {"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
        {"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
        {"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
        {"ipv6", RTE_ETH_FLOW_IPV6},
        {"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
        {"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
        {"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
        {"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
        {"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
        {"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
        {"port", RTE_ETH_FLOW_PORT},
        {"vxlan", RTE_ETH_FLOW_VXLAN},
        {"geneve", RTE_ETH_FLOW_GENEVE},
        {"nvgre", RTE_ETH_FLOW_NVGRE},
    };

    for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
        if (flowtype_str_table[i].ftype == flow_type)
            return flowtype_str_table[i].str;
    }

    return NULL;
}

static inline void
print_fdir_flex_mask(int fd, struct rte_eth_fdir_flex_conf *flex_conf,
                     uint32_t num) {
    struct rte_eth_fdir_flex_mask *mask;
    uint32_t i, j;
    char *p;

    for (i = 0; i < flex_conf->nb_flexmasks; i++) {
        mask = &flex_conf->flex_mask[i];
        p = flowtype_to_str(mask->flow_type);
        unixctl_command_reply(fd, "\n    %s:\t", p ? p : "unknown");
        for (j = 0; j < num; j++)
            unixctl_command_reply(fd, " %02x", mask->mask[j]);
    }
    unixctl_command_reply(fd, "\n");
}

static inline void
print_fdir_mask(int fd, struct rte_eth_fdir_masks *mask,
                enum rte_fdir_mode mode) {
    unixctl_command_reply(fd, "\n    vlan_tci: 0x%04x",
                          rte_be_to_cpu_16(mask->vlan_tci_mask));

    if (mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
        unixctl_command_reply(fd,
                              ", mac_addr: 0x%02x, tunnel_type: 0x%01x,"
                              " tunnel_id: 0x%08x",
                              mask->mac_addr_byte_mask, mask->tunnel_type_mask,
                              rte_be_to_cpu_32(mask->tunnel_id_mask));
    else if (mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
        unixctl_command_reply(fd, ", src_ipv4: 0x%08x, dst_ipv4: 0x%08x",
                              rte_be_to_cpu_32(mask->ipv4_mask.src_ip),
                              rte_be_to_cpu_32(mask->ipv4_mask.dst_ip));

        unixctl_command_reply(fd, "\n    src_port: 0x%04x, dst_port: 0x%04x",
                              rte_be_to_cpu_16(mask->src_port_mask),
                              rte_be_to_cpu_16(mask->dst_port_mask));

        unixctl_command_reply(fd, "\n    src_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
                              rte_be_to_cpu_32(mask->ipv6_mask.src_ip[0]),
                              rte_be_to_cpu_32(mask->ipv6_mask.src_ip[1]),
                              rte_be_to_cpu_32(mask->ipv6_mask.src_ip[2]),
                              rte_be_to_cpu_32(mask->ipv6_mask.src_ip[3]));

        unixctl_command_reply(fd, "\n    dst_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
                              rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[0]),
                              rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[1]),
                              rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[2]),
                              rte_be_to_cpu_32(mask->ipv6_mask.dst_ip[3]));
    }

    unixctl_command_reply(fd, "\n");
}

static inline void
print_fdir_flex_payload(int fd, struct rte_eth_fdir_flex_conf *flex_conf,
                        uint32_t num) {
    struct rte_eth_flex_payload_cfg *cfg;
    uint32_t i, j;

    for (i = 0; i < flex_conf->nb_payloads; i++) {
        cfg = &flex_conf->flex_set[i];
        if (cfg->type == RTE_ETH_RAW_PAYLOAD)
            unixctl_command_reply(fd, "\n    RAW:  ");
        else if (cfg->type == RTE_ETH_L2_PAYLOAD)
            unixctl_command_reply(fd, "\n    L2_PAYLOAD:	");
        else if (cfg->type == RTE_ETH_L3_PAYLOAD)
            unixctl_command_reply(fd, "\n    L3_PAYLOAD:	");
        else if (cfg->type == RTE_ETH_L4_PAYLOAD)
            unixctl_command_reply(fd, "\n    L4_PAYLOAD:	");
        else
            unixctl_command_reply(fd,
                                  "\n    UNKNOWN PAYLOAD(%u):  ", cfg->type);
        for (j = 0; j < num; j++)
            unixctl_command_reply(fd, "  %-5u", cfg->src_offset[j]);
    }
    unixctl_command_reply(fd, "\n");
}

static inline void
print_fdir_flow_type(int fd, uint32_t flow_types_mask) {
    int i;
    char *p;

    for (i = RTE_ETH_FLOW_UNKNOWN; i < RTE_ETH_FLOW_MAX; i++) {
        if (!(flow_types_mask & (1 << i)))
            continue;
        p = flowtype_to_str(i);
        if (p)
            unixctl_command_reply(fd, " %s", p);
        else
            unixctl_command_reply(fd, " unknown");
    }
    unixctl_command_reply(fd, "\n");
}

static void
netdev_show_fdir_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                        __attribute__((unused)) int argc) {
    struct rte_eth_fdir_stats fdir_stat;
    struct rte_eth_fdir_info fdir_info;
    uint16_t port_id;
    uint16_t i;
    struct lb_device *dev;
    int ret;

    LB_DEVICE_FOREACH(i, dev) {
        static const char *fdir_stats_border = "########################";

        port_id = dev->port_id;
        ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_FDIR);
        if (ret < 0) {
            unixctl_command_reply(fd, "\n FDIR is not supported on port %-2d\n",
                                  port_id);
            return;
        }

        memset(&fdir_info, 0, sizeof(fdir_info));
        rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                                RTE_ETH_FILTER_INFO, &fdir_info);
        memset(&fdir_stat, 0, sizeof(fdir_stat));
        rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                                RTE_ETH_FILTER_STATS, &fdir_stat);
        unixctl_command_reply(fd, "\n%s FDIR infos for port %s %s\n",
                              fdir_stats_border, dev->name, fdir_stats_border);
        unixctl_command_reply(fd, "  MODE: ");
        if (fdir_info.mode == RTE_FDIR_MODE_PERFECT)
            unixctl_command_reply(fd, "  PERFECT\n");
        else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN)
            unixctl_command_reply(fd, "  PERFECT-MAC-VLAN\n");
        else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
            unixctl_command_reply(fd, "  PERFECT-TUNNEL\n");
        else if (fdir_info.mode == RTE_FDIR_MODE_SIGNATURE)
            unixctl_command_reply(fd, "  SIGNATURE\n");
        else
            unixctl_command_reply(fd, "  DISABLE\n");
        if (fdir_info.mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN &&
            fdir_info.mode != RTE_FDIR_MODE_PERFECT_TUNNEL) {
            unixctl_command_reply(fd, "  SUPPORTED FLOW TYPE: ");
            print_fdir_flow_type(fd, fdir_info.flow_types_mask[0]);
        }
        unixctl_command_reply(fd, "  FLEX PAYLOAD INFO:\n");
        unixctl_command_reply(
            fd,
            "  max_len:	      %-10" PRIu32 "  payload_limit: %-10" PRIu32 "\n"
            "  payload_unit:  %-10" PRIu32 "  payload_seg:   %-10" PRIu32 "\n"
            "  bitmask_unit:  %-10" PRIu32 "  bitmask_num:   %-10" PRIu32 "\n",
            fdir_info.max_flexpayload, fdir_info.flex_payload_limit,
            fdir_info.flex_payload_unit, fdir_info.max_flex_payload_segment_num,
            fdir_info.flex_bitmask_unit, fdir_info.max_flex_bitmask_num);
        unixctl_command_reply(fd, "  MASK: ");
        print_fdir_mask(fd, &fdir_info.mask, fdir_info.mode);
        if (fdir_info.flex_conf.nb_payloads > 0) {
            unixctl_command_reply(fd, "  FLEX PAYLOAD SRC OFFSET:");
            print_fdir_flex_payload(fd, &fdir_info.flex_conf,
                                    fdir_info.max_flexpayload);
        }
        if (fdir_info.flex_conf.nb_flexmasks > 0) {
            unixctl_command_reply(fd, "  FLEX MASK CFG:");
            print_fdir_flex_mask(fd, &fdir_info.flex_conf,
                                 fdir_info.max_flexpayload);
        }
        unixctl_command_reply(
            fd, "  guarant_count: %-10" PRIu32 "  best_count:    %" PRIu32 "\n",
            fdir_stat.guarant_cnt, fdir_stat.best_cnt);
        unixctl_command_reply(
            fd, "  guarant_space: %-10" PRIu32 "  best_space:    %" PRIu32 "\n",
            fdir_info.guarant_spc, fdir_info.best_spc);
        unixctl_command_reply(
            fd,
            "  collision: %-10" PRIu32 "  free:	    %" PRIu32 "\n"
            "  maxhash:	  %-10" PRIu32 "  maxlen:    %" PRIu32 "\n"
            "  add:	      %-10" PRIu64 "  remove:    %" PRIu64 "\n"
            "  f_add:     %-10" PRIu64 "  f_remove:	%" PRIu64 "\n",
            fdir_stat.collision, fdir_stat.free, fdir_stat.maxhash,
            fdir_stat.maxlen, fdir_stat.add, fdir_stat.remove, fdir_stat.f_add,
            fdir_stat.f_remove);
        unixctl_command_reply(fd, "%s############################%s\n",
                              fdir_stats_border, fdir_stats_border);
    }
}

UNIXCTL_CMD_REGISTER("netdev/fdir", "", "Show NIC FDIR.", 0, 0,
                     netdev_show_fdir_cmd_cb);

static int
laddr_stats_arg_parse(char *argv[], int argc, int *json_fmt) {
    int i = 0;
    int rc;

    if (i < argc) {
        rc = strcmp(argv[i++], "--json");
        if (rc != 0)
            return i - 1;
        *json_fmt = 1;
    } else {
        *json_fmt = 0;
    }

    return i;
}

static void
laddr_stats_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt = 0, json_first_obj = 1;
    int rc;
    uint16_t devid;
    struct lb_device *dev;
    uint32_t lcore_id;
    struct lb_laddr_list *laddr_list;
    struct lb_laddr *laddr;
    uint32_t i, j;

    rc = laddr_stats_arg_parse(argv, argc, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    if (json_fmt)
        unixctl_command_reply(fd, "[");

    LB_DEVICE_FOREACH(devid, dev) {
        uint32_t total_lports[LB_IPPROTO_MAX] = {0},
                 avail_lports[LB_IPPROTO_MAX] = {0};

        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            laddr_list = &dev->laddr_list[lcore_id];
            for (i = 0; i < laddr_list->nb; i++) {
                laddr = &laddr_list->entries[i];
                for (j = 0; j < LB_IPPROTO_MAX; j++) {
                    if (laddr->ports[j] != NULL) {
                        avail_lports[j] += rte_ring_count(laddr->ports[j]);
                        total_lports[j] += LB_MAX_L4_PORT - LB_MIN_L4_PORT;
                    }
                }
            }
        }

        if (!json_fmt) {
            unixctl_command_reply(fd, "dev: %s\n", dev->name);
            unixctl_command_reply(fd, "  type: TCP\n");
            unixctl_command_reply(fd, "    avail_lports: %u\n",
                                  avail_lports[LB_IPPROTO_TCP]);
            unixctl_command_reply(fd, "    total_lports: %u\n",
                                  total_lports[LB_IPPROTO_TCP]);
            unixctl_command_reply(fd, "  type: UDP\n");
            unixctl_command_reply(fd, "    avail_lports: %u\n",
                                  avail_lports[LB_IPPROTO_UDP]);
            unixctl_command_reply(fd, "    total_lports: %u\n",
                                  total_lports[LB_IPPROTO_UDP]);
        } else {
            unixctl_command_reply(fd, json_first_obj ? "{" : ",{");
            json_first_obj = 0;
            unixctl_command_reply(fd, JSON_KV_S_FMT("dev", ","), dev->name);
            unixctl_command_reply(fd, JSON_KV_32_FMT("tcp_avail_lports", ","),
                                  avail_lports[LB_IPPROTO_TCP]);
            unixctl_command_reply(fd, JSON_KV_32_FMT("tcp_total_lports", ","),
                                  total_lports[LB_IPPROTO_TCP]);
            unixctl_command_reply(fd, JSON_KV_32_FMT("udp_avail_lports", ","),
                                  avail_lports[LB_IPPROTO_UDP]);
            unixctl_command_reply(fd, JSON_KV_32_FMT("udp_total_lports", "}"),
                                  avail_lports[LB_IPPROTO_UDP]);
        }
    }

    if (json_fmt)
        unixctl_command_reply(fd, "]\n");
}

UNIXCTL_CMD_REGISTER("laddr/stats", "[--json].", "Show local ip addr.", 0, 1,
                     laddr_stats_cmd_cb);