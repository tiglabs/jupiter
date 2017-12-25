/* Copyright (c) 2017. TIG developer. */

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <stdint.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "lb_config.h"
#include "lb_device.h"
#include "parser.h"
#include "unixctl_command.h"

#define RTE_LOGTYPE_LB RTE_LOGTYPE_USER1

struct rte_mempool *lb_pktmbuf_pool;
struct lb_net_device *lb_netdev;

static void
__tx_offload_enabled(struct lb_net_device *dev) {
    if (dev->tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
        dev->tx_ol_flags |= LB_TX_OL_IPV4_CKSUM;
        RTE_LOG(INFO, LB, "Hardware Ip checksum enable.\n");
    }

    if (dev->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
        dev->tx_ol_flags |= LB_TX_OL_UDP_CKSUM;
        RTE_LOG(INFO, LB, "Hardware Udp checksum enable.\n");
    }

    if (dev->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
        dev->tx_ol_flags |= LB_TX_OL_TCP_CKSUM;
        RTE_LOG(INFO, LB, "Hardware Tcp checksum enable.\n");
    }
}

static void
__netdev_init_hw_info(struct lb_net_device *dev) {
    const struct netdev_config *cfg = &lb_cfg->netdev;
    struct rte_eth_dev_info dev_info;
    uint16_t port_id = dev->phy_portid;

    /* Net dev default info */
    rte_eth_dev_info_get(port_id, &dev_info);
    dev->rx_offload_capa = dev_info.rx_offload_capa;
    dev->tx_offload_capa = dev_info.tx_offload_capa;
    dev->max_rx_queues = dev_info.max_rx_queues;
    dev->max_tx_queues = dev_info.max_tx_queues;
    dev->max_rx_desc = dev_info.rx_desc_lim.nb_max;
    dev->max_tx_desc = dev_info.tx_desc_lim.nb_max;
    dev->nb_rx_desc = RTE_MIN(cfg->rxq_desc_num, dev->max_rx_desc);
    dev->nb_tx_desc = RTE_MIN(cfg->txq_desc_num, dev->max_tx_desc);
    if (rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_NTUPLE) == 0) {
        dev->ntuple_filter_support = 1;
    } else {
        dev->ntuple_filter_support = 0;
    }
    rte_eth_dev_get_mtu(port_id, &dev->mtu);
    if (cfg->enable_tx_offload) {
        __tx_offload_enabled(dev);
    }
    rte_eth_macaddr_get(dev->phy_portid, &dev->ha);
}

static void
__netdev_map_queue_to_lcore(struct lb_net_device *dev) {
    uint32_t lcore_count = rte_lcore_count();
    uint32_t lcore_id;
    uint16_t rxq_id = 0, txq_id = 0;

    if (lcore_count < 2) {
        rte_exit(EXIT_FAILURE, "Min number of lcore should be 2.\n");
    }
    if (dev->max_rx_queues < lcore_count - 1) {
        rte_exit(EXIT_FAILURE, "Max number of lcore should be %u.\n",
                 dev->max_rx_queues + 1);
    }
    if (dev->max_tx_queues < lcore_count) {
        rte_exit(EXIT_FAILURE, "Max number of lcore should be %u.\n",
                 dev->max_tx_queues);
    }
    dev->nb_rx_queues = lcore_count - 1;
    dev->nb_tx_queues = lcore_count;
    if (dev->nb_rx_queues > 1 && !dev->ntuple_filter_support) {
        rte_exit(EXIT_FAILURE, "Net device not support ntuple filter, number "
                               "of lcore should be 2.\n");
    }
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        dev->lcore_to_rxq[lcore_id] = rxq_id++;
    }
    RTE_LCORE_FOREACH(lcore_id) { dev->lcore_to_txq[lcore_id] = txq_id++; }
}

static void
__eth_dev_config(uint16_t port_id, uint16_t nb_rxq, uint16_t nb_txq,
                 uint16_t rxq_size, uint16_t txq_size,
                 const struct rte_eth_conf *dev_conf,
                 const struct rte_eth_rxconf *rx_conf,
                 const struct rte_eth_txconf *tx_conf, struct rte_mempool *mp) {
    uint16_t i;

    if (rte_eth_dev_configure(port_id, nb_rxq, nb_txq, dev_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Configure device%u failed.\n", port_id);
    }
    for (i = 0; i < nb_rxq; i++) {
        if (rte_eth_rx_queue_setup(port_id, i, rxq_size,
                                   rte_eth_dev_socket_id(port_id), rx_conf,
                                   mp) < 0) {
            rte_exit(EXIT_FAILURE, "Configure device%u rx queue failed.\n",
                     port_id);
        }
    }
    for (i = 0; i < nb_txq; i++) {
        if (rte_eth_tx_queue_setup(port_id, i, txq_size,
                                   rte_eth_dev_socket_id(port_id),
                                   tx_conf) < 0) {
            rte_exit(EXIT_FAILURE, "Configure device%u rx queue failed.\n",
                     port_id);
        }
    }
    if (rte_eth_dev_start(port_id) < 0) {
        rte_exit(EXIT_FAILURE, "device%u start failed.\n", port_id);
    }
}

static void
__netdev_init_kni(struct lb_net_device *dev, struct rte_mempool *mp) {
    static const struct rte_eth_conf dev_conf = {
        .rxmode =
            {
                .mq_mode = ETH_MQ_RX_RSS,
                .max_rx_pkt_len = ETHER_MAX_LEN,
            },
    };
    struct netdev_config *cfg = &(lb_cfg->netdev);
    char mac[ETHER_ADDR_FMT_SIZE];
    char *devargs;
    int len;

    ether_format_addr(mac, ETHER_ADDR_FMT_SIZE, &dev->ha);
    len =
        snprintf(NULL, 0, "virtio_user%d,path=/dev/vhost-net,mac=%s,iface=%s%d",
                 dev->phy_portid, mac, cfg->name_prefix, dev->phy_portid);
    len += 1;
    devargs = malloc(len);
    if (!devargs) {
        rte_exit(EXIT_FAILURE, "Alloc memory for devargs failed.\n");
    }
    snprintf(devargs, len,
             "virtio_user%d,path=/dev/vhost-net,mac=%s,iface=%s%d",
             dev->phy_portid, mac, cfg->name_prefix, dev->phy_portid);
    if (rte_eth_dev_attach(devargs, &dev->kni_portid) < 0) {
        rte_exit(EXIT_FAILURE, "Create vdev failed.\n");
    }

    __eth_dev_config(dev->kni_portid, 1, 1, 256, 256, &dev_conf, NULL, NULL,
                     mp);

    /* config kni ip */
    dev->ip = cfg->kni_ip;
    dev->netmask = cfg->kni_netmask;
    dev->gw = cfg->kni_gateway;

    free(devargs);
}

static void
tx_buffer_callback(struct rte_mbuf **pkts, uint16_t unsend, void *userdata) {
    uint16_t i;
    struct lb_net_device *dev = userdata;

    for (i = 0; i < unsend; i++) {
        rte_pktmbuf_free(pkts[i]);
    }
    dev->tx_dropped[rte_lcore_id()] += unsend;
}

static void
__init_tx_buffer(struct lb_net_device *dev) {
    uint32_t lcore_id;

    RTE_LCORE_FOREACH(lcore_id) {
        dev->tx_buffer[lcore_id] =
            rte_zmalloc("tx-buffer", RTE_ETH_TX_BUFFER_SIZE(PKT_MAX_BURST), 0);
        if (!dev->tx_buffer[lcore_id]) {
            rte_exit(EXIT_FAILURE, "Create tx-buffer failed.\n");
        }
        rte_eth_tx_buffer_init(dev->tx_buffer[lcore_id], PKT_MAX_BURST);
        rte_eth_tx_buffer_set_err_callback(dev->tx_buffer[lcore_id],
                                           tx_buffer_callback, dev);
    }
}

static void
__netdev_init_phy(struct lb_net_device *dev, struct rte_mempool *mp) {
    static const struct rte_eth_conf dev_conf = {
        .rxmode =
            {
                .mq_mode = ETH_MQ_RX_RSS,
                .max_rx_pkt_len = ETHER_MAX_LEN,
                .split_hdr_size = 0,
                .header_split = 0,   /**< Header Split disabled*/
                .hw_ip_checksum = 0, /**< IP checksum offload enabled */
                .hw_vlan_filter = 0, /**< VLAN filtering disabled */
                .jumbo_frame = 0,    /**< Jumbo Frame Support disabled */
                .hw_strip_crc = 0,   /**< CRC stripped by hardware */
            },
        .txmode =
            {
                .mq_mode = ETH_MQ_TX_NONE,
            },
        .rx_adv_conf =
            {
                .rss_conf =
                    {
                        .rss_key = NULL,
                        .rss_hf = ETH_RSS_PROTO_MASK,
                    },
            },
        .lpbk_mode = 0,
    };
    struct rte_eth_link eth_link;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf tx_conf;

    __init_tx_buffer(dev);

    rte_eth_dev_info_get(0, &dev_info);
    tx_conf = dev_info.default_txconf;
    if (dev->tx_ol_flags & LB_TX_OL_IPV4_CKSUM ||
        dev->tx_ol_flags & LB_TX_OL_TCP_CKSUM ||
        dev->tx_ol_flags & LB_TX_OL_UDP_CKSUM) {
        tx_conf.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS;
    }

    __eth_dev_config(dev->phy_portid, dev->nb_rx_queues, dev->nb_tx_queues,
                     dev->nb_rx_desc, dev->nb_tx_desc, &dev_conf, NULL,
                     &tx_conf, mp);

    rte_eth_link_get_nowait(dev->phy_portid, &eth_link);
    dev->link_status = eth_link.link_status;
    RTE_LOG(INFO, LB, "port%" PRIu32 " (%" PRIu32 " Gbps) %s\n",
            dev->phy_portid, eth_link.link_speed / 1000,
            eth_link.link_status ? "LINK_UP" : "LINK_DOWN");
}

static void
__ip_filter_add(uint16_t ifid, uint32_t dst_ip, uint16_t rxq_id) {
    struct rte_eth_ntuple_filter filter = {
        .flags = RTE_5TUPLE_FLAGS,
        .dst_ip = dst_ip,
        .dst_ip_mask = UINT32_MAX, /* Enable */
        .src_ip = 0,
        .src_ip_mask = 0, /* Disable */
        .dst_port = 0,
        .dst_port_mask = 0, /* Disable */
        .src_port = 0,
        .src_port_mask = 0, /* Disable */
        .proto = 0,
        .proto_mask = 0, /* Disable */
        .tcp_flags = 0,
        .priority = 1, /* Lowest */
        .queue = rxq_id,
    };

    if (rte_eth_dev_filter_ctrl(ifid, RTE_ETH_FILTER_NTUPLE, RTE_ETH_FILTER_ADD,
                                &filter) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot set device ip filter.\n");
    }
    if (rte_eth_dev_set_link_up(ifid) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot set device link up.\n");
    }
}

static struct rte_ring *
__init_local_ports(const char *name, uint16_t min_port, uint16_t max_port) {
    struct rte_ring *ports;
    uint16_t port;
    int ret;

    ports = rte_ring_create(name, 65536, rte_socket_id(),
                            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ports) {
        rte_exit(EXIT_FAILURE, "Cannot create ring %s for local ports: %s\n",
                 name, rte_strerror(rte_errno));
    }
    for (port = min_port; port != max_port; port++) {
        ret = rte_ring_sp_enqueue(ports,
                                  (void *)(uintptr_t)rte_cpu_to_be_16(port));
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Cannot put port to ring %s: %s\n", name,
                     rte_strerror(rte_errno));
        }
    }
    return ports;
}

static void
__init_local_ipv4_addr(struct lb_local_ipv4_addr *addr, uint32_t ip,
                       uint16_t rxq_id, uint16_t min_port, uint16_t max_port) {
    char name[RTE_RING_NAMESIZE];

    addr->ip = ip;
    addr->rxq_id = rxq_id;
    snprintf(name, RTE_RING_NAMESIZE, "tcp-ports%p", addr);
    addr->ports[LB_PROTO_TCP] = __init_local_ports(name, min_port, max_port);
    snprintf(name, RTE_RING_NAMESIZE, "udp-ports%p", addr);
    addr->ports[LB_PROTO_UDP] = __init_local_ports(name, min_port, max_port);
}

static void
__netdev_init_local_ipaddr(struct lb_net_device *dev) {
    struct netdev_config *cfg = &(lb_cfg->netdev);
    uint32_t lip_min_count_percore;
    uint32_t lip_idx = 0;
    uint32_t lcore_id;
    uint16_t rxq_id;

    if (cfg->local_ip_count < rte_lcore_count() - 1) {
        rte_exit(EXIT_FAILURE,
                 "The number of local ipv4 address (%u) is less than "
                 "the number of worker thread (%u).\n",
                 cfg->local_ip_count, rte_lcore_count() - 1);
    }
    lip_min_count_percore = cfg->local_ip_count / (rte_lcore_count() - 1);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        struct lb_local_ipv4_addr *addrs;
        uint32_t i;

        addrs = rte_calloc(NULL, lip_min_count_percore + 1,
                           sizeof(struct lb_local_ipv4_addr), 0);
        if (!addrs) {
            rte_exit(EXIT_FAILURE,
                     "Cannot alloc memory for local ipv4 address.\n");
        }
        rxq_id = dev->lcore_to_rxq[lcore_id];
        for (i = 0; i < lip_min_count_percore; ++i) {
            __init_local_ipv4_addr(&addrs[i], cfg->local_ips[lip_idx], rxq_id,
                                   cfg->l4_port_min, cfg->l4_port_max);
            if (dev->ntuple_filter_support) {
                __ip_filter_add(dev->phy_portid, cfg->local_ips[lip_idx],
                                rxq_id);
            }
            lip_idx++;
        }
        dev->local_ipaddrs_percore[lcore_id] = addrs;
        dev->local_ipaddr_count_percore[lcore_id] = lip_min_count_percore;
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        struct lb_local_ipv4_addr *addr;

        if (lip_idx == cfg->local_ip_count)
            break;
        addr = dev->local_ipaddrs_percore[lcore_id] +
               dev->local_ipaddr_count_percore[lcore_id];
        rxq_id = dev->lcore_to_rxq[lcore_id];
        __init_local_ipv4_addr(addr, cfg->local_ips[lip_idx], rxq_id,
                               cfg->l4_port_min, cfg->l4_port_max);
        dev->local_ipaddr_count_percore[lcore_id]++;
        if (dev->ntuple_filter_support) {
            __ip_filter_add(dev->phy_portid, cfg->local_ips[lip_idx], rxq_id);
        }
        lip_idx++;
    }
}

static void
net_device_init(void) {
    lb_netdev = rte_zmalloc(NULL, sizeof(struct lb_net_device), 0);
    if (!lb_netdev) {
        rte_exit(EXIT_FAILURE, "Alloc memory for net device failed.\n");
    }
    lb_netdev->phy_portid = 0;
    __netdev_init_hw_info(lb_netdev);
    __netdev_map_queue_to_lcore(lb_netdev);
    __netdev_init_kni(lb_netdev, lb_pktmbuf_pool);
    __netdev_init_phy(lb_netdev, lb_pktmbuf_pool);
    __netdev_init_local_ipaddr(lb_netdev);
}

static void
netdev_reset_stats_cmd_cb(__attribute__((unused)) int fd,
                          __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    rte_eth_stats_reset(lb_netdev->phy_portid);
}

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
#define _JSON_FMT(O) "{" O "}\n"
#define _(K, S) "\"" K "\":%" PRIu64 S
    static const char *ndev_stats_json_fmt = _JSON_FMT(
        _("RX-packets", ",") _("RX-bytes", ",") _("RX-errors", ",")
            _("RX-nombuf", ",") _("RX-misses", ",") _("RX-dropped", ",")
                _("TX-packets", ",") _("TX-bytes", ",") _("TX-errors", ",")
                    _("TX-dropped", ",") _("Rx-pps", ",") _("Tx-pps", ",")
                        _("Rx-Bps", ",") _("Tx-Bps", ",")
                            _("pktmbuf-in-use", ",") _("pktmbuf-avail", ""));
#undef _
#undef _JSON_FMT

#define _NORM_FMT(O) O
#define _(K, S) K ": %" PRIu64 "\n"
    static const char *ndev_stats_norm_fmt = _NORM_FMT(
        _("RX-packets", ",") _("RX-bytes", ",") _("RX-errors", ",")
            _("RX-nombuf", ",") _("RX-misses", ",") _("RX-dropped", ",")
                _("TX-packets", ",") _("TX-bytes", ",") _("TX-errors", ",")
                    _("TX-dropped", ",") _("Rx-pps", ",") _("Tx-pps", ",")
                        _("Rx-Bps", ",") _("Tx-Bps", ",")
                            _("pktmbuf-in-use", ",") _("pktmbuf-avail", ""));
#undef _
#undef _NORM_FMT

    struct rte_eth_stats stats;
    uint32_t lcore_id;
    uint64_t tx_dropped = 0;
    uint64_t rx_dropped = 0;
    uint64_t throughput[4];
    const char *output_fmt;

    if (argc > 0) {
        if (strcmp(argv[0], "--json") == 0) {
            output_fmt = ndev_stats_json_fmt;
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[0]);
            return;
        }
    } else {
        output_fmt = ndev_stats_norm_fmt;
    }

    rte_eth_stats_get(lb_netdev->phy_portid, &stats);
    RTE_LCORE_FOREACH(lcore_id) {
        tx_dropped += lb_netdev->tx_dropped[lcore_id];
        rx_dropped += lb_netdev->rx_dropped[lcore_id];
    }
    /* Throughput */
    netdev_throughput_get(&stats, throughput);
    unixctl_command_reply(fd, output_fmt, stats.ipackets, stats.ibytes,
                          stats.ierrors, stats.rx_nombuf, stats.imissed,
                          rx_dropped, stats.opackets, stats.obytes,
                          stats.oerrors, tx_dropped, throughput[0],
                          throughput[1], throughput[2], throughput[3],
                          (uint64_t)rte_mempool_in_use_count(lb_pktmbuf_pool),
                          (uint64_t)rte_mempool_avail_count(lb_pktmbuf_pool));
}

static void
netdev_show_ipaddr_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    {
        char buf[3][32];

        ipv4_addr_tostring(lb_netdev->ip, buf[0], sizeof(buf[0]));
        ipv4_addr_tostring(lb_netdev->netmask, buf[1], sizeof(buf[1]));
        ipv4_addr_tostring(lb_netdev->gw, buf[2], sizeof(buf[2]));
        unixctl_command_reply(fd,
                              "KNI-IPADDR:\n"
                              "  IP               Netmask          GW\n"
                              "  %-15s  %-15s  %-15s\n",
                              buf[0], buf[1], buf[2]);
    }
    {
        uint32_t lcore_id, i;
        struct lb_local_ipv4_addr *addr;
        char buf[32];

        unixctl_command_reply(fd, "LOCAL-IPADDR:\n"
                                  "  IP               RXQ_ID\n");
        RTE_LCORE_FOREACH_SLAVE(lcore_id) {
            for (i = 0; i < lb_netdev->local_ipaddr_count_percore[lcore_id];
                 i++) {
                addr = &lb_netdev->local_ipaddrs_percore[lcore_id][i];
                ipv4_addr_tostring(addr->ip, buf, sizeof(buf));
                unixctl_command_reply(fd, "  %-15s  %-5u\n", buf, addr->rxq_id);
            }
        }
    }
}

static void
netdev_show_hwinfo_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    char mac[32];
    struct rte_eth_link link_params;

    mac_addr_tostring(&lb_netdev->ha, mac, sizeof(mac));
    memset(&link_params, 0, sizeof(link_params));
    rte_eth_link_get(0, &link_params);
    unixctl_command_reply(fd,
                          "HWaddress: %s\n"
                          "Rxq_Num: %u\n"
                          "Link-Status: %s\n",
                          mac, lb_netdev->nb_rx_queues,
                          link_params.link_status == ETH_LINK_DOWN ? "DOWN"
                                                                   : "UP");
}

static void
pktmbuf_pool_init(void) {
    struct netdev_config *cfg = &(lb_cfg->netdev);
    uint32_t num;

    num = (cfg->rxq_desc_num + cfg->txq_desc_num) * rte_lcore_count() +
          cfg->mbuf_num;
    lb_pktmbuf_pool =
        rte_pktmbuf_pool_create("pktmbuf-pool", num, 256, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!lb_pktmbuf_pool) {
        rte_exit(EXIT_FAILURE, "Create pktmbuf pool failed.\n");
    }
}

void
lb_net_device_init(void) {
    if (rte_eth_dev_count() != 1) {
        rte_exit(EXIT_FAILURE, "The number of Net device is not equal to 1.\n");
    }

    pktmbuf_pool_init();
    net_device_init();

    unixctl_command_register("netdev/reset", "", "Reset NIC packet statistics.",
                             0, 0, netdev_reset_stats_cmd_cb);
    unixctl_command_register("netdev/stats", "[--json].",
                             "Show NIC packet statistics.", 0, 1,
                             netdev_show_stats_cmd_cb);
    unixctl_command_register("netdev/ipaddr", "",
                             "Show KNI/LOCAL ipv4 address.", 0, 0,
                             netdev_show_ipaddr_cmd_cb);
    unixctl_command_register("netdev/hwinfo", "", "Show NIC link-status.", 0, 0,
                             netdev_show_hwinfo_cmd_cb);
}

