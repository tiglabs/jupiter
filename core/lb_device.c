/* Copyright (c) 2018. TIG developer. */

#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pci.h>

#include <cjson.h>
#include <unixctl_command.h>

#include "lb.h"
#include "lb_arp.h"
#include "lb_config.h"
#include "lb_device.h"
#include "lb_fnat_laddr.h"
#include "lb_icmp6.h"
#include "lb_ip_address.h"
#include "lb_ip_neighbour.h"
#include "lb_mib.h"
#include "lb_parser.h"

#define MULTI_TXQ 1
#define RXQ_SIZE 1024
#define TXQ_SIZE 1024

struct rte_mempool *pktmbuf_pool;
struct lb_device *lb_devices[LB_DEV_NUM];

static uint16_t nb_rxq;
static uint16_t nb_txq;
static uint16_t rxq_size = RXQ_SIZE;
static uint16_t txq_size = TXQ_SIZE;

static int
dpdk_dev_fdir_filter_add(uint16_t port_id, ip46_address_t *ip46,
                         uint32_t rxq_id) {
    static uint32_t soft_id = 1;
    struct rte_eth_fdir_filter fdir;

    memset(&fdir, 0, sizeof(fdir));
    if (ip46_address_is_ip4(ip46)) {
        fdir.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_OTHER;
        memcpy(&fdir.input.flow.ip4_flow.dst_ip, &ip46->ip4,
               sizeof(ip4_address_t));
    } else {
        fdir.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV6_OTHER;
        memcpy(fdir.input.flow.ipv6_flow.dst_ip, &ip46->ip6,
               sizeof(ip6_address_t));
    }
    fdir.action.rx_queue = rxq_id;
    fdir.soft_id = soft_id++;
    return rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                                   RTE_ETH_FILTER_ADD, &fdir);
}

static struct rte_mempool *
pktmbuf_pool_create(void) {
    uint32_t mp_size;

    if (rte_eth_dev_adjust_nb_rx_tx_desc(0, &rxq_size, &txq_size) < 0) {
        log_err("%s(): get rxq txq size failed.\n", __func__);
        return NULL;
    }

    mp_size =
        (nb_rxq * rxq_size + nb_txq * txq_size) * rte_eth_dev_count() + 4096;
    return rte_pktmbuf_pool_create("lb_pkt_mp", mp_size,
                                   /* cache_size */
                                   32,
                                   /* priv_size */
                                   0,
                                   /* data_room_size */
                                   RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
}

static int
dpdk_dev_config_start(uint16_t port_id, uint16_t nb_rxq, uint16_t nb_txq,
                      uint16_t rxq_size, uint16_t txq_size, uint32_t socket_id,
                      struct rte_mempool *mp) {
    struct rte_eth_conf dev_conf;
    int rc;
    uint16_t i;

    memset(&dev_conf, 0, sizeof(dev_conf));
    dev_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    if (nb_rxq > 1) {
        dev_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        dev_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
        dev_conf.fdir_conf.mode = RTE_FDIR_MODE_SIGNATURE;
        dev_conf.fdir_conf.mask.ipv4_mask.dst_ip = 0xFFFFFFFF;
        dev_conf.fdir_conf.mask.ipv6_mask.dst_ip[0] = 0xFFFFFFFF;
        dev_conf.fdir_conf.mask.ipv6_mask.dst_ip[1] = 0xFFFFFFFF;
        dev_conf.fdir_conf.mask.ipv6_mask.dst_ip[2] = 0xFFFFFFFF;
        dev_conf.fdir_conf.mask.ipv6_mask.dst_ip[3] = 0xFFFFFFFF;
        dev_conf.fdir_conf.drop_queue = 127;
    }

    rc = rte_eth_dev_configure(port_id, nb_rxq, nb_txq, &dev_conf);
    if (rc < 0) {
        log_err("%s(): config port%u failed, %s.\n", __func__, port_id,
                strerror(-rc));
        return rc;
    }

    rc = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rxq_size, &txq_size);
    if (rc < 0) {
        log_err("%s(): adjust port%u failed, %s.\n", __func__, port_id,
                strerror(-rc));
        return rc;
    }

    for (i = 0; i < nb_rxq; i++) {
        rc = rte_eth_rx_queue_setup(port_id, i, rxq_size, socket_id, NULL, mp);
        if (rc < 0) {
            log_err("%s(): Setup the rxq%u of port%u failed, %s.\n", __func__,
                    i, port_id, strerror(-rc));
            return rc;
        }
    }

    for (i = 0; i < nb_txq; i++) {
        rc = rte_eth_tx_queue_setup(port_id, i, txq_size, socket_id, NULL);
        if (rc < 0) {
            log_err("%s(): Setup the txq%u of port%u failed, %s.\n", __func__,
                    i, port_id, strerror(-rc));
            return rc;
        }
    }

    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        log_err("%s(): Start device failed.\n", __func__);
        return -1;
    }

    rte_eth_promiscuous_enable(port_id);
    return 0;
}

static struct rte_kni *
dpdk_kni_create(const char *name, uint16_t port_id, struct rte_mempool *mp) {
    struct rte_kni_conf kni_conf;
    struct rte_kni_ops kni_ops;
    struct rte_eth_dev_info info;
    static int done = 0;

    if (!done) {
        rte_kni_init(rte_eth_dev_count());
        done = 1;
    }

    memset(&info, 0, sizeof(info));
    rte_eth_dev_info_get(port_id, &info);

    memset(&kni_conf, 0, sizeof(kni_conf));
    memcpy(kni_conf.name, name, RTE_KNI_NAMESIZE);
    kni_conf.core_id = rte_get_master_lcore();
    kni_conf.force_bind = 1;
    kni_conf.group_id = port_id;
    kni_conf.mbuf_size = RTE_MBUF_DEFAULT_DATAROOM;
    if (info.pci_dev) {
        kni_conf.addr = info.pci_dev->addr;
        kni_conf.id = info.pci_dev->id;
    }
    rte_eth_macaddr_get(port_id, (struct ether_addr *)&kni_conf.mac_addr);
    rte_eth_dev_get_mtu(port_id, &kni_conf.mtu);

    memset(&kni_ops, 0, sizeof(kni_ops));
    kni_ops.port_id = port_id;

    return rte_kni_alloc(mp, &kni_conf, &kni_ops);
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

static struct lb_device *
lb_device_create(uint16_t port_id, struct lb_device_conf *cfg) {
    struct lb_device *dev;
    uint32_t lcore_id;
    uint16_t qid;

    if (!(dev = rte_malloc(NULL, sizeof(struct lb_device), 0))) {
        return NULL;
    }
    dev->port_id = port_id;
    dev->ip4 = cfg->ip4;
    dev->ip4_gw = cfg->ip4_gw;
    dev->ip4_netmask = cfg->ip4_netmask;
    dev->ip6 = cfg->ip6;
    dev->ip6_gw = cfg->ip6_gw;
    dev->ip6_netmask = cfg->ip6_netmask;
    strncpy(dev->name, cfg->name, RTE_KNI_NAMESIZE);
    rte_eth_macaddr_get(port_id, (struct ether_addr *)&dev->ha);

    rte_spinlock_init(&dev->txq_lock);
    rte_spinlock_init(&dev->kni_lock);

    for (qid = 0; qid < rte_lcore_count(); qid++) {
        dev->tx_buffers[qid] =
            rte_zmalloc("tx-buffer", RTE_ETH_TX_BUFFER_SIZE(PKT_RX_BURST_MAX),
                        RTE_CACHE_LINE_SIZE);
        if (dev->tx_buffers[qid] == NULL) {
            log_err("%s(): Create tx pkt buffer failed.\n", __func__);
            return NULL;
        }
        rte_eth_tx_buffer_init(dev->tx_buffers[qid], PKT_RX_BURST_MAX);
        rte_eth_tx_buffer_set_err_callback(dev->tx_buffers[qid],
                                           tx_buffer_callback, dev);
    }

    RTE_LCORE_FOREACH(lcore_id) {
        char ring_name[RTE_RING_NAMESIZE];

        snprintf(ring_name, RTE_RING_NAMESIZE, "pdq-%p-%u", dev, lcore_id);
        dev->pkt_dispatch_queues[lcore_id] =
            rte_ring_create(ring_name, 1024, SOCKET_ID_ANY, 0);
        if (!dev->pkt_dispatch_queues[lcore_id]) {
            log_err("%s(): create packet dispatch queue failed.\n", __func__);
            return NULL;
        }
    }

    {
        struct rte_hash_parameters param;
        char name[RTE_HASH_NAMESIZE];

        memset(&param, 0, sizeof(param));
        snprintf(name, RTE_HASH_NAMESIZE, "lip_vip_hash_%p", dev);
        param.name = name;
        param.entries = 64 << 10;
        param.key_len = sizeof(ip46_address_t);
        param.socket_id = SOCKET_ID_ANY;
        param.hash_func = rte_hash_crc;
        dev->vip_lip_hash = rte_hash_create(&param);
        if (!dev->vip_lip_hash) {
            log_err("%s(): create lip vip hash failed.\n", __func__);
            return NULL;
        }
    }

    dev->kni = dpdk_kni_create(cfg->name, port_id, pktmbuf_pool);
    if (!dev->kni) {
        log_err("%s(): create kni failed.\n", __func__);
        return NULL;
    }

    if (dpdk_dev_config_start(port_id, nb_rxq, nb_txq, rxq_size, txq_size,
                              SOCKET_ID_ANY, pktmbuf_pool) < 0) {
        log_err("%s(): config and start port%u failed.\n", __func__, port_id);
        return NULL;
    }

    return dev;
}

int
lb_device_module_init(struct lb_conf *lb_cfg) {
    uint16_t inbound_port_id, outbound_port_id;
    char pci_name[PCI_PRI_STR_SIZE];
    struct lb_device *dev;

    nb_rxq = rte_lcore_count() - 1;
#ifdef MULTI_TXQ
    nb_txq = rte_lcore_count();
#else
    nb_txq = rte_lcore_count() - 1;
#endif
    rxq_size = RXQ_SIZE;
    txq_size = TXQ_SIZE;

    pktmbuf_pool = pktmbuf_pool_create();
    if (!pktmbuf_pool) {
        log_err("%s(): create pktmbuf pool fialed.\n", __func__);
        return -1;
    }

    /*  inbound device */
    rte_pci_device_name(&lb_cfg->inbound.pcis[0], pci_name, sizeof(pci_name));
    if (rte_eth_dev_get_port_by_name(pci_name, &inbound_port_id) < 0) {
        log_err("%s(): get id for port(%s) failed.\n", __func__, pci_name);
        return -1;
    }

    rte_pci_device_name(&lb_cfg->outbound.pcis[0], pci_name, sizeof(pci_name));
    if (rte_eth_dev_get_port_by_name(pci_name, &outbound_port_id) < 0) {
        log_err("%s(): get id for port(%s) failed.\n", __func__, pci_name);
        return -1;
    }

    dev = lb_device_create(inbound_port_id, &lb_cfg->inbound);
    if (!dev) {
        log_err("%s(): create inbound device failed.\n", __func__);
        return -1;
    }
    lb_devices[LB_DEV_INBOUND] = dev;

    /*  outbound device */
    if (inbound_port_id != outbound_port_id) {
        dev = lb_device_create(outbound_port_id, &lb_cfg->outbound);
        if (!dev) {
            log_err("%s(): create outbound device failed.\n", __func__);
            return -1;
        }
    }
    lb_devices[LB_DEV_OUTBOUND] = dev;

    /* config fnat laddr */
    uint32_t laddr_id;

    for (laddr_id = 0; laddr_id < lb_cfg->inbound.nb_fnat_laddr_v4;
         laddr_id++) {
        ip4_address_t *fnat_ip4 = &lb_cfg->inbound.fnat_laddrs_v4[laddr_id];
        ip46_address_t fnat_ip46;
        int rx_lcore_id;

        rx_lcore_id = lb_fnat_laddr_add_ip4(fnat_ip4);
        if (rx_lcore_id < 0) {
            log_err("%s(): add fnat laddr failed, " IPv4_BYTES_FMT "\n",
                    __func__, IPv4_BYTES(fnat_ip4->as_u32));
            return -1;
        }
        ip46_address_set_ip4(&fnat_ip46, fnat_ip4);
        if (lb_device_add_vip_lip(lb_device_get_inbound(), &fnat_ip46) < 0) {
            log_err("%s(): add lip failed, " IPv4_BYTES_FMT "\n", __func__,
                    IPv4_BYTES(fnat_ip4->as_u32));
            return -1;
        }
        if (nb_rxq > 1 && dpdk_dev_fdir_filter_add(
                              lb_devices[LB_DEV_INBOUND]->port_id, &fnat_ip46,
                              lb_lcore_index(rx_lcore_id)) < 0) {
            log_err("%s(): add fdir filter failed, " IPv4_BYTES_FMT "\n",
                    __func__, IPv4_BYTES(fnat_ip4->as_u32));
            return -1;
        }
    }

    for (laddr_id = 0; laddr_id < lb_cfg->inbound.nb_fnat_laddr_v6;
         laddr_id++) {
        ip6_address_t *fnat_ip6 = &lb_cfg->inbound.fnat_laddrs_v6[laddr_id];
        ip46_address_t fnat_ip46;
        int rx_lcore_id;

        rx_lcore_id = lb_fnat_laddr_add_ip6(fnat_ip6);
        if (rx_lcore_id < 0) {
            log_err("%s(): add fnat laddr failed, " IPv6_BYTES_FMT "\n",
                    __func__, IPv6_BYTES(fnat_ip6->as_u8));
            return -1;
        }
        ip46_address_set_ip6(&fnat_ip46, fnat_ip6);
        if (lb_device_add_vip_lip(lb_device_get_inbound(), &fnat_ip46) < 0) {
            log_err("%s(): add lip failed, " IPv6_BYTES_FMT "\n", __func__,
                    IPv6_BYTES(fnat_ip6->as_u8));
            return -1;
        }
        if (nb_rxq > 1 && dpdk_dev_fdir_filter_add(
                              lb_devices[LB_DEV_INBOUND]->port_id, &fnat_ip46,
                              lb_lcore_index(rx_lcore_id)) < 0) {
            log_err("%s(): add fdir filter failed, " IPv6_BYTES_FMT "\n",
                    __func__, IPv6_BYTES(fnat_ip6->as_u8));
            return -1;
        }
    }
    return 0;
}

void
lb_device_xmit_burst(struct lb_device *dev, struct rte_mbuf **pkts,
                     uint32_t num) {
    uint32_t lcore_id = rte_lcore_id();
    uint16_t txq_id;
    uint32_t i;

#ifdef MULTI_TXQ
    txq_id = lb_lcore_index(lcore_id);
    for (i = 0; i < num; i++) {
        rte_eth_tx_buffer(dev->port_id, txq_id, dev->tx_buffers[txq_id],
                          pkts[i]);
    }
#else
    if (rte_get_master_lcore() == lcore_id)
        txq_id = 0;
    else
        txq_id = lb_lcore_index(lcore_id);

    if (txq_id == 0)
        rte_spinlock_lock(&dev->txq_lock);

    for (i = 0; i < num; i++) {
        rte_eth_tx_buffer(dev->port_id, txq_id, dev->tx_buffers[txq_id],
                          pkts[i]);
    }

    if (txq_id == 0)
        rte_spinlock_unlock(&dev->txq_lock);
#endif
}

void
lb_device_xmit(struct lb_device *dev, struct rte_mbuf *m) {
    lb_device_xmit_burst(dev, &m, 1);
}

void
lb_device_flush(struct lb_device *dev) {
    uint32_t lcore_id = rte_lcore_id();
    uint16_t txq_id;

#ifdef MULTI_TXQ
    txq_id = lb_lcore_index(lcore_id);
    rte_eth_tx_buffer_flush(dev->port_id, txq_id, dev->tx_buffers[txq_id]);
#else
    if (rte_get_master_lcore() == lcore_id)
        txq_id = 0;
    else
        txq_id = lb_lcore_index(lcore_id);

    if (txq_id == 0)
        rte_spinlock_lock(&dev->txq_lock);

    rte_eth_tx_buffer_flush(dev->port_id, txq_id, dev->tx_buffers[txq_id]);

    if (txq_id == 0)
        rte_spinlock_unlock(&dev->txq_lock);
#endif
}

uint16_t
lb_device_rx_burst(struct lb_device *dev, struct rte_mbuf **pkts,
                   uint16_t num) {
    uint32_t lcore_id = rte_lcore_id();
    uint16_t rxq_id = lb_lcore_index(lcore_id);

    return rte_eth_rx_burst(dev->port_id, rxq_id, pkts, num);
}

void
lb_device_kni_rx_handle(struct lb_device *dev) {
    struct rte_kni *kni = dev->kni;
    unsigned nb_rx;
    struct rte_mbuf *rx_pkts[PKT_RX_BURST_MAX];

    rte_kni_handle_request(kni);
    nb_rx = rte_kni_rx_burst(kni, rx_pkts, PKT_RX_BURST_MAX);
    lb_device_xmit_burst(dev, rx_pkts, nb_rx);
}

void
lb_device_kni_xmit(struct lb_device *dev, struct rte_mbuf *m) {
    struct rte_kni *kni = dev->kni;

    rte_spinlock_lock(&dev->kni_lock);
    if (rte_kni_tx_burst(kni, &m, 1) != 1) {
        rte_pktmbuf_free(m);
        LB_MIB_INC_STATS(KNI_TX_DROP);
    }
    rte_spinlock_unlock(&dev->kni_lock);
}

int
lb_device_ip4_output(struct rte_mbuf *m, ip4_address_t *dst_addr,
                     struct lb_device *dev) {
    ip4_address_t rt_addr;
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    if (ip4_address_is_equal_masked(dst_addr, &dev->ip4, &dev->ip4_netmask)) {
        rt_addr = *dst_addr;
    } else {
        rt_addr = dev->ip4_gw;
    }
    if (lb_ip4_neighbour_lookup_ha(&rt_addr, &eth->d_addr) < 0) {
        rte_pktmbuf_free(m);
        lb_arp_request(&rt_addr, dev);
        LB_MIB_INC_STATS(ARP_LOOKUP_DROP);
        return -1;
    } else {
        ether_addr_copy(&dev->ha, &eth->s_addr);
        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
        lb_device_xmit(dev, m);
        return 0;
    }
}

int
lb_device_ip6_output(struct rte_mbuf *m, ip6_address_t *dst_addr,
                     struct lb_device *dev) {
    ip6_address_t rt_addr;
    struct ether_hdr *eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    if (ip6_address_is_equal_masked(dst_addr, &dev->ip6, &dev->ip6_netmask)) {
        ip6_address_copy(&rt_addr, dst_addr);
    } else {
        ip6_address_copy(&rt_addr, &dev->ip6_gw);
    }
    if (lb_ip6_neighbour_lookup_ha(&rt_addr, &eth->d_addr) < 0) {
        rte_pktmbuf_free(m);
        lb_icmp6_neigh_request(&rt_addr, dev);
        LB_MIB_INC_STATS(ND_LOOKUP_DROP);
        return -1;
    } else {
        ether_addr_copy(&dev->ha, &eth->s_addr);
        eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
        lb_device_xmit(dev, m);
        return 0;
    }
}

int
lb_device_add_vip_lip(struct lb_device *dev, ip46_address_t *ip46) {
    void *p;
    uint32_t count;

    if (rte_hash_lookup_data(dev->vip_lip_hash, ip46, &p) >= 0) {
        count = (uint32_t)(uintptr_t)p;
    } else {
        count = 0;
    }
    count += 1;
    if (rte_hash_add_key_data(dev->vip_lip_hash, ip46,
                              (void *)(uintptr_t)count) < 0) {
        return -1;
    } else {
        return 0;
    }
}

void
lb_device_del_vip_lip(struct lb_device *dev, ip46_address_t *ip46) {
    void *p;
    uint32_t count;

    if (rte_hash_lookup_data(dev->vip_lip_hash, ip46, &p) < 0) {
        return;
    }
    count = (uint32_t)(uintptr_t)p;
    count--;
    if (count == 0) {
        rte_hash_del_key(dev->vip_lip_hash, ip46);
    } else {
        rte_hash_add_key_data(dev->vip_lip_hash, ip46,
                              (void *)(uintptr_t)count);
    }
}

int
lb_device_vip_lip_is_exist_v4(struct lb_device *dev, ip4_address_t *ip4) {
    ip46_address_t ip46;

    ip46_address_set_ip4(&ip46, ip4);
    return rte_hash_lookup(dev->vip_lip_hash, &ip46) >= 0;
}

int
lb_device_vip_lip_is_exist_v6(struct lb_device *dev, ip6_address_t *ip6) {
    ip46_address_t ip46;

    ip46_address_set_ip6(&ip46, ip6);
    return rte_hash_lookup(dev->vip_lip_hash, &ip46) >= 0;
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
    uint64_t diff_pkts_rx, diff_pkts_tx, diff_cycles, diff_secs;
    uint64_t diff_bytes_rx, diff_bytes_tx;

    diff_cycles = prev_cycles;
    prev_cycles = rte_rdtsc();

    if (diff_cycles > 0) {
        diff_cycles = prev_cycles - diff_cycles;
        diff_secs = (diff_cycles + rte_get_tsc_hz() - 1) / rte_get_tsc_hz();
    }

    diff_pkts_rx = stats->ipackets - prev_pkts_rx;
    diff_pkts_tx = stats->opackets - prev_pkts_tx;
    prev_pkts_rx = stats->ipackets;
    prev_pkts_tx = stats->opackets;
    throughput[0] =
        diff_cycles > 0 ? (diff_pkts_rx + diff_secs - 1) / diff_secs : 0;
    throughput[1] =
        diff_cycles > 0 ? (diff_pkts_tx + diff_secs - 1) / diff_secs : 0;

    diff_bytes_rx = stats->ibytes - prev_bytes_rx;
    diff_bytes_tx = stats->obytes - prev_bytes_tx;
    prev_bytes_rx = stats->ibytes;
    prev_bytes_tx = stats->obytes;
    throughput[2] =
        diff_cycles > 0 ? (diff_bytes_rx + diff_secs - 1) / diff_secs : 0;
    throughput[3] =
        diff_cycles > 0 ? (diff_bytes_tx + diff_secs - 1) / diff_secs : 0;
}

static void
netdev_stats_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt;
    uint32_t i;
    struct lb_device *dev;
    struct rte_eth_stats stats;
    uint64_t throughput[4];
    uint32_t lcore_id;
    uint64_t tx_dropped;
    uint64_t rx_dropped;
    uint32_t mbuf_in_use, mbuf_avail;
    cJSON *objs;

    if (argc > 0 && strcmp(argv[0], "--json") == 0) {
        json_fmt = 1;
    } else {
        json_fmt = 0;
    }

    if (json_fmt) {
        objs = cJSON_CreateArray();
    }

    for (i = 0; i < LB_DEV_NUM; i++) {
        dev = lb_devices[i];

        tx_dropped = 0;
        rx_dropped = 0;

        rte_eth_stats_get(dev->port_id, &stats);
        netdev_throughput_get(&stats, throughput);
        mbuf_in_use = rte_mempool_in_use_count(pktmbuf_pool);
        mbuf_avail = rte_mempool_avail_count(pktmbuf_pool);
        RTE_LCORE_FOREACH(lcore_id) {
            tx_dropped += dev->lcore_stats[lcore_id].tx_dropped;
            rx_dropped += dev->lcore_stats[lcore_id].rx_dropped;
        }

        if (json_fmt) {
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddStringToObject(obj, "dev", dev->name);
            cJSON_AddNumberToObject(obj, "RX-packets", stats.ipackets);
            cJSON_AddNumberToObject(obj, "RX-bytes", stats.ibytes);
            cJSON_AddNumberToObject(obj, "RX-errors", stats.ierrors);
            cJSON_AddNumberToObject(obj, "RX-nombuf", stats.rx_nombuf);
            cJSON_AddNumberToObject(obj, "RX-misses", stats.imissed);
            cJSON_AddNumberToObject(obj, "RX-dropped", rx_dropped);
            cJSON_AddNumberToObject(obj, "TX-packets", stats.opackets);
            cJSON_AddNumberToObject(obj, "TX-bytes", stats.obytes);
            cJSON_AddNumberToObject(obj, "TX-errors", stats.oerrors);
            cJSON_AddNumberToObject(obj, "TX-dropped", tx_dropped);
            cJSON_AddNumberToObject(obj, "Rx-pps", throughput[0]);
            cJSON_AddNumberToObject(obj, "Tx-pps", throughput[1]);
            cJSON_AddNumberToObject(obj, "Rx-Bps", throughput[2]);
            cJSON_AddNumberToObject(obj, "Tx-Bps", throughput[3]);
            cJSON_AddNumberToObject(obj, "pktmbuf-in-use", mbuf_in_use);
            cJSON_AddNumberToObject(obj, "pktmbuf-avail", mbuf_avail);
            cJSON_AddItemToArray(objs, obj);
        } else {
            unixctl_command_reply(fd, "dev: %s\n", dev->name);
            unixctl_command_reply(fd, "  RX-packets: %" PRIu64 "\n",
                                  stats.ipackets);
            unixctl_command_reply(fd, "  RX-bytes: %" PRIu64 "\n",
                                  stats.ibytes);
            unixctl_command_reply(fd, "  RX-errors: %" PRIu64 "\n",
                                  stats.ierrors);
            unixctl_command_reply(fd, "  RX-nombuf: %" PRIu64 "\n",
                                  stats.rx_nombuf);
            unixctl_command_reply(fd, "  RX-misses: %" PRIu64 "\n",
                                  stats.imissed);
            unixctl_command_reply(fd, "  RX-dropped: %" PRIu64 "\n",
                                  rx_dropped);
            unixctl_command_reply(fd, "  TX-packets: %" PRIu64 "\n",
                                  stats.opackets);
            unixctl_command_reply(fd, "  TX-bytes: %" PRIu64 "\n",
                                  stats.obytes);
            unixctl_command_reply(fd, "  TX-errors: %" PRIu64 "\n",
                                  stats.oerrors);
            unixctl_command_reply(fd, "  TX-dropped: %" PRIu64 "\n",
                                  tx_dropped);
            unixctl_command_reply(fd, "  Rx-pps: %" PRIu64 "\n", throughput[0]);
            unixctl_command_reply(fd, "  Tx-pps: %" PRIu64 "\n", throughput[1]);
            unixctl_command_reply(fd, "  Rx-Bps: %" PRIu64 "\n", throughput[2]);
            unixctl_command_reply(fd, "  Tx-Bps: %" PRIu64 "\n", throughput[3]);
            unixctl_command_reply(fd, "  pktmbuf-in-use: %" PRIu32 "\n",
                                  mbuf_in_use);
            unixctl_command_reply(fd, "  pktmbuf-avail: %" PRIu32 "\n",
                                  mbuf_avail);
        }

        if (lb_device_get_inbound() == lb_device_get_outbound())
            break;
    }

    if (json_fmt) {
        char *str = cJSON_PrintUnformatted(objs);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(objs);
    }
}

UNIXCTL_CMD_REGISTER("netdev/stats", "[--json].", "Show NIC packet statistics.",
                     0, 1, netdev_stats_cmd_cb);

static void
netdev_stats_reset_cmd_cb(__attribute__((unused)) int fd,
                          __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint16_t i;
    struct lb_device *dev;

    for (i = 0; i < LB_DEV_NUM; i++) {
        dev = lb_devices[i];
        rte_eth_stats_reset(dev->port_id);
        memset(dev->lcore_stats, 0, sizeof(dev->lcore_stats));
    }
}

UNIXCTL_CMD_REGISTER("netdev/stats/reset", "", "Reset NIC packet statistics.",
                     0, 0, netdev_stats_reset_cmd_cb);

static void
netdev_show_ipaddr_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint32_t i;
    struct lb_device *dev;
    char ip[INET6_ADDRSTRLEN];

    for (i = 0; i < LB_DEV_NUM; i++) {
        dev = lb_devices[i];
        unixctl_command_reply(fd, "dev: %s\n", dev->name);
        unixctl_command_reply(fd, "  ip4: %s\n",
                              ip4_address_format(&dev->ip4, ip));
        unixctl_command_reply(fd, "  ip4-netmask: %s\n",
                              ip4_address_format(&dev->ip4_netmask, ip));
        unixctl_command_reply(fd, "  ip4-gw: %s\n",
                              ip4_address_format(&dev->ip4_gw, ip));
        unixctl_command_reply(fd, "  ip6: %s\n",
                              ip6_address_format(&dev->ip6, ip));
        unixctl_command_reply(fd, "  ip6-prefix: %s\n",
                              ip6_address_format(&dev->ip6_netmask, ip));
        unixctl_command_reply(fd, "  ip6-gw: %s\n",
                              ip6_address_format(&dev->ip6_gw, ip));
        if (lb_device_get_outbound() == lb_device_get_inbound())
            break;
    }
}

UNIXCTL_CMD_REGISTER("ip/addr", "", "Show KNI ip address.", 0, 0,
                     netdev_show_ipaddr_cmd_cb);

static void
netdev_show_hwinfo_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                          __attribute__((unused)) int argc) {
    uint32_t i;
    struct lb_device *dev;
    char mac[32];
    struct rte_eth_link link_params;

    for (i = 0; i < LB_DEV_NUM; i++) {
        dev = lb_devices[i];
        unixctl_command_reply(fd, "dev: %s\n", dev->name);
        unixctl_command_reply(fd, "  port-id: %u\n", dev->port_id);
        mac_addr_tostring(&dev->ha, mac, sizeof(mac));
        unixctl_command_reply(fd, "  hw: %s\n", mac);
        memset(&link_params, 0, sizeof(link_params));
        rte_eth_link_get_nowait(dev->port_id, &link_params);
        unixctl_command_reply(fd, "  link-status: %s\n",
                              link_params.link_status == ETH_LINK_DOWN ? "DOWN"
                                                                       : "UP");
        if (lb_device_get_outbound() == lb_device_get_inbound())
            break;
    }
}

UNIXCTL_CMD_REGISTER("netdev/hwinfo", "", "Show NIC link-status.", 0, 0,
                     netdev_show_hwinfo_cmd_cb);