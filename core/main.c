/* Copyright (c) 2017. TIG developer. */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pdump.h>
#include <rte_rwlock.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <rte_udp.h>

#include "lb_arp.h"
#include "lb_config.h"
#include "lb_device.h"
#include "lb_proto_icmp.h"
#include "lb_proto_tcp.h"
#include "lb_proto_udp.h"
#include "lb_rwlock.h"
#include "lb_service.h"
#include "lcore_event.h"
#include "parser.h"
#include "unixctl_command.h"

#define RTE_LOGTYPE_LB RTE_LOGTYPE_USER1

#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

#define VERSION "0.0.1"

#define TRUE 1
#define FALSE 0

#define SOCK_FILEPATH "/var/run/jupiter.sock"
#define PID_FILEPATH "/var/run/jupiter.pid"
#define DEFAULT_CONF_FILEPATH "/etc/jupiter/jupiter.cfg"

static int proc_exit = FALSE;
static int unixctl_fd;

static const char *lb_cfgfile;
static const char *lb_procname;
static int lb_daemon = FALSE;

rte_rwlock_t lb_thread_rwlock = RTE_RWLOCK_INITIALIZER;

static int
master_thread(__attribute__((unused)) void *arg) {
    struct lb_net_device *dev = lb_netdev;
    uint32_t lcore_id = rte_lcore_id();
    uint16_t txq_id = dev->lcore_to_txq[lcore_id];
    struct rte_eth_dev_tx_buffer *tx_buffer = dev->tx_buffer[lcore_id];
    struct rte_mbuf *rx_pkts[PKT_MAX_BURST];
    uint32_t nb_pkts, i;
    static uint32_t loop_count = 0;

    while (!proc_exit) {
        /* doing unixctl command */
        unixctl_server_run_once(unixctl_fd);

        /* doing lcore event */
        lcore_event_poll(lcore_id);

        /* doing timer */
        if (loop_count++ > 10000) {
            loop_count = 0;
            rte_timer_manage();
        }

        /* doing kni */
        nb_pkts = rte_eth_rx_burst(dev->kni_portid, 0, rx_pkts, PKT_MAX_BURST);
        for (i = 0; i < nb_pkts; ++i) {
            rte_eth_tx_buffer(dev->phy_portid, txq_id, tx_buffer, rx_pkts[i]);
        }
        rte_eth_tx_buffer_flush(dev->phy_portid, txq_id, tx_buffer);
    }
    return 0;
}

static void
kni_packet_event_cb(__attribute__((unused)) unsigned snd_lcoreid, void *param) {
    struct rte_mbuf *mbuf = param;

    if (rte_eth_tx_burst(lb_netdev->kni_portid, 0, &mbuf, 1) != 1) {
        rte_pktmbuf_free(mbuf);
    }
}

static void
arp_packet_event_cb(__attribute__((unused)) unsigned snd_lcoreid, void *param) {
    struct rte_mbuf *mbuf = param;

    lb_arp_packet_recv(mbuf);
    if (rte_eth_tx_burst(lb_netdev->kni_portid, 0, &mbuf, 1) != 1) {
        rte_pktmbuf_free(mbuf);
    }
}

#define ETHER_TYPE_IPv4_BE 0x0008
#define ETHER_TYPE_ARP_BE 0x0608

static void
packet_handle(struct rte_mbuf *pkt) {
    struct ether_hdr *ethh;
    struct ipv4_hdr *iph;

    ethh = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    switch (ethh->ether_type) {
    case ETHER_TYPE_IPv4_BE:
        goto l3_packet;
    case ETHER_TYPE_ARP_BE:
        if (lcore_event_notify(rte_get_master_lcore(), arp_packet_event_cb,
                               pkt) < 0) {
            goto drop_packet;
        }
        return;
    default:
        goto drop_packet;
    }

l3_packet:
    iph = (struct ipv4_hdr *)((char *)ethh + ETHER_HDR_LEN);
    if (lb_netdev_chk_ipv4(iph->dst_addr) == IS_MYADDR ||
        IS_IPV4_MCAST(iph->dst_addr)) {
        if (lcore_event_notify(rte_get_master_lcore(), kni_packet_event_cb,
                               pkt) < 0) {
            goto drop_packet;
        }
        return;
    }

    switch (iph->next_proto_id) {
    case IPPROTO_TCP:
        if (lb_tcp_fullnat_handle(pkt, iph) < 0) {
            lb_netdev->rx_dropped[rte_lcore_id()]++;
        }
        return;
    case IPPROTO_UDP:
        if (lb_udp_fullnat_handle(pkt, iph) < 0) {
            lb_netdev->rx_dropped[rte_lcore_id()]++;
        }
        return;
    case IPPROTO_ICMP:
        if (lb_icmp_fullnat_handle(pkt, iph) < 0) {
            lb_netdev->rx_dropped[rte_lcore_id()]++;
        }
        return;
    default:
        goto drop_packet;
    }

drop_packet:
    rte_pktmbuf_free(pkt);
    lb_netdev->rx_dropped[rte_lcore_id()]++;
}

static int
worker_thread(__attribute__((unused)) void *arg) {
    uint32_t lcore_id = rte_lcore_id();
    uint16_t txq_id = lb_netdev->lcore_to_txq[lcore_id];
    uint16_t rxq_id = lb_netdev->lcore_to_rxq[lcore_id];
    struct rte_eth_dev_tx_buffer *tx_buffer = lb_netdev->tx_buffer[lcore_id];
    struct rte_mbuf *rx_pkts[PKT_MAX_BURST];
    uint32_t nb_pkts, i;
    static uint32_t loop_count = 0;

    while (!proc_exit) {
        thread_read_lock();

        /* doing lcore event */
        lcore_event_poll(lcore_id);

        /* doing timer */
        if (loop_count++ > 10000) {
            loop_count = 0;
            rte_timer_manage();
        }

        nb_pkts = rte_eth_rx_burst(0, rxq_id, rx_pkts, PKT_MAX_BURST);
        for (i = 0; i < nb_pkts; ++i) {
            packet_handle(rx_pkts[i]);
        }
        rte_eth_tx_buffer_flush(0, txq_id, tx_buffer);
        thread_read_unlock();
    }
    return 0;
}

static void
exit_cmd_cb(__attribute__((unused)) int fd,
            __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    proc_exit = TRUE;
}

static void
version_cmd_cb(int fd, __attribute__((unused)) char *argv[],
               __attribute__((unused)) int argc) {
    unixctl_command_reply(fd, "version: %s\n", VERSION);
}

static void
memory_cmd_cb(int fd, char *argv[], int argc) {
#define _JSON_FMT(O) "{" O "}\n"
#define _(K, V, S) "\"" K "\":" V S
    static const char *memort_json_fmt = _JSON_FMT(
        _("Heap_size", "%zu", ",") _("Free_size", "%zu", ",")
            _("Alloc_size", "%zu", ",") _("Greatest_free_size", "%zu", ",")
                _("Alloc_count", "%u", ",") _("Free_count", "%u", ""));
#undef _
#undef _JSON_FMT

#define _NORM_FMT(O) O
#define _(K, V, S) K ": " V "\n"
    static const char *memory_norm_fmt = _NORM_FMT(
        _("Heap_size", "%zu", ",") _("Free_size", "%zu", ",")
            _("Alloc_size", "%zu", ",") _("Greatest_free_size", "%zu", ",")
                _("Alloc_count", "%u", ",") _("Free_count", "%u", ""));
#undef _
#undef _NORM_FMT

    struct rte_malloc_socket_stats sock_stats;
    const char *output_fmt;

    if (argc > 0) {
        if (strcmp(argv[0], "--json") == 0) {
            output_fmt = memort_json_fmt;
        } else {
            unixctl_command_reply_error(fd, "Unknow option: %s\n", argv[0]);
            return;
        }
    } else {
        output_fmt = memory_norm_fmt;
    }
    if ((rte_malloc_get_socket_stats(rte_socket_id(), &sock_stats) < 0)) {
        unixctl_command_reply_error(fd, "Cannot get memory stats.\n");
        return;
    }
    unixctl_command_reply(fd, output_fmt, sock_stats.heap_totalsz_bytes,
                          sock_stats.heap_freesz_bytes,
                          sock_stats.heap_allocsz_bytes,
                          sock_stats.greatest_free_size, sock_stats.alloc_count,
                          sock_stats.free_count);
}

static void
coredump_enable(void) {
    pid_t pid;
    struct rlimit rlim_old, rlim_new;

    pid = getpid();
    rlim_new.rlim_cur = RLIM_INFINITY;
    rlim_new.rlim_max = RLIM_INFINITY;
    if (prlimit(pid, RLIMIT_CORE, &rlim_new, &rlim_old) != -1) {
        printf("RLIMIT_CORE: %ld/%ld\n", rlim_new.rlim_cur, rlim_new.rlim_max);
    } else {
        printf("RLIMIT_CORE: error\n");
    }
}

static void
init_module(void) {
    char *dpdk_argv[lb_cfg->dpdk.argc];
    int i;

    for (i = 0; i < lb_cfg->dpdk.argc; i++) {
        dpdk_argv[i] = strdup(lb_cfg->dpdk.argv[i]);
    }
    if (rte_eal_init(lb_cfg->dpdk.argc, dpdk_argv) < 0) {
        rte_exit(EXIT_FAILURE, "EAL init failed.\n");
    }
    rte_timer_subsystem_init();
    rte_pdump_init(NULL);

    lb_net_device_init();
    lcore_event_init();
    lb_arp_table_init();
    lb_service_table_init();
    lb_proto_tcp_init();
    lb_proto_udp_init();
    lb_proto_icmp_init();

    unixctl_fd = unixctl_server_create(SOCK_FILEPATH);
    if (unixctl_fd < 0) {
        rte_exit(EXIT_FAILURE, "Cannot create unxictl server: %s.\n",
                 SOCK_FILEPATH);
    }
}

static void
proc_check_running(void) {
    int fd;
    pid_t pid;
    char buf[32];

    fd = open(PID_FILEPATH, O_RDWR | O_CREAT);
    if (fd < 0) {
        printf("can not open %s\n", PID_FILEPATH);
        exit(-1);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        printf("%s is running.\n", lb_procname);
        exit(-1);
    }
    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);

    pid = getpid();
    snprintf(buf, sizeof(buf), "%d", pid);
    if (write(fd, buf, strlen(buf)) < 0) {
        printf("write pid to %s failed.\n", PID_FILEPATH);
        exit(-1);
    }
}

static void
create_daemon(void) {
    if (lb_daemon && daemon(0, 0) < 0) {
        printf("Cannot create daemon.\n");
        exit(-1);
    }
}

static void
usage(const char *progname) {
    printf("usage: %s [--conf=%s] [--daemon] [--version] [--help]\n", progname,
           DEFAULT_CONF_FILEPATH);
    exit(0);
}

static const char *
parse_progname(const char *arg) {
    char *p;
    if ((p = strrchr(arg, '/')) != NULL)
        return strdup(p + 1);
    return strdup(arg);
}

static void
parse_args(int argc, char *argv[]) {
    int i;

    lb_procname = parse_progname(argv[0]);
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--conf=", 7) == 0) {
            lb_cfgfile = strdup(argv[i] + 7);
        } else if (strncmp(argv[i], "--daemon", 8) == 0) {
            lb_daemon = TRUE;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("Version: %s\n", VERSION);
            exit(0);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(lb_procname);
        } else {
            printf("Unknow options: %s\n", argv[i]);
            usage(lb_procname);
        }
    }
    if (!lb_cfgfile) {
        lb_cfgfile = DEFAULT_CONF_FILEPATH;
    }
}

int
main(int argc, char **argv) {
    uint32_t lcore_id;

    parse_args(argc, argv);
    create_daemon();
    proc_check_running();
    lb_config_load(lb_cfgfile, lb_procname);
    init_module();
    coredump_enable();

    unixctl_command_register("memory", "[--json].", "Show memory usage.", 0, 1,
                             memory_cmd_cb);
    unixctl_command_register("version", "", "Show version.", 0, 0,
                             version_cmd_cb);
    unixctl_command_register("exit", "", "Kill jupiter-service.", 0, 0,
                             exit_cmd_cb);
    unixctl_command_register("quit", "", "Kill jupiter-service.", 0, 0,
                             exit_cmd_cb);
    unixctl_command_register("stop", "", "Kill jupiter-service.", 0, 0,
                             exit_cmd_cb);
    RTE_LOG(INFO, LB, "version: %s\n", VERSION);

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(worker_thread, NULL, lcore_id);
    }

    master_thread(NULL);
    rte_eal_mp_wait_lcore();
    return 0;
}

