/* Copyright (c) 2018. TIG developer. */

#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_pdump.h>
#include <rte_timer.h>

#include <unixctl_command.h>

#include "lb_arp.h"
#include "lb_clock.h"
#include "lb_config.h"
#include "lb_device.h"
#include "lb_format.h"
#include "lb_parser.h"
#include "lb_proto.h"
#include "lb_service.h"

#define VERSION "0.1"

#define RUN_ONCE_N_MS(f, n)                                                    \
    do {                                                                       \
        static uint64_t last_tsc = 0;                                          \
        uint64_t curr_tsc;                                                     \
                                                                               \
        curr_tsc = rte_rdtsc();                                                \
        if (curr_tsc - last_tsc >= MS_TO_CYCLES(n)) {                          \
            f();                                                               \
            last_tsc = curr_tsc;                                               \
        }                                                                      \
    } while (0)

/* unixctl command */
static int unixctl_fd;
static struct rte_timer unixctl_timer;

/* clock */
rte_atomic32_t lb_clock;
static struct rte_timer lb_clock_timer;

#define SOCK_FILEPATH "/var/run/jupiter.sock"
#define PID_FILEPATH "/var/run/jupiter.pid"
#define DEFAULT_CONF_FILEPATH "/etc/jupiter/jupiter.cfg"

static const char *lb_cfgfile = DEFAULT_CONF_FILEPATH;
static const char *lb_procname;
static int lb_daemon = 0;
static int lb_loop = 1;

static void
lb_clock_timer_cb(__attribute__((unused)) struct rte_timer *t,
                  __attribute__((unused)) void *arg) {
    rte_atomic32_t *clock = arg;

    rte_atomic32_inc(clock);
}

static int
lb_clock_timer_init(void) {
    uint64_t ticks;

    rte_atomic32_init(&lb_clock);
    rte_timer_init(&lb_clock_timer);
    /* 10ms */
    ticks = MS_TO_CYCLES((MS_PER_S + LB_CLOCK_HZ - 1) / LB_CLOCK_HZ);
    return rte_timer_reset(&lb_clock_timer, ticks, PERIODICAL,
                           rte_get_master_lcore(), lb_clock_timer_cb,
                           &lb_clock);
}

static void
unixctl_server_timer_cb(__attribute__((unused)) struct rte_timer *t,
                        __attribute__((unused)) void *arg) {
    unixctl_server_run_once(unixctl_fd);
}

static int
unixctl_server_init(const char *path) {
    unixctl_fd = unixctl_server_create(path);
    if (unixctl_fd < 0) {
        RTE_LOG(ERR, USER1, "%s(): unixctl_server_create failed, path = %s.\n",
                __func__, path);
        return -1;
    }
    rte_timer_init(&unixctl_timer);
    return rte_timer_reset(&unixctl_timer, MS_TO_CYCLES(5), PERIODICAL,
                           rte_get_master_lcore(), unixctl_server_timer_cb,
                           NULL);
}

static void
handle_packets(struct rte_mbuf **pkts, uint16_t n, uint16_t port_id) {
    uint16_t i;
    struct lb_device *dev;
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv4_hdr *iph;
    struct lb_proto *p;

    dev = &lb_devices[port_id];
    for (i = 0; i < n; i++) {
        m = pkts[i];

        eth = rte_pktmbuf_mtod_offset(m, struct ether_hdr *, 0);
        switch (rte_be_to_cpu_16(eth->ether_type)) {
        case ETHER_TYPE_ARP:
            if (rte_ring_enqueue(dev->ring, m) < 0) {
                rte_pktmbuf_free(m);
            }
            break;
        case ETHER_TYPE_IPv4:
            iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, ETHER_HDR_LEN);
            if (iph->dst_addr == dev->ipv4) {
                if (rte_ring_enqueue(dev->ring, m) < 0) {
                    rte_pktmbuf_free(m);
                }
            } else {
                p = lb_proto_get(iph->next_proto_id);
                if (p != NULL) {
                    p->fullnat_handle(m, iph, port_id);
                } else {
                    rte_pktmbuf_free(m);
                }
            }
            break;
        default:
            rte_pktmbuf_free(m);
        }
    }
}
/*
#include <rte_tcp.h>

#define IPV4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)
#define TCP_HDR(iph) (struct tcp_hdr *)((char *)(iph) + IPV4_HLEN(iph))

static int
drop_ack(struct rte_mbuf *m)
{
        struct ether_hdr *eth;
        struct ipv4_hdr *iph;
        struct tcp_hdr *th;

        eth = rte_pktmbuf_mtod_offset(m, struct ether_hdr *, 0);
        if (eth->ether_type != rte_be_to_cpu_16(0x0800))
                return 0;
        iph = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, ETHER_HDR_LEN);
        if (iph->next_proto_id != IPPROTO_TCP)
                return 0;
        th = TCP_HDR(iph);
        if (th->tcp_flags & TCP_ACK_FLAG && !(th->tcp_flags & TCP_SYN_FLAG) &&
!(th->tcp_flags & TCP_FIN_FLAG)) return 1; return 0;
}*/

static int
master_loop(__attribute__((unused)) void *arg) {
    uint32_t lcore_id;
    uint16_t i, j, nb_ports;
    uint16_t nb_ctx;
    struct {
        uint16_t port_id;
        uint16_t txq_id;
        struct rte_eth_dev_tx_buffer *tx_buffer;
        struct rte_kni *kni;
        struct rte_ring *ring;
    } ctx[RTE_MAX_ETHPORTS];
    struct rte_mbuf *pkts[PKT_MAX_BURST];
    uint32_t n, nb_tx;
    struct ether_hdr *ethh;

    lcore_id = rte_lcore_id();
    nb_ctx = 0;
    nb_ports = rte_eth_dev_count();
    for (i = 0; i < nb_ports; i++) {
        if (lb_devices[i].type != LB_DEV_T_NORM &&
            lb_devices[i].type != LB_DEV_T_MASTER) {
            continue;
        }

        ctx[nb_ctx].port_id = i;
        ctx[nb_ctx].txq_id = lb_devices[i].lcore_conf[lcore_id].txq_id;
        ctx[nb_ctx].tx_buffer = lb_devices[i].tx_buffer[lcore_id];
        ctx[nb_ctx].kni = lb_devices[i].kni;
        ctx[nb_ctx].ring = lb_devices[i].ring;

        nb_ctx++;
    }

    if (nb_ctx == 0) {
        RTE_LOG(INFO, USER1, "%s(): master thread exit early.\n", __func__);
        return 0;
    }

    RTE_LOG(INFO, USER1, "%s(): master thread started.\n", __func__);

    while (lb_loop) {
        for (i = 0; i < nb_ctx; i++) {
            rte_kni_handle_request(ctx[i].kni);

            n = rte_kni_rx_burst(ctx[i].kni, pkts, PKT_MAX_BURST);

            for (j = 0; j < n; j++) {
                rte_eth_tx_buffer(n, ctx[i].txq_id, ctx[i].tx_buffer, pkts[j]);
            }

            rte_eth_tx_buffer_flush(ctx[i].port_id, ctx[i].txq_id,
                                    ctx[i].tx_buffer);

            n = rte_ring_dequeue_burst(ctx[i].ring, (void **)pkts,
                                       PKT_MAX_BURST, NULL);
            for (j = 0; j < n; j++) {
                ethh = rte_pktmbuf_mtod_offset(pkts[j], struct ether_hdr *, 0);
                if (ethh->ether_type == rte_be_to_cpu_16(ETHER_TYPE_ARP)) {
                    lb_arp_input(pkts[j], ctx[i].port_id);
                }
            }
            nb_tx = rte_kni_tx_burst(ctx[i].kni, pkts, n);
            for (j = nb_tx; j < n; j++) {
                rte_pktmbuf_free(pkts[j]);
            }
        }

        RUN_ONCE_N_MS(rte_timer_manage, 1);
    }

    return 0;
}

static int
worker_loop(__attribute__((unused)) void *arg) {
    uint32_t lcore_id;
    uint16_t i, nb_ports;
    uint16_t nb_ctx;
    struct {
        uint16_t port_id;
        uint16_t rxq_id, txq_id;
        struct rte_eth_dev_tx_buffer *tx_buffer;
        struct rte_mbuf *rx_pkts[PKT_MAX_BURST];
        uint32_t n;
    } ctx[RTE_MAX_ETHPORTS];

    lcore_id = rte_lcore_id();
    nb_ctx = 0;
    nb_ports = rte_eth_dev_count();
    for (i = 0; i < nb_ports; i++) {
        if (lb_devices[i].type != LB_DEV_T_NORM &&
            lb_devices[i].type != LB_DEV_T_MASTER) {
            continue;
        }

        ctx[nb_ctx].port_id = i;
        ctx[nb_ctx].rxq_id = lb_devices[i].lcore_conf[lcore_id].rxq_id;
        ctx[nb_ctx].txq_id = lb_devices[i].lcore_conf[lcore_id].txq_id;
        ctx[nb_ctx].tx_buffer = lb_devices[i].tx_buffer[lcore_id];

        nb_ctx++;
    }

    if (nb_ctx == 0) {
        RTE_LOG(INFO, USER1, "%s(): worker%u thread exit early.\n", __func__,
                lcore_id);
        return 0;
    }

    RTE_LOG(INFO, USER1, "%s(): worker%u thread started.\n", __func__,
            lcore_id);

    while (lb_loop) {
        for (i = 0; i < nb_ctx; i++) {
            rte_eth_tx_buffer_flush(ctx[i].port_id, ctx[i].txq_id,
                                    ctx[i].tx_buffer);
        }

        for (i = 0; i < nb_ctx; i++) {
            ctx[i].n = rte_eth_rx_burst(ctx[i].port_id, ctx[i].rxq_id,
                                        ctx[i].rx_pkts, PKT_MAX_BURST);
        }

        for (i = 0; i < nb_ctx; i++) {
            handle_packets(ctx[i].rx_pkts, ctx[i].n, ctx[i].port_id);
        }

        RUN_ONCE_N_MS(rte_timer_manage, 1);
    }

    return 0;
}

static int
main_loop(void *arg) {
    if (rte_get_master_lcore() == rte_lcore_id()) {
        return master_loop(arg);
    } else {
        return worker_loop(arg);
    }
}

static void
usage(const char *progname) {
    printf("usage: %s [--conf=%s] [--daemon] [--version] [--help]\n", progname,
           DEFAULT_CONF_FILEPATH);
    exit(0);
}

static void
parse_args(int argc, char **argv) {
    int i;

    if ((lb_procname = strrchr(argv[0], '/')) != NULL)
        lb_procname = strdup(lb_procname + 1);
    else
        lb_procname = strdup(argv[0]);

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--conf=", 7) == 0) {
            lb_cfgfile = strdup(argv[i] + 7);
        } else if (strncmp(argv[i], "--daemon", 8) == 0) {
            lb_daemon = 1;
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
}

static void
create_daemon(void) {
    if (daemon(0, 0) < 0) {
        printf("%s(): Daemon failed.\n", __func__);
        exit(-1);
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

int
main(int argc, char **argv) {
    int rc;

    parse_args(argc, argv);
    if (lb_daemon)
        create_daemon();

    proc_check_running();

    rc = lb_config_file_load(lb_cfgfile);
    if (rc < 0) {
        printf("%s(): Load config file %s failed.\n", __func__, lb_cfgfile);
        return rc;
    }

    rc = rte_eal_init(lb_cfg->dpdk.argc, lb_cfg->dpdk.argv);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): rte_eal_init failed.\n", __func__);
        return rc;
    }

    rte_timer_subsystem_init();
    rte_pdump_init(NULL);

    rc = lb_device_init(lb_cfg->devices, lb_cfg->nb_decices);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): lb_device_init failed.\n", __func__);
        return rc;
    }

    rc = lb_arp_init();
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): lb_arp_init failed.\n", __func__);
        return rc;
    }

    rc = lb_clock_timer_init();
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): lb_clock_timer_init failed.\n", __func__);
        return rc;
    }

    rc = unixctl_server_init(SOCK_FILEPATH);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): unixctl_server_init failed.\n", __func__);
        return rc;
    }

    rc = lb_service_init();
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): lb_service_init failed.\n", __func__);
        return rc;
    }

    rc = lb_proto_init();
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): lb_proto_init failed.\n", __func__);
        return rc;
    }

    rc = rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): Launch remote thread failed.\n", __func__);
        return rc;
    }

    return 0;
}

static void
exit_cmd_cb(__attribute__((unused)) int fd,
            __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    lb_loop = 0;
}

UNIXCTL_CMD_REGISTER("exit", "", "", 0, 0, exit_cmd_cb);

static void
quit_cmd_cb(__attribute__((unused)) int fd,
            __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    lb_loop = 0;
}

UNIXCTL_CMD_REGISTER("quit", "", "", 0, 0, quit_cmd_cb);

static void
stop_cmd_cb(__attribute__((unused)) int fd,
            __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    lb_loop = 0;
}

UNIXCTL_CMD_REGISTER("stop", "", "", 0, 0, stop_cmd_cb);

static void
version_cmd_cb(__attribute__((unused)) int fd,
               __attribute__((unused)) char *argv[],
               __attribute__((unused)) int argc) {
    unixctl_command_reply(fd, "%s\n", VERSION);
}

UNIXCTL_CMD_REGISTER("version", "", "", 0, 0, version_cmd_cb);

static int
memory_arg_parse(char *argv[], int argc, int *json_fmt) {
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
memory_cmd_cb(int fd, char *argv[], int argc) {
    int json_fmt = 0, json_first_obj = 1;
    int rc;
    struct rte_malloc_socket_stats sock_stats;
    uint32_t socket_id;

    rc = memory_arg_parse(argv, argc, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }

    if (json_fmt)
        unixctl_command_reply(fd, "[");

    for (socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; socket_id++) {
        if (rte_malloc_get_socket_stats(socket_id, &sock_stats) < 0) {
            unixctl_command_reply_error(fd, "Cannot get memory stats.\n");
            return;
        }

        if (!json_fmt) {
            unixctl_command_reply(fd, "Socket%u\n", socket_id);
            unixctl_command_reply(fd, NORM_KV_64_FMT("  Heap_size", "\n"),
                                  (uint64_t)sock_stats.heap_totalsz_bytes);
            unixctl_command_reply(fd, NORM_KV_64_FMT("  Free_size", "\n"),
                                  (uint64_t)sock_stats.heap_freesz_bytes);
            unixctl_command_reply(fd, NORM_KV_64_FMT("  Alloc_size", "\n"),
                                  (uint64_t)sock_stats.heap_allocsz_bytes);
            unixctl_command_reply(
                fd, NORM_KV_64_FMT("  Greatest_free_size", "\n"),
                (uint64_t)sock_stats.greatest_free_size);
            unixctl_command_reply(fd, NORM_KV_32_FMT("  Alloc_count", "\n"),
                                  (uint32_t)sock_stats.alloc_count);
            unixctl_command_reply(fd, NORM_KV_32_FMT("  Free_count", "\n"),
                                  (uint32_t)sock_stats.free_count);
        } else {
            unixctl_command_reply(fd, json_first_obj ? "{" : ",{");
            json_first_obj = 0;
            unixctl_command_reply(fd, JSON_KV_32_FMT("Socket", ","), socket_id);
            unixctl_command_reply(fd, JSON_KV_64_FMT("Heap_size", ","),
                                  (uint64_t)sock_stats.heap_totalsz_bytes);
            unixctl_command_reply(fd, JSON_KV_64_FMT("Free_size", ","),
                                  (uint64_t)sock_stats.heap_freesz_bytes);
            unixctl_command_reply(fd, JSON_KV_64_FMT("Alloc_size", ","),
                                  (uint64_t)sock_stats.heap_allocsz_bytes);
            unixctl_command_reply(fd, JSON_KV_64_FMT("Greatest_free_size", ","),
                                  (uint64_t)sock_stats.greatest_free_size);
            unixctl_command_reply(fd, JSON_KV_32_FMT("Alloc_count", ","),
                                  (uint32_t)sock_stats.alloc_count);
            unixctl_command_reply(fd, JSON_KV_32_FMT("Free_count", ""),
                                  (uint32_t)sock_stats.free_count);
            unixctl_command_reply(fd, "}");
        }
    }
    if (json_fmt)
        unixctl_command_reply(fd, "]\n");
}

UNIXCTL_CMD_REGISTER("memory", "[--json].", "Show memory information.", 0, 1,
                     memory_cmd_cb);

