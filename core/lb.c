/* Copyright (c) 2018. TIG developer. */

#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>
#include <rte_timer.h>

#include <cjson.h>
#include <unixctl_command.h>

#include "lb.h"
#include "lb_arp.h"
#include "lb_config.h"
#include "lb_device.h"
#include "lb_icmp.h"
#include "lb_icmp6.h"
#include "lb_ip_neighbour.h"
#include "lb_mib.h"
#include "lb_service.h"
#include "lb_tcp.h"
#include "lb_udp.h"

#define VERSION "0.1"

#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP 89
#endif

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

#define SOCK_FILEPATH "/var/run/jupiter.sock"
#define PID_FILEPATH "/var/run/jupiter.pid"
#define DEFAULT_CONF_FILEPATH "/etc/jupiter/jupiter.cfg"

static const char *lb_cfgfile = DEFAULT_CONF_FILEPATH;
static const char *lb_procname;
static int lb_daemon = 0;
static bool lb_loop = 1;

uint32_t lb_lcore_indexs[RTE_MAX_LCORE];

static void
lb_lcore_index_init(void) {
    uint32_t i = 0;
    uint32_t lcore_id;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) { lb_lcore_indexs[lcore_id] = i++; }
    lb_lcore_indexs[rte_get_master_lcore()] = i;
}

/* clock */
rte_atomic32_t lb_clock;
static struct rte_timer lb_clock_timer;

/* unixctl command */
static int unixctl_fd;
static struct rte_timer unixctl_timer;

static void
lb_clock_timer_cb(__attribute__((unused)) struct rte_timer *t,
                  __attribute__((unused)) void *arg) {
    rte_atomic32_inc(&lb_clock);
}

static int
lb_clock_timer_init(void) {
    uint64_t ticks;

    rte_atomic32_init(&lb_clock);
    rte_timer_init(&lb_clock_timer);
    /* 10ms */
    ticks = MS_TO_CYCLES((MS_PER_S + LB_CLOCK_HZ - 1) / LB_CLOCK_HZ);
    return rte_timer_reset(&lb_clock_timer, ticks, PERIODICAL,
                           rte_get_master_lcore(), lb_clock_timer_cb, NULL);
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
        log_err("%s(): unixctl_server_create failed, path = %s.\n", __func__,
                path);
        return -1;
    }
    rte_timer_init(&unixctl_timer);
    return rte_timer_reset(&unixctl_timer, MS_TO_CYCLES(5), PERIODICAL,
                           rte_get_master_lcore(), unixctl_server_timer_cb,
                           NULL);
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

static void
master_pkt_dispatch_dequeue_handle(struct lb_device *dev) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_mbuf *pkts[PKT_RX_BURST_MAX];
    uint16_t nb, i;
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv4_hdr *iph4;
    struct ipv6_hdr *iph6;

    nb = lb_device_pkt_dispatch_dequeue(dev, pkts, PKT_RX_BURST_MAX, lcore_id);
    for (i = 0; i < nb; i++) {
        m = pkts[i];
        eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
        switch (rte_be_to_cpu_16(eth->ether_type)) {
        case ETHER_TYPE_ARP:
            lb_arp_input(m, eth, dev);
            break;
        case ETHER_TYPE_IPv4:
            iph4 = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                                           sizeof(struct ether_hdr));
            switch (iph4->next_proto_id) {
            case IPPROTO_ICMP:
                lb_icmp_input(m, iph4, dev);
                break;
            default:
                lb_device_kni_xmit(dev, m);
            }
            break;
        case ETHER_TYPE_IPv6:
            iph6 = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
                                           sizeof(struct ether_hdr));
            switch (iph6->proto) {
            case IPPROTO_ICMPV6:
                lb_icmp6_input(m, iph6, dev);
                break;
            default:
                lb_device_kni_xmit(dev, m);
            }
            break;
        default:
            lb_device_kni_xmit(dev, m);
        }
    }
}

static void
worker_pkt_dispatch_dequeue_handle(struct lb_device *dev) {
    uint32_t lcore_id = rte_lcore_id();
    struct rte_mbuf *pkts[PKT_RX_BURST_MAX];
    uint16_t nb, i;
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv4_hdr *iph4;
    struct ipv6_hdr *iph6;

    nb = lb_device_pkt_dispatch_dequeue(dev, pkts, PKT_RX_BURST_MAX, lcore_id);
    for (i = 0; i < nb; i++) {
        m = pkts[i];
        eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
        switch (rte_be_to_cpu_16(eth->ether_type)) {
        case ETHER_TYPE_IPv4:
            iph4 = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                                           sizeof(struct ether_hdr));
            switch (iph4->next_proto_id) {
            case IPPROTO_TCP:
                // break;
            case IPPROTO_UDP:
                // break;
            default:
                rte_pktmbuf_free(m);
            }
            break;
        case ETHER_TYPE_IPv6:
            iph6 = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
                                           sizeof(struct ether_hdr));
            switch (iph6->proto) {
            case IPPROTO_TCP:
                // break;
            case IPPROTO_UDP:
                // break;
            default:
                rte_pktmbuf_free(m);
            }
            break;
        default:
            rte_pktmbuf_free(m);
        }
    }
}

static void
device_rx_queue_handle(struct lb_device *dev) {
    struct rte_mbuf *pkts[PKT_RX_BURST_MAX];
    uint16_t nb, i;
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv4_hdr *iph4;
    struct ipv6_hdr *iph6;

    nb = lb_device_rx_burst(dev, pkts, PKT_RX_BURST_MAX);
    for (i = 0; i < nb; i++) {
        m = pkts[i];
        eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
        switch (rte_be_to_cpu_16(eth->ether_type)) {
        case ETHER_TYPE_IPv4:
            iph4 = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                                           sizeof(struct ether_hdr));
            if (iph4->dst_addr == dev->ip4.as_u32) {
                lb_device_pkt_dispatch_enqueue(dev, m, rte_get_master_lcore());
                break;
            }
            if (iph4->time_to_live <= 1) {
                rte_pktmbuf_free(m);
                break;
            }
            if (rte_ipv4_frag_pkt_is_fragmented(iph4)) {
                rte_pktmbuf_free(m);
                break;
            }
            switch (iph4->next_proto_id) {
            case IPPROTO_TCP:
                lb_tcp_input(m, iph4, dev, 1);
                break;
            case IPPROTO_UDP:
                lb_udp_input(m, iph4, 1);
                break;
            case IPPROTO_ICMP:
            case IPPROTO_OSPFIGP:
            default:
                lb_device_pkt_dispatch_enqueue(dev, m, rte_get_master_lcore());
            }
            break;
        case ETHER_TYPE_IPv6:
            iph6 = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
                                           sizeof(struct ether_hdr));
            if (ip6_address_cmp((ip6_address_t *)&iph6->dst_addr, &dev->ip6) ==
                0) {
                lb_device_pkt_dispatch_enqueue(dev, m, rte_get_master_lcore());
                break;
            }
            if (iph6->hop_limits <= 1) {
                rte_pktmbuf_free(m);
                break;
            }
            if (rte_ipv6_frag_get_ipv6_fragment_header(iph6)) {
                rte_pktmbuf_free(m);
                break;
            }
            switch (iph6->proto) {
            case IPPROTO_TCP:
                lb_tcp_input(m, iph6, dev, 0);
                break;
            case IPPROTO_UDP:
                lb_udp_input(m, iph6, 0);
                break;
            case IPPROTO_OSPFIGP:
            case IPPROTO_ICMPV6:
            default:
                lb_device_pkt_dispatch_enqueue(dev, m, rte_get_master_lcore());
            }
            break;
        case ETHER_TYPE_ARP:
        default:
            lb_device_pkt_dispatch_enqueue(dev, m, rte_get_master_lcore());
        }
    }
}

static int
master_loop(__attribute__((unused)) void *arg) {
    struct lb_device *dev;
    uint32_t i;

    while (lb_loop) {
        for (i = 0; i < LB_DEV_NUM; i++) {
            dev = lb_devices[i];
            lb_device_flush(dev);
            lb_device_kni_rx_handle(dev);
            master_pkt_dispatch_dequeue_handle(dev);
        }
        RUN_ONCE_N_MS(rte_timer_manage, 1);
    }
    return 0;
}

static int
worker_loop(__attribute__((unused)) void *arg) {
    struct lb_device *dev;
    uint32_t i;

    while (lb_loop) {
        for (i = 0; i < LB_DEV_NUM; i++) {
            dev = lb_devices[i];
            lb_device_flush(dev);
            device_rx_queue_handle(dev);
            worker_pkt_dispatch_dequeue_handle(dev);
            RUN_ONCE_N_MS(rte_timer_manage, 1);
        }
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
        log_err("%s(): rte_eal_init failed.\n", __func__);
        return rc;
    }

    rte_timer_subsystem_init();
    rte_pdump_init(NULL);
    lb_lcore_index_init();

    if (lb_clock_timer_init() < 0) {
        log_err("%s(): lb_clock_timer_init failed.\n", __func__);
        return -1;
    }

    if (lb_mib_init() < 0) {
        log_err("%s(): lb_mib_init failed.\n", __func__);
        return -1;
    }

    if (unixctl_server_init(SOCK_FILEPATH) < 0) {
        RTE_LOG(ERR, USER1, "%s(): unixctl_server_init failed.\n", __func__);
        return rc;
    }

    if (lb_device_module_init(lb_cfg) < 0) {
        log_err("%s(): lb_device_module_init failed.\n", __func__);
        return -1;
    }

    if (lb_ip_neighbour_table_init() < 0) {
        log_err("%s(): lb_ip_neighbour_table_init failed.\n", __func__);
        return -1;
    }

    if (lb_service_module_init() < 0) {
        log_err("%s(): lb_service_module_init failed.\n", __func__);
        return -1;
    }

    if (lb_tcp_module_init() < 0) {
        log_err("%s(): lb_tcp_module_init failed.\n", __func__);
        return -1;
    }

    if (lb_udp_module_init() < 0) {
        log_err("%s(): lb_udp_module_init failed.\n", __func__);
        return -1;
    }

    rc = rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    if (rc < 0) {
        RTE_LOG(ERR, USER1, "%s(): Launch remote thread failed.\n", __func__);
        return rc;
    }

    return 0;
}

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
    int json_fmt = 0;
    int rc;
    struct rte_malloc_socket_stats sock_stats;
    uint32_t socket_id;

    rc = memory_arg_parse(argv, argc, &json_fmt);
    if (rc != argc) {
        unixctl_command_reply_error(fd, "Invalid parameter: %s.\n", argv[rc]);
        return;
    }
    if (json_fmt) {
        cJSON *array = cJSON_CreateArray();
        if (!array)
            return;
        for (socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; socket_id++) {
            if (rte_malloc_get_socket_stats(socket_id, &sock_stats) < 0)
                continue;
            cJSON *obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(obj, "Socket", socket_id);
            cJSON_AddNumberToObject(obj, "Heap_size",
                                    sock_stats.heap_totalsz_bytes);
            cJSON_AddNumberToObject(obj, "Free_size",
                                    sock_stats.heap_freesz_bytes);
            cJSON_AddNumberToObject(obj, "Alloc_size",
                                    sock_stats.heap_allocsz_bytes);
            cJSON_AddNumberToObject(obj, "Greatest_free_size",
                                    sock_stats.greatest_free_size);
            cJSON_AddNumberToObject(obj, "Alloc_count", sock_stats.alloc_count);
            cJSON_AddNumberToObject(obj, "Free_count", sock_stats.free_count);
            cJSON_AddItemToArray(array, obj);
        }
        char *str = cJSON_PrintUnformatted(array);
        unixctl_command_reply_string(fd, str);
        cJSON_free(str);
        cJSON_Delete(array);
    } else {
        for (socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; socket_id++) {
            if (rte_malloc_get_socket_stats(socket_id, &sock_stats) < 0) {
                unixctl_command_reply_error(fd, "Cannot get memory stats.\n");
                return;
            }
            unixctl_command_reply(fd, "Socket%u\n", socket_id);
            unixctl_command_reply(fd, "  Heap_size: %u\n",
                                  sock_stats.heap_totalsz_bytes);
            unixctl_command_reply(fd, "  Free_size: %u\n",
                                  sock_stats.heap_freesz_bytes);
            unixctl_command_reply(fd, "  Alloc_size: %u\n",
                                  sock_stats.heap_allocsz_bytes);
            unixctl_command_reply(fd, "  Greatest_free_size: %u\n",
                                  sock_stats.greatest_free_size);
            unixctl_command_reply(fd, "  Alloc_count: %u\n",
                                  sock_stats.alloc_count);
            unixctl_command_reply(fd, "  Free_count: %u\n",
                                  sock_stats.free_count);
        }
    }
}

UNIXCTL_CMD_REGISTER("memory", "[--json].", "Show memory information.", 0, 1,
                     memory_cmd_cb);

static void
quit_cmd_cb(__attribute__((unused)) int fd,
            __attribute__((unused)) char *argv[],
            __attribute__((unused)) int argc) {
    lb_loop = 0;
}

UNIXCTL_CMD_REGISTER("quit", "", "", 0, 0, quit_cmd_cb);