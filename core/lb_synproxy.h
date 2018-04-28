/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_SYNPROXY_H__
#define __LB_SYNPROXY_H__

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

struct lb_conn;
struct lb_conn_table;
struct lb_device;

/* Add MASKs for TCP OPT in "data" coded in cookie */
/* |[21][20][19-16][15-0]|
 * [21]    SACK
 * [20]    TimeStamp
 * [19-16] snd_wscale
 * [15-0]  MSSIND
 */
#define LB_SYNPROXY_OTHER_BITS 12
#define LB_SYNPROXY_OTHER_MASK (((uint32_t)1 << LB_SYNPROXY_OTHER_BITS) - 1)
#define LB_SYNPROXY_MSS_BITS 12
#define LB_SYNPROXY_MSS_MASK ((uint32_t)0xf << LB_SYNPROXY_MSS_BITS)

#define LB_SYNPROXY_SACKOK_BIT 21
#define LB_SYNPROXY_SACKOK_MASK ((uint32_t)1 << LB_SYNPROXY_SACKOK_BIT)

#define LB_SYNPROXY_TSOK_BIT 20
#define LB_SYNPROXY_TSOK_MASK ((uint32_t)1 << LB_SYNPROXY_TSOK_BIT)

#define LB_SYNPROXY_SND_WSCALE_BITS 16
#define LB_SYNPROXY_SND_WSCALE_MASK                                            \
    ((uint32_t)0xf << LB_SYNPROXY_SND_WSCALE_BITS)

#define LB_SYNPROXY_WSCALE_MAX 14

struct synproxy_options {
    uint16_t snd_wscale : 8, /* Window scaling received from sender          */
        tstamp_ok : 1,       /* TIMESTAMP seen on SYN packet                 */
        wscale_ok : 1,       /* Wscale seen on SYN packet                    */
        sack_ok : 1;         /* SACK seen on SYN packet                      */
    uint16_t mss_clamp;      /* Maximal mss, negotiated at connection setup  */
};

struct synproxy {
    struct rte_mbuf *syn_mbuf;
    struct rte_mbuf *ack_mbuf;
    uint32_t syn_retry;
    uint32_t isn;
    uint32_t oft;
};

uint32_t synproxy_cookie_ipv4_init_sequence(struct ipv4_hdr *iph,
                                            struct tcp_hdr *th,
                                            struct synproxy_options *opts);
uint32_t synproxy_cookie_ipv4_check(struct ipv4_hdr *iph, struct tcp_hdr *th,
                                    struct synproxy_options *opts);
int synproxy_recv_backend_synack(struct rte_mbuf *m, struct ipv4_hdr *iph,
                                 struct tcp_hdr *th, struct lb_conn *conn,
                                 struct lb_device *dev);
int synproxy_recv_client_ack(struct rte_mbuf *m, struct ipv4_hdr *iph,
                             struct tcp_hdr *th, struct lb_conn_table *ct,
                             struct lb_device *dev);
int synproxy_recv_client_syn(struct rte_mbuf *m, struct ipv4_hdr *iph,
                             struct tcp_hdr *th, struct lb_device *dev);
void synproxy_seq_adjust_client(struct tcp_hdr *th, struct synproxy *proxy);
void synproxy_seq_adjust_backend(struct tcp_hdr *th, struct synproxy *proxy);

#endif
