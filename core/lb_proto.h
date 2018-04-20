/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_PROTO_H__
#define __LB_PROTO_H__

#include <netinet/in.h>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

enum lb_proto_type {
    LB_IPPROTO_TCP,
    LB_IPPROTO_UDP,
    LB_IPPROTO_ICMP,
    LB_IPPROTO_MAX,
};

enum {
    LB_DIR_ORIGINAL,
    LB_DIR_REPLY,
    LB_DIR_MAX,
};

struct lb_proto {
    uint8_t id;
    enum lb_proto_type type;
    int (*init)(void);
    int (*fullnat_handle)(struct rte_mbuf *, struct ipv4_hdr *, uint16_t);
};

#define IPv4_HLEN(iph) (((iph)->version_ihl & IPV4_HDR_IHL_MASK) << 2)
#define TCP_HDR(iph) (struct tcp_hdr *)((char *)(iph) + IPv4_HLEN(iph))
#define UDP_HDR(iph) (struct udp_hdr *)((char *)(iph) + IPv4_HLEN(iph))

#define SYN(th) ((th)->tcp_flags & TCP_SYN_FLAG)
#define ACK(th) ((th)->tcp_flags & TCP_ACK_FLAG)
#define RST(th) ((th)->tcp_flags & TCP_RST_FLAG)
#define FIN(th) ((th)->tcp_flags & TCP_FIN_FLAG)

/*
 *	TCP option
 */

#define TCPOPT_NOP 1       /* Padding */
#define TCPOPT_EOL 0       /* End of options */
#define TCPOPT_MSS 2       /* Segment size negotiating */
#define TCPOPT_WINDOW 3    /* Window scaling */
#define TCPOPT_SACK_PERM 4 /* SACK Permitted */
#define TCPOPT_SACK 5      /* SACK Block */
#define TCPOPT_TIMESTAMP 8 /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG 19   /* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN 34 /* Fast open (RFC7413) */
#define TCPOPT_EXP 254     /* Experimental */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS 4
#define TCPOLEN_WINDOW 3
#define TCPOLEN_SACK_PERM 2
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_MD5SIG 18
#define TCPOLEN_FASTOPEN_BASE 2
#define TCPOLEN_EXP_FASTOPEN_BASE 4

#define TCPOLEN_TSTAMP_ALIGNED 12
#define TCPOLEN_WSCALE_ALIGNED 4
#define TCPOLEN_SACKPERM_ALIGNED 4
#define TCPOLEN_SACK_BASE 2
#define TCPOLEN_SACK_BASE_ALIGNED 4
#define TCPOLEN_SACK_PERBLOCK 8
#define TCPOLEN_MD5SIG_ALIGNED 20
#define TCPOLEN_MSS_ALIGNED 4

enum tcp_conntrack {
    TCP_CONNTRACK_NONE,
    TCP_CONNTRACK_SYN_SENT,
    TCP_CONNTRACK_SYN_RECV,
    TCP_CONNTRACK_ESTABLISHED,
    TCP_CONNTRACK_FIN_WAIT,
    TCP_CONNTRACK_CLOSE_WAIT,
    TCP_CONNTRACK_LAST_ACK,
    TCP_CONNTRACK_TIME_WAIT,
    TCP_CONNTRACK_CLOSE,
    TCP_CONNTRACK_LISTEN, /* obsolete */
#define TCP_CONNTRACK_SYN_SENT2 TCP_CONNTRACK_LISTEN
    TCP_CONNTRACK_MAX,
    TCP_CONNTRACK_IGNORE
};

extern struct lb_proto *lb_protos[LB_IPPROTO_MAX];
extern enum lb_proto_type lb_proto_types[IPPROTO_MAX];

#define LB_PROTO_REGISTER(p)                                                   \
    __attribute__((constructor)) static void proto_register_##p(void) {        \
        lb_protos[p.type] = &p;                                                \
        lb_proto_types[p.id] = p.type;                                         \
    }

static inline struct lb_proto *
lb_proto_get(uint8_t id) {
    return lb_protos[lb_proto_types[id]];
}

int lb_proto_init(void);

#endif

