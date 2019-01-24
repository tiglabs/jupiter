/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_TCP_H__
#define __LB_TCP_H__

#include <rte_eth_ctrl.h>
#include <rte_tcp.h>

#include "lb.h"
#include "lb_connection.h"

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

/* TOA */

#define TCPOPT_TOA 200
#define TCPOPT_TOA6 201

#define TCPOLEN_TOA 8   /* |opcode|size|ip+port| = 1 + 1 + 6 */
#define TCPOLEN_TOA6 20 /* |opcode|size|ip+port| = 1 + 1 + 18 */

struct tcp_opt_toa {
    uint8_t optcode;
    uint8_t optsize;
    uint16_t port;
    uint32_t addr;
} __attribute__((__packed__));

struct tcp_opt_toa6 {
    uint8_t optcode;
    uint8_t optsize;
    uint16_t port;
    uint32_t addr[4];
} __attribute__((__packed__));

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

#define sNO TCP_CONNTRACK_NONE
#define sSS TCP_CONNTRACK_SYN_SENT
#define sSR TCP_CONNTRACK_SYN_RECV
#define sES TCP_CONNTRACK_ESTABLISHED
#define sFW TCP_CONNTRACK_FIN_WAIT
#define sCW TCP_CONNTRACK_CLOSE_WAIT
#define sLA TCP_CONNTRACK_LAST_ACK
#define sTW TCP_CONNTRACK_TIME_WAIT
#define sCL TCP_CONNTRACK_CLOSE
#define sS2 TCP_CONNTRACK_SYN_SENT2
#define sIV TCP_CONNTRACK_MAX
#define sIG TCP_CONNTRACK_IGNORE

enum tcp_bit_set {
    TCP_SYN_SET,
    TCP_SYNACK_SET,
    TCP_FIN_SET,
    TCP_ACK_SET,
    TCP_RST_SET,
    TCP_NONE_SET,
};

enum {
    TCP_TIMER_TIMEOUT,
    TCP_TIMER_RETRASYN,
    TCP_TIMER_MAX,
};

#define TCP_RETRASYN_TIMEOUT_INIT 1000u   /*ms*/
#define TCP_RETRASYN_TIMEOUT_MAX 120000u /*ms*/

void tcp_conn_timer_reset(struct lb_connection *conn, uint32_t timer_id,
                          uint32_t timeout);
void tcp_conn_timer_stop(struct lb_connection *conn, uint32_t timer_id);

struct lb_connection *tcp_conn_create(void *iphdr, struct tcp_hdr *th,
                                      uint8_t is_synproxy, uint8_t is_ip4);

void tcp_set_conntrack_state(struct lb_connection *conn,
                             const struct tcp_hdr *th, lb_direction_t dir);

void lb_tcp_input(struct rte_mbuf *m, void *iphdr, struct lb_device *dev,
                  uint8_t is_ip4);

int lb_tcp_module_init(void);

#endif