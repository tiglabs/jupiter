/* Copyright (c) 2018. TIG developer. */

#include <rte_cycles.h>
#include <rte_eth_ctrl.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_tcp.h>

#include <unixctl_command.h>

#include "lb_clock.h"
#include "lb_conn.h"
#include "lb_device.h"
#include "lb_format.h"
#include "lb_proto.h"
#include "lb_synproxy.h"
#include "lb_tcp_secret_seq.h"
#include "lb_toa.h"

//#define TCP_DEBUG
#ifdef TCP_DEBUG
#define TCP_PRINT(...)                                                         \
    do {                                                                       \
        fprintf(stderr, "[core%u]TCP: ", rte_lcore_id());                      \
        fprintf(stderr, __VA_ARGS__);                                          \
    } while (0)
#else
#define TCP_PRINT(...)                                                         \
    do {                                                                       \
    } while (0)
#endif

#define IPv4_TCP_FMT IPv4_BE_FMT ":%u -> " IPv4_BE_FMT ":%u [%c%c%c%c]"
#define IPv4_TCP_ARG(iph, th)                                                  \
    IPv4_BE_ARG((iph)->src_addr), rte_be_to_cpu_16((th)->src_port),            \
        IPv4_BE_ARG((iph)->dst_addr), rte_be_to_cpu_16((th)->dst_port),        \
        SYN(th) ? 'S' : '-', ACK(th) ? 'A' : '-', RST(th) ? 'R' : '-',         \
        FIN(th) ? 'F' : '-'

#define TCP_MAX_CONN (1 << 22)

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

/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:	initial state
 * SYN_SENT:	SYN-only packet seen
 * SYN_SENT2:	SYN-only packet seen from reply dir, simultaneous open
 * SYN_RECV:	SYN-ACK packet seen
 * ESTABLISHED:	ACK packet seen
 * FIN_WAIT:	FIN packet seen
 * CLOSE_WAIT:	ACK seen (after FIN)
 * LAST_ACK:	FIN seen (after FIN)
 * TIME_WAIT:	last ACK seen
 * CLOSE:	closed connection (RST)
 *
 * Packets marked as IGNORED (sIG):
 *	if they may be either invalid or valid
 *	and the receiver may send back a connection
 *	closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *	if we regard them as truly invalid packets
 */
static const uint8_t tcp_conntracks[2][6][TCP_CONNTRACK_MAX] = {
    {/* ORIGINAL */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*syn*/ {sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2},
     /*
      *	sNO -> sSS	Initialize a new connection
      *	sSS -> sSS	Retransmitted SYN
      *	sS2 -> sS2	Late retransmitted SYN
      *	sSR -> sIG
      *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
      *			are errors. Receiver will reply with RST
      *			and close the connection.
      *			Or we are not in sync and hold a dead connection.
      *	sFW -> sIG
      *	sCW -> sIG
      *	sLA -> sIG
      *	sTW -> sSS	Reopened connection (RFC 1122).
      *	sCL -> sSS
      */
     /*          sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*synack*/ {sIV, sIV, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR},
     /*
      *	sNO -> sIV	Too late and no reason to do anything
      *	sSS -> sIV	Client can't send SYN and then SYN/ACK
      *	sS2 -> sSR	SYN/ACK sent to SYN2 in simultaneous open
      *	sSR -> sIG
      *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
      *			are errors. Receiver will reply with RST
      *			and close the connection.
      *			Or we are not in sync and hold a dead connection.
      *	sFW -> sIG
      *	sCW -> sIG
      *	sLA -> sIG
      *	sTW -> sIG
      *	sCL -> sIG
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*fin*/ {sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV},
     /*
      *	sNO -> sIV	Too late and no reason to do anything...
      *	sSS -> sIV	Client migth not send FIN in this state:
      *			we enforce waiting for a SYN/ACK reply first.
      *	sS2 -> sIV
      *	sSR -> sFW	Close started.
      *	sES -> sFW
      *	sFW -> sLA	FIN seen in both directions, waiting for
      *			the last ACK.
      *			Migth be a retransmitted FIN as well...
      *	sCW -> sLA
      *	sLA -> sLA	Retransmitted FIN. Remain in the same state.
      *	sTW -> sTW
      *	sCL -> sCL
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*ack*/ {sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV},
     /*
      *	sNO -> sES	Assumed.
      *	sSS -> sIV	ACK is invalid: we haven't seen a SYN/ACK yet.
      *	sS2 -> sIV
      *	sSR -> sES	Established state is reached.
      *	sES -> sES	:-)
      *	sFW -> sCW	Normal close request answered by ACK.
      *	sCW -> sCW
      *	sLA -> sTW	Last ACK detected.
      *	sTW -> sTW	Retransmitted last ACK. Remain in the same state.
      *	sCL -> sCL
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*rst*/ {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
     /*none*/ {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV}},
    {/* REPLY */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*syn*/ {sIV, sS2, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sS2},
     /*
      *	sNO -> sIV	Never reached.
      *	sSS -> sS2	Simultaneous open
      *	sS2 -> sS2	Retransmitted simultaneous SYN
      *	sSR -> sIV	Invalid SYN packets sent by the server
      *	sES -> sIV
      *	sFW -> sIV
      *	sCW -> sIV
      *	sLA -> sIV
      *	sTW -> sIV	Reopened connection, but server may not do it.
      *	sCL -> sIV
      */
     /*          sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*synack*/ {sIV, sSR, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sSR},
     /*
      *	sSS -> sSR	Standard open.
      *	sS2 -> sSR	Simultaneous open
      *	sSR -> sSR	Retransmitted SYN/ACK.
      *	sES -> sIG	Late retransmitted SYN/ACK?
      *	sFW -> sIG	Might be SYN/ACK answering ignored SYN
      *	sCW -> sIG
      *	sLA -> sIG
      *	sTW -> sIG
      *	sCL -> sIG
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*fin*/ {sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV},
     /*
      *	sSS -> sIV	Server might not send FIN in this state.
      *	sS2 -> sIV
      *	sSR -> sFW	Close started.
      *	sES -> sFW
      *	sFW -> sLA	FIN seen in both directions.
      *	sCW -> sLA
      *	sLA -> sLA	Retransmitted FIN.
      *	sTW -> sTW
      *	sCL -> sCL
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*ack*/ {sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG},
     /*
      *	sSS -> sIG	Might be a half-open connection.
      *	sS2 -> sIG
      *	sSR -> sSR	Might answer late resent SYN.
      *	sES -> sES	:-)
      *	sFW -> sCW	Normal close request answered by ACK.
      *	sCW -> sCW
      *	sLA -> sTW	Last ACK detected.
      *	sTW -> sTW	Retransmitted last ACK.
      *	sCL -> sCL
      */
     /*       sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2 */
     /*rst*/ {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
     /*none*/ {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV}}};

uint32_t tcp_timeouts[TCP_CONNTRACK_MAX] = {
    [TCP_CONNTRACK_NONE] = 2 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_SYN_SENT] = 30 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_SYN_RECV] = 30 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_ESTABLISHED] = 90 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_FIN_WAIT] = 30 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_CLOSE_WAIT] = 30 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_LAST_ACK] = 30 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_TIME_WAIT] = 0 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_CLOSE] = 0 * LB_CLOCK_HZ,
    [TCP_CONNTRACK_LISTEN] = 0 * LB_CLOCK_HZ,
};

static const char *const tcp_conntrack_names[] = {
    "NONE",       "SYN_SENT", "SYN_RECV",  "ESTABLISHED", "FIN_WAIT",
    "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",       "SYN_SENT2",
};

static struct lb_conn_table lb_conn_tbls[RTE_MAX_LCORE];

static inline uint32_t
get_conntrack_index(const struct tcp_hdr *th) {
    if (RST(th))
        return TCP_RST_SET;
    else if (SYN(th))
        return (ACK(th) ? TCP_SYNACK_SET : TCP_SYN_SET);
    else if (FIN(th))
        return TCP_FIN_SET;
    else if (ACK(th))
        return TCP_ACK_SET;
    else
        return TCP_NONE_SET;
}

static void
tcp_set_conntack_state(struct lb_conn *conn, struct tcp_hdr *th, int dir) {
    uint32_t index;
    uint32_t old_state;
    uint32_t new_state;
    uint32_t lcore_id = rte_lcore_id();
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t timeout;

    index = get_conntrack_index(th);
    old_state = conn->state;
    new_state = tcp_conntracks[dir][index][old_state];
    if (!(conn->flags & LB_CONN_F_ACTIVE) &&
        (new_state == TCP_CONNTRACK_ESTABLISHED)) {
        conn->flags |= LB_CONN_F_ACTIVE;
        rte_atomic32_add(&rs->active_conns, 1);
        rte_atomic32_add(&vs->active_conns, 1);
        vs->stats[lcore_id].conns += 1;
        rs->stats[lcore_id].conns += 1;
    } else if ((conn->flags & LB_CONN_F_ACTIVE) &&
               (new_state != TCP_CONNTRACK_ESTABLISHED)) {
        conn->flags &= ~LB_CONN_F_ACTIVE;
        rte_atomic32_add(&rs->active_conns, -1);
        rte_atomic32_add(&vs->active_conns, -1);
    }
    if (new_state < TCP_CONNTRACK_MAX) {
        conn->state = new_state;
        conn->timeout = tcp_timeouts[new_state];
    }
    if (new_state == TCP_CONNTRACK_ESTABLISHED) {
        timeout = vs->est_timeout;
        conn->timeout =
            timeout != 0 ? timeout : tcp_timeouts[TCP_CONNTRACK_ESTABLISHED];
    }

    if (conn->state == TCP_CONNTRACK_CLOSE ||
        conn->state == TCP_CONNTRACK_TIME_WAIT) {
        TCP_PRINT("conn:{cip=%u.%u.%u.%u cport=%u, "
                  "vip=%u.%u.%u.%u, vport=%u, lip=%u.%u.%u.%u, "
                  "lport=%u,rip=%u.%u.%u.%u, rport=%u, %c%c%c%c, state=%s}\n",
                  IPv4_BE_ARG(conn->cip), rte_be_to_cpu_16(conn->cport),
                  IPv4_BE_ARG(conn->vip), rte_be_to_cpu_16(conn->vport),
                  IPv4_BE_ARG(conn->lip), rte_be_to_cpu_16(conn->lport),
                  IPv4_BE_ARG(conn->rip), rte_be_to_cpu_16(conn->rport),
                  SYN(th) ? 'S' : '-', ACK(th) ? 'A' : '-', RST(th) ? 'R' : '-',
                  FIN(th) ? 'F' : '-',
                  conn->state == TCP_CONNTRACK_CLOSE ? "close" : "timewait");
    }
}

static void
tcp_set_packet_stats(struct lb_conn *conn, struct rte_mbuf *m, uint8_t dir) {
    struct lb_real_service *rs;
    struct lb_virt_service *vs;
    uint32_t cid;

    cid = rte_lcore_id();
    rs = conn->real_service;
    vs = rs->virt_service;
    vs->stats[cid].bytes[dir] += m->pkt_len;
    vs->stats[cid].packets[dir] += 1;
    rs->stats[cid].bytes[dir] += m->pkt_len;
    rs->stats[cid].packets[dir] += 1;
}

static void
tcp_conn_timer_task_cb(struct lb_conn *conn) {
    struct rte_mbuf *mcopy;
    struct ipv4_hdr *iph;

    if ((conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT) &&
        (conn->proxy.syn_mbuf != NULL)) {
        if (conn->proxy.syn_retry == 0) {
            rte_pktmbuf_free(conn->proxy.syn_mbuf);
            conn->proxy.syn_mbuf = NULL;
        } else {
            conn->proxy.syn_retry--;
            mcopy = rte_pktmbuf_clone(conn->proxy.syn_mbuf,
                                      conn->proxy.syn_mbuf->pool);
            if (mcopy != NULL) {
                iph = rte_pktmbuf_mtod_offset(mcopy, struct ipv4_hdr *,
                                              ETHER_HDR_LEN);
                lb_device_output(mcopy, iph, conn->dev);
            }
        }
    }
}

static int
tcp_conn_timer_expire_cb(struct lb_conn *conn, uint32_t ctime) {
    /* sent rst to client and real srvice. */

    if (ctime - conn->use_time > conn->timeout)
        return 0;
    else
        return -1;
}

static struct lb_conn *
tcp_conn_schedule(struct lb_conn_table *ct, struct ipv4_hdr *iph,
                  struct tcp_hdr *th, struct lb_device *dev) {
    struct lb_virt_service *vs;
    struct lb_real_service *rs;
    struct lb_conn *conn;

    if (!SYN(th) || ACK(th) || RST(th) || FIN(th))
        return NULL;

    vs = lb_vs_get(iph->dst_addr, th->dst_port, iph->next_proto_id);
    if (vs == NULL)
        return NULL;

    if (lb_vs_check_max_conn(vs)) {
        lb_vs_put(vs);
        return NULL;
    }

    rs = lb_vs_get_rs(vs, iph->src_addr, th->src_port);
    if (rs == NULL) {
        lb_vs_put(vs);
        return NULL;
    }

    conn = lb_conn_new(ct, iph->src_addr, th->src_port, rs, 0, dev);
    if (conn == NULL) {
        lb_vs_put(vs);
        lb_vs_put_rs(rs);
        return NULL;
    }

    lb_vs_put(vs);

    return conn;
}

static void
tcp_opt_remove_timestamp(struct tcp_hdr *th) {
    uint8_t *ptr;
    int len;
    uint32_t *tmp;

    ptr = (uint8_t *)(th + 1);
    len = (th->data_off >> 2) - sizeof(struct tcp_hdr);
    while (len > 0) {
        int opcode = *ptr++;
        int opsize;

        switch (opcode) {
        case TCPOPT_EOL:
            return;
        case TCPOPT_NOP:
            len--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2)
                return;
            if (opsize > len)
                return;
            if ((opcode == TCPOPT_TIMESTAMP) && (opsize == TCPOLEN_TIMESTAMP)) {
                *(ptr - 2) = TCPOPT_NOP;
                *(ptr - 1) = TCPOPT_NOP;
                tmp = (uint32_t *)ptr;
                *tmp++ = 0x01010101;
                *tmp = 0x01010101;
            }
            ptr += opsize - 2;
            len -= opsize;
        }
    }
}

static void
tcp_response_rst(struct rte_mbuf *m, struct ipv4_hdr *iph, struct tcp_hdr *th,
                 struct lb_device *dev) {
    uint32_t tmpaddr;
    struct tcp_hdr *nth;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t tcp_flags;

    if (RST(th)) {
        rte_pktmbuf_free(m);
        return;
    }

    rte_pktmbuf_reset(m);
    m->pkt_len = m->data_len =
        ETHER_HDR_LEN + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr);

    iph->type_of_service = 0;
    iph->total_length =
        rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    iph->packet_id = 0;
    iph->fragment_offset = 0;
    iph->time_to_live = 63;
    tmpaddr = iph->src_addr;
    iph->src_addr = iph->dst_addr;
    iph->dst_addr = tmpaddr;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (ACK(th)) {
        seq = th->sent_seq;
        ack = 0;
        tcp_flags = TCP_RST_FLAG;
    } else {
        seq = 0;
        if (!SYN(th))
            ack = rte_be_to_cpu_32(th->sent_seq);
        else
            ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
        tcp_flags = TCP_RST_FLAG;
        tcp_flags |= TCP_ACK_FLAG;
    }
    sport = th->src_port;
    dport = th->dst_port;

    nth = (struct tcp_hdr *)(iph + 1);
    nth->src_port = dport;
    nth->dst_port = sport;
    nth->sent_seq = seq;
    nth->recv_ack = ack;
    nth->data_off = sizeof(struct tcp_hdr) << 2;
    nth->tcp_flags = tcp_flags;
    nth->rx_win = 0;
    nth->tcp_urp = 0;
    nth->cksum = 0;
    nth->cksum = rte_ipv4_udptcp_cksum(iph, th);

    lb_device_output(m, iph, dev);
}

static int
tcp_fullnat_recv_client(struct rte_mbuf *m, struct ipv4_hdr *iph,
                        struct tcp_hdr *th, struct lb_conn_table *ct,
                        struct lb_conn *conn, struct lb_device *dev) {
    if (conn != NULL) {
        if (conn->state == TCP_CONNTRACK_CLOSE) {
            tcp_response_rst(m, iph, th, dev);
            return 0;
        }
        if (conn->state == TCP_CONNTRACK_TIME_WAIT) {
            if (conn->flags & LB_CONN_F_SYNPROXY) {
                if (!SYN(th) && ACK(th) && !RST(th) && !FIN(th)) {
                    lb_conn_expire(ct, conn);
                    conn = NULL;
                }
            } else {
                if (SYN(th) && !ACK(th) && !RST(th) && !FIN(th)) {
                    lb_conn_expire(ct, conn);
                    conn = NULL;
                }
            }
        }
    }

    if (conn == NULL) {
        if (synproxy_recv_client_ack(m, iph, th, ct, dev) == 0) {
            return 0;
        }
        conn = tcp_conn_schedule(ct, iph, th, dev);
        if (conn == NULL) {
            TCP_PRINT(IPv4_TCP_FMT " [CONN SCHEDULE DROP]\n",
                      IPv4_TCP_ARG(iph, th));
            tcp_response_rst(m, iph, th, dev);
            return 0;
        }
    }

    if ((conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT) &&
        (!SYN(th) && ACK(th) && !RST(th) && !FIN(th))) {
        TCP_PRINT(IPv4_TCP_FMT " [SYNPROXY SYN_SENT DROP]\n",
                  IPv4_TCP_ARG(iph, th));
        rte_pktmbuf_free(conn->proxy.ack_mbuf);
        conn->proxy.ack_mbuf = m;
        return 0;
    }

    if (!(conn->real_service->flags & LB_RS_F_AVAILABLE)) {
        TCP_PRINT(IPv4_TCP_FMT " [RS NOT AVAILABLE DROP]\n",
                  IPv4_TCP_ARG(iph, th));
        lb_conn_expire(ct, conn);
        tcp_response_rst(m, iph, th, dev);
        return 0;
    }

    if (SYN(th)) {
        tcp_opt_remove_timestamp(th);
        tcp_secret_seq_init(conn->lip, conn->rip, conn->lport, conn->rport,
                            rte_be_to_cpu_32(th->sent_seq), &conn->tseq);
    }

    if ((conn->flags & LB_CONN_F_TOA) &&
        (conn->state == TCP_CONNTRACK_SYN_RECV) && !SYN(th) && ACK(th) &&
        !RST(th) && !FIN(th))
        tcp_opt_add_toa(m, iph, th, conn->cip, conn->cport);

    tcp_set_conntack_state(conn, th, LB_DIR_ORIGINAL);
    tcp_set_packet_stats(conn, m, LB_DIR_ORIGINAL);

    iph->src_addr = conn->lip;
    iph->dst_addr = conn->rip;
    th->src_port = conn->lport;
    th->dst_port = conn->rport;
    tcp_secret_seq_adjust_client(th, &conn->tseq);
    synproxy_seq_adjust_client(th, &conn->proxy);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    return lb_device_output(m, iph, dev);
}

static int
tcp_fullnat_recv_backend(struct rte_mbuf *m, struct ipv4_hdr *iph,
                         struct tcp_hdr *th, struct lb_conn *conn,
                         struct lb_device *dev) {
    if (synproxy_recv_backend_synack(m, iph, th, conn, dev) == 0)
        return 0;

    tcp_set_conntack_state(conn, th, LB_DIR_REPLY);
    tcp_set_packet_stats(conn, m, LB_DIR_REPLY);

    iph->src_addr = conn->vip;
    iph->dst_addr = conn->cip;
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    tcp_secret_seq_adjust_backend(th, &conn->tseq);
    synproxy_seq_adjust_backend(th, &conn->proxy);
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph, th);

    return lb_device_output(m, iph, dev);
}

static int
tcp_fullnat_handle(struct rte_mbuf *m, struct ipv4_hdr *iph,
                   struct lb_device *dev) {
    struct lb_conn_table *ct;
    struct lb_conn *conn;
    struct tcp_hdr *th;
    uint8_t dir;

    ct = &lb_conn_tbls[rte_lcore_id()];
    th = TCP_HDR(iph);

    TCP_PRINT(IPv4_TCP_FMT " [NEW PACKET]\n", IPv4_TCP_ARG(iph, th));

    if (synproxy_recv_client_syn(m, iph, th, dev) == 0)
        return 0;

    conn = lb_conn_find(ct, iph->src_addr, iph->dst_addr, th->src_port,
                        th->dst_port, &dir);
    if (dir == LB_DIR_REPLY) {
        TCP_PRINT(IPv4_TCP_FMT " [REPLY]\n", IPv4_TCP_ARG(iph, th));
        return tcp_fullnat_recv_backend(m, iph, th, conn, dev);
    } else {
        TCP_PRINT(IPv4_TCP_FMT " [ORIGINAL]\n", IPv4_TCP_ARG(iph, th));
        return tcp_fullnat_recv_client(m, iph, th, ct, conn, dev);
    }
}

static int
tcp_fullnat_init(void) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    int rc;
    int size;

    size = TCP_MAX_CONN / (rte_lcore_count() - 1);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        rc = lb_conn_table_init(
            ct, LB_IPPROTO_TCP, lcore_id, tcp_timeouts[TCP_CONNTRACK_NONE],
            size, tcp_conn_timer_task_cb, tcp_conn_timer_expire_cb);
        if (rc < 0) {
            RTE_LOG(ERR, USER1, "%s(): lb_conn_table_init failed.\n", __func__);
            return rc;
        }
        RTE_LOG(INFO, USER1, "%s(): Create tcp connection table on lcore%u.\n",
                __func__, lcore_id);
    }

    return 0;
}

static struct lb_proto proto_tcp = {
    .id = IPPROTO_TCP,
    .type = LB_IPPROTO_TCP,
    .init = tcp_fullnat_init,
    .fullnat_handle = tcp_fullnat_handle,
};

LB_PROTO_REGISTER(proto_tcp);

static void
tcp_conn_dump_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                     __attribute__((unused)) int argc) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    struct lb_conn *conn;
    void *tmp;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        rte_spinlock_lock(&ct->spinlock);
        for_each_conn_safe(conn, &ct->timeout_list, next, tmp) {
            unixctl_command_reply(
                fd,
                "cip: " IPv4_BE_FMT ", cport: %u, "
                "vip: " IPv4_BE_FMT ", vport: %u, "
                "lip: " IPv4_BE_FMT ", lport: %u, "
                "rip: " IPv4_BE_FMT ", rport: %u, "
                "flags: 0x%x, state: %s, usetime:%u, timeout=%u\n",
                IPv4_BE_ARG(conn->cip), rte_be_to_cpu_16(conn->cport),
                IPv4_BE_ARG(conn->vip), rte_be_to_cpu_16(conn->vport),
                IPv4_BE_ARG(conn->lip), rte_be_to_cpu_16(conn->lport),
                IPv4_BE_ARG(conn->rip), rte_be_to_cpu_16(conn->rport),
                conn->flags, tcp_conntrack_names[conn->state], conn->use_time,
                conn->timeout);
        }
        rte_spinlock_unlock(&ct->spinlock);
    }
}

UNIXCTL_CMD_REGISTER("tcp/conn/dump", "", "Dump TCP connections.", 0, 0,
                     tcp_conn_dump_cmd_cb);

static void
tcp_conn_stats_normal(int fd) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;

    unixctl_command_reply(fd, "             ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        unixctl_command_reply(fd, "lcore%-5u  ", lcore_id);
    }
    unixctl_command_reply(fd, "\n");

    unixctl_command_reply(fd, "avail_conns  ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        unixctl_command_reply(fd, "%-10u  ", rte_mempool_avail_count(ct->mp));
    }
    unixctl_command_reply(fd, "\n");

    unixctl_command_reply(fd, "inuse_conns  ");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        unixctl_command_reply(fd, "%-10u  ", rte_mempool_in_use_count(ct->mp));
    }
    unixctl_command_reply(fd, "\n");
}

static void
tcp_conn_stats_json(int fd) {
    uint32_t lcore_id;
    struct lb_conn_table *ct;
    uint8_t json_first_obj = 1;

    unixctl_command_reply(fd, "[");
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        ct = &lb_conn_tbls[lcore_id];
        if (json_first_obj) {
            json_first_obj = 0;
            unixctl_command_reply(fd, "{");
        } else {
            unixctl_command_reply(fd, ",{");
        }
        unixctl_command_reply(fd, JSON_KV_32_FMT("lcore", ","), lcore_id);
        unixctl_command_reply(fd, JSON_KV_32_FMT("avail_conns", ","),
                              rte_mempool_avail_count(ct->mp));
        unixctl_command_reply(fd, JSON_KV_32_FMT("inuse_conns", ""),
                              rte_mempool_in_use_count(ct->mp));
        unixctl_command_reply(fd, "}");
    }
    unixctl_command_reply(fd, "]\n");
}

static void
tcp_conn_stats_cmd_cb(int fd, char *argv[], int argc) {
    if (argc > 0 && strcmp(argv[0], "--json") == 0)
        tcp_conn_stats_json(fd);
    else
        tcp_conn_stats_normal(fd);
}

UNIXCTL_CMD_REGISTER("tcp/conn/stats", "[--json].",
                     "Show the number of TCP connections.", 0, 1,
                     tcp_conn_stats_cmd_cb);