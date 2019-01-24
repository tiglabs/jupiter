/* Copyright (c) 2018. TIG developer. */

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

#include <cryptohash.h>
#include <unixctl_command.h>

#include "lb.h"
#include "lb_connection.h"
#include "lb_device.h"
#include "lb_ip_address.h"
#include "lb_mib.h"
#include "lb_service.h"
#include "lb_tcp.h"
#include "lb_tcp_synproxy.h"
#include "lb_timer_wheel.h"

static uint32_t tcp_seq_secure[MD5_MESSAGE_BYTES / 4];

static inline void
tcp_seq_secure_init_once(void) {
    static uint8_t inited = 0;
    int i;

    if (likely(inited))
        return;

    for (i = 0; i < MD5_MESSAGE_BYTES / 4; i++) {
        tcp_seq_secure[i] = rte_rand();
    }

    inited = !inited;
}

static inline uint32_t
seq_scale(uint32_t seq) {
    /*
     *	As close as possible to RFC 793, which
     *	suggests using a 250 kHz clock.
     *	Further reading shows this assumes 2 Mb/s networks.
     *	For 10 Mb/s Ethernet, a 1 MHz clock is appropriate.
     *	For 10 Gb/s Ethernet, a 1 GHz clock should be ok, but
     *	we also need to limit the resolution so that the uint32_t seq
     *	overlaps less than one time per MSL (2 minutes).
     *	Choosing a clock of 64 ns period is OK. (period of 274 s)
     */
    return seq + (uint32_t)(lb_time_now_ns() >> 6);
}

static uint32_t
tcp_v4_init_secure_seq(uint32_t saddr, uint32_t daddr, uint16_t sport,
                       uint16_t dport) {
    uint32_t hash[MD5_DIGEST_WORDS];

    tcp_seq_secure_init_once();

    hash[0] = saddr;
    hash[1] = daddr;
    hash[2] = ((uint32_t)sport << 16) + (uint32_t)dport;
    hash[3] = tcp_seq_secure[15];

    md5_transform(hash, tcp_seq_secure);

    return seq_scale(hash[0]);
}

static uint32_t
tcp_v6_init_secure_seq(const uint32_t *saddr, const uint32_t *daddr,
                       uint16_t sport, uint16_t dport) {
    uint32_t secret[MD5_MESSAGE_BYTES / 4];
    uint32_t hash[MD5_DIGEST_WORDS];
    uint32_t i;

    tcp_seq_secure_init_once();

    rte_memcpy(hash, saddr, 16);
    for (i = 0; i < 4; i++)
        secret[i] = tcp_seq_secure[i] + daddr[i];
    secret[4] = tcp_seq_secure[4] + (((uint32_t)sport << 16) + (uint32_t)dport);
    for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
        secret[i] = tcp_seq_secure[i];

    md5_transform(hash, secret);

    return seq_scale(hash[0]);
}

static const char *const tcp_conntrack_names[] = {
    "NONE",       "SYN_SENT", "SYN_RECV",  "ESTABLISHED", "FIN_WAIT",
    "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",       "SYN_SENT2",
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

static void tcp_conn_destory(struct lb_connection *conn);
static void tcp_timer_timeout_cb(struct lb_tw_timer *timer, void *arg);
static void tcp_timer_retrasyn_cb(struct lb_tw_timer *timer, void *arg);

static struct lb_conn_table *tcp_conn_table;

#define SECS MS_PER_S
#define MINS (60 * SECS)
#define HOURS (60 * MINS)
#define DAYS (24 * HOURS)

static uint32_t tcp_timeouts[TCP_CONNTRACK_MAX] = {
    [TCP_CONNTRACK_NONE] = 10 * SECS,
    [TCP_CONNTRACK_SYN_SENT] = 2 * MINS,
    [TCP_CONNTRACK_SYN_RECV] = 1 * MINS,
    [TCP_CONNTRACK_ESTABLISHED] = 5 * MINS,
    [TCP_CONNTRACK_FIN_WAIT] = 2 * MINS,
    [TCP_CONNTRACK_CLOSE_WAIT] = 1 * MINS,
    [TCP_CONNTRACK_LAST_ACK] = 30 * SECS,
    [TCP_CONNTRACK_TIME_WAIT] = 0 * SECS,
    [TCP_CONNTRACK_CLOSE] = 0 * SECS,
    [TCP_CONNTRACK_LISTEN] = 0 * SECS,
};

static lb_tw_timer_cb_t tcp_timer_cbs[TCP_TIMER_MAX] = {
    [TCP_TIMER_TIMEOUT] = tcp_timer_timeout_cb,
    [TCP_TIMER_RETRASYN] = tcp_timer_retrasyn_cb,
};

static void
tcp_timer_timeout_cb(struct lb_tw_timer *timer, void *arg) {
    struct lb_connection *conn = arg;

    (void)timer;
    if (conn->state < TCP_CONNTRACK_TIME_WAIT) {
        switch (conn->state) {
        case TCP_CONNTRACK_SYN_SENT:
            LB_MIB_INC_STATS(TCP_TO_SYN_SENT);
            break;
        case TCP_CONNTRACK_SYN_RECV:
            LB_MIB_INC_STATS(TCP_TO_SYN_RECV);
            break;
        case TCP_CONNTRACK_ESTABLISHED:
            LB_MIB_INC_STATS(TCP_TO_ESTABLISHED);
            break;
        case TCP_CONNTRACK_FIN_WAIT:
            LB_MIB_INC_STATS(TCP_TO_FIN_WAIT);
            break;
        case TCP_CONNTRACK_CLOSE_WAIT:
            LB_MIB_INC_STATS(TCP_TO_CLOSE_WAIT);
            break;
        case TCP_CONNTRACK_LAST_ACK:
            LB_MIB_INC_STATS(TCP_TO_LAST_ACK);
            break;
        }
    }
    tcp_conn_destory(conn);
}

static void
tcp_timer_retrasyn_cb(struct lb_tw_timer *timer, void *arg) {
    struct lb_connection *conn = arg;
    struct rte_mbuf *m;
    struct ether_hdr *eth;
    struct ipv4_hdr *iph4;
    struct ipv6_hdr *iph6;

    (void)timer;
    if ((conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT) &&
        (conn->synproxy_synpkt != NULL)) {
        m = rte_pktmbuf_clone(conn->synproxy_synpkt,
                              conn->synproxy_synpkt->pool);
        if (!m) {
            LB_MIB_INC_STATS(MBUF_ALLOC_FAILED);
            return;
        }
        eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
        if (rte_be_to_cpu_16(eth->ether_type) == ETHER_TYPE_IPv4) {
            iph4 = (struct ipv4_hdr *)(eth + 1);
            lb_inbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
        } else {
            iph6 = (struct ipv6_hdr *)(eth + 1);
            lb_inbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
        }
        conn->synproxy_rto =
            RTE_MIN(conn->synproxy_rto << 1, TCP_RETRASYN_TIMEOUT_MAX);
        tcp_conn_timer_reset(conn, TCP_TIMER_RETRASYN, conn->synproxy_rto);
        LB_MIB_INC_STATS(SYNPROXY_RETRAN_SYN);
    }
}

void
tcp_conn_timer_reset(struct lb_connection *conn, uint32_t timer_id,
                     uint32_t timeout) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_tw_timer_wheel *tw = &tcp_conn_table->timer_wheels[lcore_id];

    lb_tw_timer_restart(tw, &conn->timers[timer_id], timeout,
                        tcp_timer_cbs[timer_id], conn);
}

void
tcp_conn_timer_stop(struct lb_connection *conn, uint32_t timer_id) {
    uint32_t lcore_id = rte_lcore_id();
    struct lb_tw_timer_wheel *tw = &tcp_conn_table->timer_wheels[lcore_id];

    lb_tw_timer_stop(tw, &conn->timers[timer_id]);
}

void
tcp_set_conntrack_state(struct lb_connection *conn, const struct tcp_hdr *th,
                        lb_direction_t dir) {
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
    if (new_state < TCP_CONNTRACK_MAX)
        conn->state = new_state;
    if ((conn->state == TCP_CONNTRACK_ESTABLISHED) && (vs->est_timeout != 0))
        timeout = vs->est_timeout;
    else
        timeout = tcp_timeouts[conn->state];
    tcp_conn_timer_reset(conn, TCP_TIMER_TIMEOUT, timeout);
}

static void
tcp_set_packet_stats(struct lb_connection *conn, uint32_t pkt_len,
                     uint8_t dir) {
    struct lb_real_service *rs = conn->real_service;
    struct lb_virt_service *vs = rs->virt_service;
    uint32_t cid = rte_lcore_id();

    vs->stats[cid].bytes[dir] += pkt_len;
    vs->stats[cid].packets[dir] += 1;
    rs->stats[cid].bytes[dir] += pkt_len;
    rs->stats[cid].packets[dir] += 1;
}

static struct lb_connection *
tcp_conn_lookup(void *iphdr, struct tcp_hdr *th, lb_direction_t *dir,
                uint8_t is_ip4) {
    struct lb_conn_table *table = tcp_conn_table;
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    if (is_ip4) {
        return lb_connection_lookup(table, &iph4->src_addr, &iph4->dst_addr,
                                    th->src_port, th->dst_port, dir, is_ip4);
    } else {
        return lb_connection_lookup(table, iph6->src_addr, iph6->dst_addr,
                                    th->src_port, th->dst_port, dir, is_ip4);
    }
}

struct lb_connection *
tcp_conn_create(void *iphdr, struct tcp_hdr *th, uint8_t is_synproxy,
                uint8_t is_ip4) {
    struct lb_conn_table *table = tcp_conn_table;
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;
    struct lb_connection *conn;

    if (is_ip4) {
        conn = lb_connection_create(table, &iph4->src_addr, &iph4->dst_addr,
                                    th->src_port, th->dst_port, is_synproxy,
                                    is_ip4);
        if (!conn)
            return NULL;
        conn->new_isn = tcp_v4_init_secure_seq(conn->laddr.ip4.as_u32,
                                               conn->raddr.ip4.as_u32,
                                               conn->lport, conn->rport);
    } else {
        conn = lb_connection_create(table, iph6->src_addr, iph6->dst_addr,
                                    th->src_port, th->dst_port, is_synproxy,
                                    is_ip4);
        if (!conn)
            return NULL;
        conn->new_isn = tcp_v6_init_secure_seq(conn->laddr.ip6.as_u32,
                                               conn->raddr.ip6.as_u32,
                                               conn->lport, conn->rport);
    }
    lb_tw_timer_init(&conn->timers[TCP_TIMER_TIMEOUT]);
    lb_tw_timer_init(&conn->timers[TCP_TIMER_RETRASYN]);
    if (is_synproxy) {
        conn->new_isn_oft =
            conn->new_isn - (rte_be_to_cpu_32(th->sent_seq) - 1);
        conn->synproxy_isn = rte_be_to_cpu_32(th->recv_ack) - 1;
        conn->state = TCP_CONNTRACK_SYN_SENT;
        tcp_conn_timer_reset(conn, TCP_TIMER_TIMEOUT,
                             tcp_timeouts[conn->state]);
    } else {
        conn->new_isn_oft = conn->new_isn - rte_be_to_cpu_32(th->sent_seq);
        conn->state = TCP_CONNTRACK_NONE;
    }

    return conn;
}

static void
tcp_conn_destory(struct lb_connection *conn) {
    tcp_conn_timer_stop(conn, TCP_TIMER_TIMEOUT);
    tcp_conn_timer_stop(conn, TCP_TIMER_RETRASYN);
    lb_connection_destory(conn);
}

static void
tcp_opt_add_toa(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iph;
    struct ipv6_hdr *iph6 = iph;
    uint8_t *p, *q;

    if (is_ip4) {
        struct tcp_opt_toa *toa;

        /* tcp header max length */
        if ((60 - (th->data_off >> 2)) < (int)sizeof(struct tcp_opt_toa))
            return;
        p = (uint8_t *)rte_pktmbuf_append(m, sizeof(struct tcp_opt_toa));
        q = p + sizeof(struct tcp_opt_toa);
        while (p >= ((uint8_t *)th + (th->data_off >> 2))) {
            *q = *p;
            q--;
            p--;
        }
        toa = (struct tcp_opt_toa *)((uint8_t *)th + (th->data_off >> 2));
        toa->optcode = TCPOPT_TOA;
        toa->optsize = TCPOLEN_TOA;
        toa->port = th->src_port;
        toa->addr = iph4->src_addr;
        th->data_off += (sizeof(struct tcp_opt_toa) / 4) << 4;
        iph4->total_length = rte_cpu_to_be_16(
            rte_be_to_cpu_16(iph4->total_length) + sizeof(struct tcp_opt_toa));
    } else {
        struct tcp_opt_toa6 *toa6;

        /* tcp header max length */
        if ((60 - (th->data_off >> 2)) < (int)sizeof(struct tcp_opt_toa6))
            return;
        p = (uint8_t *)rte_pktmbuf_append(m, sizeof(struct tcp_opt_toa6));
        q = p + sizeof(struct tcp_opt_toa6);
        while (p >= ((uint8_t *)th + (th->data_off >> 2))) {
            *q = *p;
            q--;
            p--;
        }
        toa6 = (struct tcp_opt_toa6 *)((uint8_t *)th + (th->data_off >> 2));
        toa6->optcode = TCPOPT_TOA6;
        toa6->optsize = TCPOLEN_TOA6;
        toa6->port = th->src_port;
        rte_memcpy(toa6->addr, iph6->src_addr, 16);
        th->data_off += (sizeof(struct tcp_opt_toa6) / 4) << 4;
        iph6->payload_len = rte_cpu_to_be_16(
            rte_be_to_cpu_16(iph6->payload_len) + sizeof(struct tcp_opt_toa6));
    }
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
tcp_response_rst(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                     struct lb_device *dev, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iph, *niph4;
    struct ipv6_hdr *iph6 = iph, *niph6;
    struct tcp_hdr *nth;
    ip46_address_t saddr;
    ip46_address_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq, ack;
    uint8_t tcp_flags;

    if (RST(th)) {
        rte_pktmbuf_free(m);
        return;
    }

    if (ACK(th)) {
        seq = th->recv_ack;
        ack = 0;
        tcp_flags = TCP_RST_FLAG;
    } else {
        seq = 0;
        if (!SYN(th))
            ack = rte_be_to_cpu_32(th->sent_seq);
        else
            ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + 1);
        tcp_flags = TCP_RST_FLAG | TCP_ACK_FLAG;
    }
    sport = th->src_port;
    dport = th->dst_port;
    if (is_ip4) {
        ip46_address_set_ip4(&saddr, (ip4_address_t *)&iph4->src_addr);
        ip46_address_set_ip4(&daddr, (ip4_address_t *)&iph4->dst_addr);
    } else {
        ip46_address_set_ip6(&saddr, (ip6_address_t *)iph6->src_addr);
        ip46_address_set_ip6(&daddr, (ip6_address_t *)iph6->dst_addr);
    }

    rte_pktmbuf_reset(m);
    nth = (struct tcp_hdr *)rte_pktmbuf_append(m, sizeof(struct tcp_hdr));
    nth->src_port = dport;
    nth->dst_port = sport;
    nth->sent_seq = seq;
    nth->recv_ack = ack;
    nth->data_off = sizeof(struct tcp_hdr) << 2;
    nth->tcp_flags = tcp_flags;
    nth->rx_win = 0;
    nth->tcp_urp = 0;
    if (is_ip4) {
        niph4 =
            (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv4_hdr));
        niph4->version_ihl = 0x45;
        niph4->type_of_service = 0;
        niph4->total_length =
            rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
        niph4->packet_id = 0;
        niph4->fragment_offset = 0;
        niph4->time_to_live = 64;
        niph4->next_proto_id = IPPROTO_TCP;
        niph4->src_addr = daddr.ip4.as_u32;
        niph4->dst_addr = saddr.ip4.as_u32;
        niph4->hdr_checksum = 0;
        niph4->hdr_checksum = rte_ipv4_cksum(niph4);
        nth->cksum = 0;
        nth->cksum = rte_ipv4_udptcp_cksum(niph4, nth);
        rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
        lb_device_ip4_output(m, (ip4_address_t *)&niph4->dst_addr, dev);
    } else {
        niph6 =
            (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv6_hdr));
        niph6->vtc_flow = rte_cpu_to_be_32(0x6 << 28);
        niph6->payload_len = rte_cpu_to_be_16(sizeof(struct tcp_hdr));
        niph6->proto = IPPROTO_TCP;
        niph6->hop_limits = 255;
        ip6_address_copy((ip6_address_t *)niph6->src_addr, &daddr.ip6);
        ip6_address_copy((ip6_address_t *)niph6->dst_addr, &saddr.ip6);
        nth->cksum = 0;
        nth->cksum = rte_ipv6_udptcp_cksum(niph6, nth);
        rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
        lb_device_ip6_output(m, (ip6_address_t *)&niph6->dst_addr, dev);
    }
}

static void
tcp_fnat64_out2in_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    struct ipv4_hdr *iph4;
    uint32_t vtc_flow;
    uint8_t hop_limits;
    uint16_t payload_len;

    vtc_flow = rte_be_to_cpu_32(iph6->vtc_flow);
    hop_limits = iph6->hop_limits;
    payload_len = rte_be_to_cpu_16(iph6->payload_len);

    rte_pktmbuf_adj(m, sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr));
    iph4 = (struct ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv4_hdr));
    iph4->version_ihl = 0x45;
    iph4->type_of_service = (vtc_flow & 0x0ff00000) >> 20;
    iph4->total_length = rte_cpu_to_be_16(sizeof(*iph4) + payload_len);
    iph4->packet_id = 0;
    iph4->fragment_offset = 0;
    iph4->time_to_live = hop_limits - 1;
    iph4->next_proto_id = IPPROTO_TCP;
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->laddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->raddr.ip4);
    th->src_port = conn->lport;
    th->dst_port = conn->rport;
    th->sent_seq =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + conn->new_isn_oft);
    th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) -
                                    conn->synproxy_isn_oft);
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph4, th);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
tcp_fnat46_in2out_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    struct ipv6_hdr *iph6;
    uint8_t tos;
    uint16_t iphdr_size;
    uint8_t ttl;
    uint16_t payload_len;

    tos = iph4->type_of_service;
    ttl = iph4->time_to_live;
    iphdr_size = (iph4->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
    payload_len = rte_be_to_cpu_16(iph4->total_length) - iphdr_size;

    rte_pktmbuf_adj(m, sizeof(struct ether_hdr) + iphdr_size);
    iph6 = (struct ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct ipv6_hdr));
    iph6->vtc_flow = rte_cpu_to_be_32((0x6 << 28) | ((uint32_t)tos << 20));
    iph6->payload_len = rte_cpu_to_be_16(payload_len);
    iph6->proto = IPPROTO_TCP;
    iph6->hop_limits = ttl - 1;
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->caddr.ip6);
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    th->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) +
                                    conn->synproxy_isn_oft);
    th->recv_ack =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) - conn->new_isn_oft);
    th->cksum = 0;
    th->cksum = rte_ipv6_udptcp_cksum(iph6, th);
    rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
    lb_outbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
tcp_fnat44_out2in_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->laddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->raddr.ip4);
    iph4->time_to_live--;
    th->src_port = conn->lport;
    th->dst_port = conn->rport;
    th->sent_seq =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + conn->new_isn_oft);
    th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) -
                                    conn->synproxy_isn_oft);
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph4, th);
    lb_inbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
tcp_fnat44_in2out_handle(struct rte_mbuf *m, struct ipv4_hdr *iph4,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    ip4_address_copy((ip4_address_t *)&iph4->src_addr, &conn->vaddr.ip4);
    ip4_address_copy((ip4_address_t *)&iph4->dst_addr, &conn->caddr.ip4);
    iph4->time_to_live--;
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    th->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) +
                                    conn->synproxy_isn_oft);
    th->recv_ack =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) - conn->new_isn_oft);
    iph4->hdr_checksum = 0;
    iph4->hdr_checksum = rte_ipv4_cksum(iph4);
    th->cksum = 0;
    th->cksum = rte_ipv4_udptcp_cksum(iph4, th);
    lb_outbound_device_ip4_output(m, (ip4_address_t *)&iph4->dst_addr);
}

static void
tcp_fnat66_out2in_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->laddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->raddr.ip6);
    iph6->hop_limits--;
    th->src_port = conn->lport;
    th->dst_port = conn->rport;
    th->sent_seq =
        rte_cpu_to_be_32((rte_be_to_cpu_32(th->sent_seq) + conn->new_isn_oft));
    th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) -
                                    conn->synproxy_isn_oft);
    th->cksum = 0;
    th->cksum = rte_ipv6_udptcp_cksum(iph6, th);
    lb_inbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
tcp_fnat66_in2out_handle(struct rte_mbuf *m, struct ipv6_hdr *iph6,
                         struct tcp_hdr *th, struct lb_connection *conn) {
    ip6_address_copy((ip6_address_t *)iph6->src_addr, &conn->vaddr.ip6);
    ip6_address_copy((ip6_address_t *)iph6->dst_addr, &conn->caddr.ip6);
    iph6->hop_limits--;
    th->src_port = conn->vport;
    th->dst_port = conn->cport;
    th->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) +
                                    conn->synproxy_isn_oft);
    th->recv_ack =
        rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) - conn->new_isn_oft);
    th->cksum = 0;
    th->cksum = rte_ipv6_udptcp_cksum(iph6, th);
    lb_outbound_device_ip6_output(m, (ip6_address_t *)iph6->dst_addr);
}

static void
tcp_in2out_input(struct rte_mbuf *m, void *iphdr, struct tcp_hdr *th,
                 struct lb_connection *conn, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    if (synproxy_recv_backend_synack(m, iphdr, th, conn, is_ip4) == 0)
        return;

    tcp_set_conntrack_state(conn, th, LB_DIR_IN2OUT);
    tcp_set_packet_stats(conn, m->pkt_len, LB_DIR_IN2OUT);

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->caddr)) {
            tcp_fnat44_in2out_handle(m, iph4, th, conn);
        } else {
            tcp_fnat46_in2out_handle(m, iph4, th, conn);
        }
    } else {
        if (ip46_address_is_ip4(&conn->caddr)) {
            // tcp_fnat64_in2out_handle(m, conn);
            rte_pktmbuf_free(m);
        } else {
            tcp_fnat66_in2out_handle(m, iph6, th, conn);
        }
    }
}

static void
tcp_out2in_input(struct rte_mbuf *m, void *iphdr, struct tcp_hdr *th,
                 struct lb_connection *conn, struct lb_device *dev, uint8_t is_ip4) {
    struct ipv4_hdr *iph4 = iphdr;
    struct ipv6_hdr *iph6 = iphdr;

    if (conn != NULL) {
        if ((conn->state == TCP_CONNTRACK_CLOSE_WAIT) ||
            (conn->state == TCP_CONNTRACK_TIME_WAIT) ||
            (conn->state == TCP_CONNTRACK_CLOSE)) {
            if (conn->flags & LB_CONN_F_SYNPROXY) {
                if (!SYN(th) && ACK(th) && !RST(th) && !FIN(th)) {
                    tcp_conn_destory(conn);
                    conn = NULL;
                }
            } else {
                if (SYN(th) && !ACK(th) && !RST(th) && !FIN(th)) {
                    tcp_conn_destory(conn);
                    conn = NULL;
                }
            }
        }
    }

    if (conn == NULL) {
        if (synproxy_recv_client_ack(m, iphdr, th, is_ip4) == 0)
            return;

        if (!SYN(th) || ACK(th) || RST(th) || FIN(th)) {
            tcp_response_rst(m, iphdr, th, dev, is_ip4);
            return;
        }
        if (!(conn = tcp_conn_create(iphdr, th, 0, is_ip4))) {
            tcp_response_rst(m, iphdr, th, dev, is_ip4);
            return;
        }
    }

    if ((conn->flags & LB_CONN_F_SYNPROXY) &&
        (conn->state == TCP_CONNTRACK_SYN_SENT) &&
        (!SYN(th) && ACK(th) && !RST(th) && !FIN(th))) {
        rte_pktmbuf_free(m);
        return;
    }

    if (!(conn->real_service->flags & LB_RS_F_AVAILABLE)) {
        tcp_conn_destory(conn);
        tcp_response_rst(m, iphdr, th, dev, is_ip4);
        return;
    }

    if (SYN(th)) {
        tcp_opt_remove_timestamp(th);
    }

    if ((conn->flags & LB_CONN_F_TOA) &&
        (conn->state == TCP_CONNTRACK_SYN_RECV) &&
        (!SYN(th) && ACK(th) && !RST(th) && !FIN(th)))
        tcp_opt_add_toa(m, iphdr, th, is_ip4);

    tcp_set_conntrack_state(conn, th, LB_DIR_OUT2IN);
    tcp_set_packet_stats(conn, m->pkt_len, LB_DIR_OUT2IN);

    if (is_ip4) {
        if (ip46_address_is_ip4(&conn->raddr)) {
            tcp_fnat44_out2in_handle(m, iph4, th, conn);
        } else {
            // tcp_fnat46_out2in_handle(m, conn);
            rte_pktmbuf_free(m);
        }
    } else {
        if (ip46_address_is_ip4(&conn->raddr)) {
            tcp_fnat64_out2in_handle(m, iph6, th, conn);
        } else {
            tcp_fnat66_out2in_handle(m, iph6, th, conn);
        }
    }
}

static inline struct tcp_hdr *
tcp_header(struct ipv4_hdr *iph4) {
    return (struct tcp_hdr *)((char *)iph4 +
                              ((iph4->version_ihl & IPV4_HDR_IHL_MASK) << 2));
}

static inline struct tcp_hdr *
tcp6_header(struct ipv6_hdr *iph6) {
    return (struct tcp_hdr *)(iph6 + 1);
}

void
lb_tcp_input(struct rte_mbuf *m, void *iphdr, struct lb_device *dev, uint8_t is_ip4) {
    struct tcp_hdr *th;
    lb_direction_t dir;
    struct lb_connection *conn;

    th = is_ip4 ? tcp_header(iphdr) : tcp6_header(iphdr);
    if (synproxy_recv_client_syn(m, iphdr, th, is_ip4) == 0)
        return;
    conn = tcp_conn_lookup(iphdr, th, &dir, is_ip4);
    if (dir == LB_DIR_OUT2IN)
        tcp_out2in_input(m, iphdr, th, conn, dev, is_ip4);
    else
        tcp_in2out_input(m, iphdr, th, conn, is_ip4);
}

int
lb_tcp_module_init(void) {
    tcp_conn_table = lb_conn_table_create(LB_PROTO_TCP, 500 /*ms*/);
    if (!tcp_conn_table) {
        log_err("%s(): create tcp connection table failed.\n", __func__);
        return -1;
    }
    return 0;
}

static void
tcp_conn_dump_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                     __attribute__((unused)) int argc) {
    uint32_t lcore_id;
    uint32_t i;
    struct lb_tw_timer_wheel *tw;
    struct lb_tw_timer *timer;
    struct lb_connection *conn;
    char cbuf[IPV6_ADDR_LEN];
    char vbuf[IPV6_ADDR_LEN];
    char lbuf[IPV6_ADDR_LEN];
    char rbuf[IPV6_ADDR_LEN];

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        tw = &tcp_conn_table->timer_wheels[lcore_id];
        rte_spinlock_lock(&tcp_conn_table->tw_spinlock[lcore_id]);
        for (i = 0; i < LB_TW_SLOT_NUM; i++) {
            TAILQ_FOREACH(timer, &tw->slots[i], next) {
                if (timer->callback != tcp_timer_cbs[TCP_TIMER_TIMEOUT])
                    continue;
                conn = timer->arg;
                unixctl_command_reply(fd,
                                      "cip: %s, cport: %u, "
                                      "vip: %s, vport: %u, "
                                      "lip: %s, lport: %u, "
                                      "rip: %s, rport: %u, "
                                      "state: %s, timeout: %ums\n",
                                      ip46_address_format(&conn->caddr, cbuf),
                                      rte_be_to_cpu_16(conn->cport),
                                      ip46_address_format(&conn->vaddr, vbuf),
                                      rte_be_to_cpu_16(conn->vport),
                                      ip46_address_format(&conn->laddr, lbuf),
                                      rte_be_to_cpu_16(conn->lport),
                                      ip46_address_format(&conn->raddr, rbuf),
                                      rte_be_to_cpu_16(conn->rport),
                                      tcp_conntrack_names[conn->state],
                                      lb_tw_timer_calc_timeout(tw, timer));
            }
        }
        rte_spinlock_unlock(&tcp_conn_table->tw_spinlock[lcore_id]);
    }
}

UNIXCTL_CMD_REGISTER("tcp/conn/dump", "", "Dump TCP connections.", 0, 0,
                     tcp_conn_dump_cmd_cb);