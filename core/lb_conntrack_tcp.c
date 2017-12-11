/* Copyright (c) 2017. TIG developer. */

#include <rte_tcp.h>

#include "lb_connection.h"
#include "lb_conntrack_tcp.h"

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

/* What TCP flags are set from RST/SYN/FIN/ACK. */
enum tcp_bit_set {
    TCP_SYN_SET,
    TCP_SYNACK_SET,
    TCP_FIN_SET,
    TCP_ACK_SET,
    TCP_RST_SET,
    TCP_NONE_SET,
};
/*
static const char *tcp_bitset_string[] = {
        [TCP_SYN_SET] = "SYN", [TCP_SYNACK_SET] = "SYNACK",
        [TCP_FIN_SET] = "FIN", [TCP_ACK_SET] = "ACK",
        [TCP_RST_SET] = "RST", [TCP_NONE_SET] = "NONE",
};

static const char *tcp_conntrack_string[] = {
        [TCP_CONNTRACK_NONE] = "NONE",
        [TCP_CONNTRACK_SYN_SENT] = "SYN_SENT",
        [TCP_CONNTRACK_SYN_RECV] = "SYN_RECV",
        [TCP_CONNTRACK_ESTABLISHED] = "ESTABLISHED",
        [TCP_CONNTRACK_FIN_WAIT] = "FIN_WAIT",
        [TCP_CONNTRACK_CLOSE_WAIT] = "CLOSE_WAIT",
        [TCP_CONNTRACK_LAST_ACK] = "LAST_ACK",
        [TCP_CONNTRACK_TIME_WAIT] = "TIME_WAIT",
        [TCP_CONNTRACK_CLOSE] = "CLOSE",
        [TCP_CONNTRACK_MAX] = "MAX",
        [TCP_CONNTRACK_IGNORE] = "IGNORE",
};
*/
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
     /*rst*/ {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
     /*none*/ {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV}},
    {/* REPLY */
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
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
     /* 	         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2
        */
     /*rst*/ {sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL},
     /*none*/ {sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV}}};

#define TCP_URG_FLAG 0x20
#define TCP_ACK_FLAG 0x10
#define TCP_PSH_FLAG 0x08
#define TCP_RST_FLAG 0x04
#define TCP_SYN_FLAG 0x02
#define TCP_FIN_FLAG 0x01
#define TCP_FLAG_ALL 0x3F

static inline uint32_t
get_conntrack_index(const struct tcp_hdr *th) {
    if (th->tcp_flags & TCP_RST_FLAG)
        return TCP_RST_SET;
    else if (th->tcp_flags & TCP_SYN_FLAG)
        return ((th->tcp_flags & TCP_ACK_FLAG) ? TCP_SYNACK_SET : TCP_SYN_SET);
    else if (th->tcp_flags & TCP_FIN_FLAG)
        return TCP_FIN_SET;
    else if (th->tcp_flags & TCP_ACK_FLAG)
        return TCP_ACK_SET;
    else
        return TCP_NONE_SET;
}

/*
    Args:
        if dir == 0, packet from client; if dir == 1, packet from service
    Returns:
        new conn create, return 1;
        old conn del, return -1;
        others, return 0;
*/
int
tcp_set_conntrack_state(struct lb_connection *conn, struct tcp_hdr *th,
                        int dir) {
    enum tcp_conntrack old_state;
    enum tcp_conntrack new_state;
    uint32_t index;
    int ret = 0;

    index = get_conntrack_index(th);
    old_state = conn->conntrack_state;
    new_state = tcp_conntracks[dir][index][old_state];

    if (!(conn->conntrack_flags & CONNTRACK_F_ACTIVE) &&
        new_state == TCP_CONNTRACK_ESTABLISHED) {
        conn->conntrack_flags |= CONNTRACK_F_ACTIVE;
        ret = 1;
    } else if (conn->conntrack_flags & CONNTRACK_F_ACTIVE &&
               new_state != TCP_CONNTRACK_ESTABLISHED) {
        conn->conntrack_flags &= ~CONNTRACK_F_ACTIVE;
        ret = -1;
    }

    if (new_state < TCP_CONNTRACK_MAX)
        conn->conntrack_state = new_state;
    return ret;
}

