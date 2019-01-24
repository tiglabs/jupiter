/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_MIB_H__
#define __LB_MIB_H__

#define foreach_mibs                                                           \
    _(ICMP_IN_ERRORS, "icmp-in-errors")                                        \
    _(ICMP_IN_ECHO_REQUEST, "icmp-in-echo-request")                            \
    _(ICMP_IN_DEST_UNREACHABLE, "icmp-in-dest-unreachable")                    \
    _(ICMP_OUT_ERRORS, "icmp-out-errors")                                      \
    _(ICMP_OUT_ECHO_REPLY, "icmp-out-echo-reply")                              \
    _(ICMP6_IN_ERRORS, "icmp6-in-errors")                                      \
    _(ICMP6_IN_ECHO_REQUEST, "icmp6-in-echo-request")                          \
    _(ICMP6_IN_DEST_UNREACHABLE, "icmp6-in-dest-unreachable")                  \
    _(ICMP6_OUT_ERRORS, "icmp6-out-errors")                                    \
    _(ICMP6_OUT_ECHO_REPLY, "icmp6-out-echo-reply")                            \
    _(KNI_TX_DROP, "kni-tx-drop")                                              \
    _(ND_LOOKUP_DROP, "neightbour-lookup-drop")                                \
    _(ARP_LOOKUP_DROP, "arp-lookup-drop")                                      \
    _(MBUF_ALLOC_FAILED, "mbuf-alloc-failed")                                  \
    _(SYNPROXY_RECV_SYN, "synproxy-recv-syn")                                  \
    _(SYNPROXY_ACCESS_ACK, "synproxy-access-ack")                              \
    _(SYNPROXY_RETRAN_SYN, "synproxy-retran-syn")                              \
    _(TCP_TO_SYN_SENT, "tcp-timeout-syn-sent")                                 \
    _(TCP_TO_SYN_RECV, "tcp-timeout-syn-recv")                                 \
    _(TCP_TO_ESTABLISHED, "tcp-timeout-established")                           \
    _(TCP_TO_FIN_WAIT, "tcp-timeout-fin-wait")                                 \
    _(TCP_TO_CLOSE_WAIT, "tcp-timeout-close-wait")                             \
    _(TCP_TO_LAST_ACK, "tcp-timeout-last-ack")                                 \
    _(MAX, "max")

enum {
#define _(N, S) LB_MIB_##N,
    foreach_mibs
#undef _
};

struct lb_mib {
    uint64_t mibs[LB_MIB_MAX];
};

extern struct lb_mib *lb_mibs;

#define LB_MIB_INC_STATS(field) (lb_mibs[rte_lcore_id()].mibs[LB_MIB_##field]++)

int lb_mib_init(void);

#endif