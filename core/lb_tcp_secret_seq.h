/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_TCP_SECRET_SEQ_H__
#define __LB_TCP_SECRET_SEQ_H__

#include <rte_byteorder.h>
#include <rte_tcp.h>

struct tcp_secret_seq {
    uint32_t isn;
    uint32_t oft;
};

uint32_t tcp_secret_new_seq(uint32_t saddr, uint32_t daddr, uint16_t sport,
                            uint16_t dport);

static inline void
tcp_secret_seq_init(uint32_t saddr, uint32_t daddr, uint16_t sport,
                    uint16_t dport, uint32_t isn, struct tcp_secret_seq *tseq) {
    tseq->isn = tcp_secret_new_seq(saddr, daddr, sport, dport);
    tseq->oft = tseq->isn - isn;
}

static inline void
tcp_secret_seq_adjust_client(struct tcp_hdr *th, struct tcp_secret_seq *tseq) {
    th->sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(th->sent_seq) + tseq->oft);
}

static inline void
tcp_secret_seq_adjust_backend(struct tcp_hdr *th, struct tcp_secret_seq *tseq) {
    th->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(th->recv_ack) - tseq->oft);
}

#endif

