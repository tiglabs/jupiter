/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_TCP_SYNPROXY_H__
#define __LB_TCP_SYNPROXY_H__

int synproxy_recv_client_syn(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                             uint8_t is_ip4);
int synproxy_recv_client_ack(struct rte_mbuf *m, void *iph, struct tcp_hdr *th,
                             uint8_t is_ip4);
int synproxy_recv_backend_synack(struct rte_mbuf *m, void *iph,
                                 struct tcp_hdr *th, struct lb_connection *conn,
                                 uint8_t is_ip4);

#endif