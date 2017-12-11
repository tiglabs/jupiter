/* Copyright (c) 2017. TIG developer. */

#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

struct ipv4_hdr;
struct rte_mbuf;
struct tcp_hdr;
struct udp_hdr;

uint16_t ipv4_cksum(struct ipv4_hdr *iph, struct rte_mbuf *mbuf);
uint16_t ipv4_tcp_cksum(struct ipv4_hdr *iph, struct tcp_hdr *th,
                        struct rte_mbuf *mbuf);
uint16_t ipv4_udp_cksum(struct ipv4_hdr *iph, struct udp_hdr *uh,
                        struct rte_mbuf *mbuf);
uint16_t icmp_checksum(void *buffer, size_t len);

#endif

