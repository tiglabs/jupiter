/* Copyright (c) 2017. TIG developer. */

#ifndef __CONNTRACK_TCP_H__
#define __CONNTRACK_TCP_H__

struct tcp_hdr;
struct lb_connection;

#define CONNTRACK_F_ACTIVE 0x1

int tcp_set_conntrack_state(struct lb_connection *conn, struct tcp_hdr *th,
                            int dir);
#endif

