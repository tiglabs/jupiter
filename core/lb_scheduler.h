/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_SCHEDULER_H__
#define __LB_SCHEDULER_H__

#include <sys/queue.h>

#define LB_SCHED_NODE_IDEN_MAX 32
#define LB_SCHED_NAMESIZE 64

struct lb_sched_ops;

struct lb_sched_node {
    TAILQ_ENTRY(lb_sched_node) next;
    char ident[LB_SCHED_NODE_IDEN_MAX];
    int weight;
    void *userdata;
    void *conhash_node;
};

struct lb_scheduler {
    char name[LB_SCHED_NAMESIZE];
    struct lb_sched_ops *ops;
    void *data;
    TAILQ_HEAD(, lb_sched_node) nodes;
};

int lb_scheduler_init(struct lb_scheduler *sched, const char *name);
void lb_scheduler_uninit(struct lb_scheduler *sched);
int lb_scheduler_add_node(struct lb_scheduler *sched, struct lb_sched_node *node);
int lb_scheduler_del_node(struct lb_scheduler *sched, struct lb_sched_node *node);
struct lb_sched_node *lb_scheduler_dispatch(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4);

#endif