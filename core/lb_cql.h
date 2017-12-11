/* Copyright (c) 2017. TIG developer. */

/* CQL: client query limit */

#ifndef __LB_CQL_H__
#define __LB_CQL_H__

struct lb_cql;

int lb_cql_rule_add(struct lb_cql *cql, uint32_t ip, uint32_t qps);
void lb_cql_rule_del(struct lb_cql *cql, uint32_t ip);
int lb_cql_rule_iterate(struct lb_cql *cql, uint32_t *ip, uint32_t *qps,
                        uint32_t *next);
int lb_cql_check(struct lb_cql *cql, uint32_t ip, uint64_t time);
uint32_t lb_cql_size(struct lb_cql *cql);
struct lb_cql *lb_cql_create(const char *name, uint32_t size);
void lb_cql_destory(struct lb_cql *cql);

#endif

