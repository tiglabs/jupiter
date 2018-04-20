/* Copyright (c) 2018. TIG developer. */

#include <netinet/in.h>

#include <rte_log.h>

#include "lb_proto.h"

struct lb_proto *lb_protos[LB_IPPROTO_MAX];

enum lb_proto_type lb_proto_types[IPPROTO_MAX];

int
lb_proto_init(void) {
    uint16_t i;

    RTE_LOG(INFO, USER1, "%s(): lb_protos[%u] size = %luKB\n", __func__,
            LB_IPPROTO_MAX, (sizeof(lb_protos) + 1023) / 1024);

    for (i = 0; i < LB_IPPROTO_MAX; i++) {
        if (lb_protos[i] != NULL && lb_protos[i]->init() < 0) {
            RTE_LOG(ERR, USER1, "%s(): proto[%u] init failed.\n", __func__, i);
            return -1;
        }
    }

    return 0;
}

