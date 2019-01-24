/* Copyright (c) 2018. TIG developer. */

#include <rte_lcore.h>
#include <rte_malloc.h>

#include <unixctl_command.h>

#include "lb.h"
#include "lb_mib.h"

static const char *mib_strings[] = {
#define _(N, S) [LB_MIB_##N] = S,
    foreach_mibs
#undef _
};

struct lb_mib *lb_mibs;

int
lb_mib_init(void) {
    lb_mibs = rte_malloc(NULL, sizeof(struct lb_mib) * RTE_MAX_LCORE, 0);
    if (!lb_mibs) {
        log_err("%s(): alloc memory for mib failed.\n", __func__);
        return -1;
    }
    return 0;
}

static void
mib_stats_show(int fd, __attribute__((unused)) char *argv[],
               __attribute__((unused)) int argc) {
    uint32_t i;
    uint32_t lcore_id;
    uint64_t count;

    for (i = 0; i < LB_MIB_MAX; i++) {
        count = 0;
        RTE_LCORE_FOREACH(lcore_id) {
            count += lb_mibs[lcore_id].mibs[i];
        }
        unixctl_command_reply(fd, "%s: %u\n", mib_strings[i], count);
    }
}

UNIXCTL_CMD_REGISTER("mib/stats", "", "Show local ip address.", 0, 0,
                     mib_stats_show);