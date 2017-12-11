/* Copyright (c) 2017. TIG developer. */

#include <stdio.h>

#include <rte_mempool.h>
#include <rte_ring.h>

#include "lcore_event.h"
#include "unixctl_command.h"

#define RTE_LOGTYPE_EVENT RTE_LOGTYPE_USER1

#define LCORE_EVENT_COUNT_PER_QUE 512
#define LCORE_EVENT_MAX_COUNT (RTE_MAX_LCORE / 2 * LCORE_EVENT_COUNT_PER_QUE)
#define LCORE_EVENT_MAX_BURST 32

struct lcore_event {
    void (*handle)(unsigned, void *);
    void *param;
    unsigned snd_cid;
};

static struct rte_ring *lcore_event_q[RTE_MAX_LCORE];
static struct rte_mempool *lcore_event_pool;

static volatile uint64_t lcore_event_nobuf_err = 0;
static volatile uint64_t lcore_event_enq_err = 0;

int
lcore_event_notify(unsigned recv_cid, void (*handle)(unsigned, void *),
                   void *param) {
    struct lcore_event *event;
    int ret;

    ret = rte_mempool_get(lcore_event_pool, (void **)&event);
    if (unlikely(ret < 0)) {
        lcore_event_nobuf_err++;
        return -1;
    }

    event->handle = handle;
    event->param = param;
    event->snd_cid = rte_lcore_id();

    ret = rte_ring_mp_enqueue(lcore_event_q[recv_cid], (void *)event);
    if (unlikely(ret == -ENOBUFS)) {
        lcore_event_enq_err++;
        rte_mempool_put(lcore_event_pool, (void *)event);
        return -1;
    }
    return 0;
}

void
lcore_event_poll(unsigned lcore_id) {
    struct lcore_event *events[LCORE_EVENT_MAX_BURST];
    unsigned idx, nb;
    int ret;

    ret = rte_ring_empty(lcore_event_q[lcore_id]);
    if (likely(ret == 1))
        return;

    nb = rte_ring_sc_dequeue_burst(lcore_event_q[lcore_id], (void **)events,
                                   LCORE_EVENT_MAX_BURST, NULL);
    for (idx = 0; idx < nb; idx++) {
        events[idx]->handle(events[idx]->snd_cid, events[idx]->param);
        rte_mempool_put(lcore_event_pool, (void *)events[idx]);
    }
}

int
lcore_event_show_stats(char *buf, int len) {
    memset(buf, 0, len);
    return snprintf(buf, len, "levent-avail-count: %-10" PRIu32 "\n"
                              "levent-in-use-count: %-10" PRIu32 "\n"
                              "levent-no-mbuf-err: %-10" PRIu64 "\n"
                              "levent-enq-ring-err: %-10" PRIu64 "\n",
                    rte_mempool_avail_count(lcore_event_pool),
                    rte_mempool_in_use_count(lcore_event_pool),
                    lcore_event_nobuf_err, lcore_event_enq_err);
}

static void
lcore_event_stats_cmd_cb(int fd, __attribute__((unused)) char *argv[],
                         __attribute__((unused)) int argc) {
    char buf[512];

    lcore_event_show_stats(buf, 512);
    unixctl_command_reply(fd, buf);
}

void
lcore_event_init(void) {
    unsigned lcore_id;
    char name[RTE_RING_NAMESIZE];

    RTE_LCORE_FOREACH(lcore_id) {
        snprintf(name, RTE_RING_NAMESIZE, "eventq-%u", lcore_id);
        lcore_event_q[lcore_id] = rte_ring_create(
            name, LCORE_EVENT_COUNT_PER_QUE, rte_socket_id(), 0);
        if (lcore_event_q[lcore_id] == NULL)
            rte_exit(EXIT_FAILURE, "create lcore-event queue failed.\n");
    }

    lcore_event_pool = rte_mempool_create(
        "eventpool", LCORE_EVENT_MAX_COUNT, sizeof(struct lcore_event), 256, 0,
        NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (lcore_event_pool == NULL)
        rte_exit(EXIT_FAILURE, "create lcore-event pool failed.\n");

    unixctl_command_register("lcore-event/stats", "",
                             "Show lcore event resource usage.", 0, 0,
                             lcore_event_stats_cmd_cb);
}

