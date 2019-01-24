/* Copyright (c) 2018. TIG developer. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/queue.h>

#include "lb_timer_wheel.h"

#define LB_TW_INVALID_SLOT_ID (-1U)

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
    for ((var) = TAILQ_FIRST((head));                                          \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

void
lb_tw_timer_init(struct lb_tw_timer *timer) {
    memset(timer, 0, sizeof(struct lb_tw_timer));
    timer->slot_id = LB_TW_INVALID_SLOT_ID;
}

void
lb_tw_timer_restart(struct lb_tw_timer_wheel *tw, struct lb_tw_timer *timer,
                    uint32_t timeout, lb_tw_timer_cb_t cb, void *arg) {
    uint32_t slot_offset;

    if (timer->slot_id != LB_TW_INVALID_SLOT_ID)
        TAILQ_REMOVE(&tw->slots[timer->slot_id], timer, next);
    slot_offset = timeout / tw->timer_interval;
    timer->slot_id = (tw->next_slot_id + slot_offset) % LB_TW_SLOT_NUM;
    timer->timeout = timeout;
    timer->callback = cb;
    timer->arg = arg;
    TAILQ_INSERT_TAIL(&tw->slots[timer->slot_id], timer, next);
}

void
lb_tw_timer_stop(struct lb_tw_timer_wheel *tw, struct lb_tw_timer *timer) {
    if (timer->slot_id != LB_TW_INVALID_SLOT_ID) {
        TAILQ_REMOVE(&tw->slots[timer->slot_id], timer, next);
        timer->slot_id = LB_TW_INVALID_SLOT_ID;
    }
}

void
lb_tw_timer_wheel_init(struct lb_tw_timer_wheel *tw, uint32_t timer_interval) {
    uint32_t id;

    for (id = 0; id < LB_TW_SLOT_NUM; id++) {
        TAILQ_INIT(&tw->slots[id]);
    }
    tw->next_slot_id = 0;
    tw->timer_interval = timer_interval;
}

void
lb_tw_timer_wheel_expire(struct lb_tw_timer_wheel *tw) {
    struct lb_tw_timer *timer, *tmp;

    TAILQ_FOREACH_SAFE(timer, &tw->slots[tw->next_slot_id], next, tmp) {
        if (timer->timeout <= tw->timer_interval * LB_TW_SLOT_NUM) {
            TAILQ_REMOVE(&tw->slots[tw->next_slot_id], timer, next);
            timer->slot_id = LB_TW_INVALID_SLOT_ID;
            timer->callback(timer, timer->arg);
        } else {
            timer->timeout -= tw->timer_interval * LB_TW_SLOT_NUM;
        }
    }
    tw->next_slot_id = (tw->next_slot_id + 1) % LB_TW_SLOT_NUM;
}

uint32_t
lb_tw_timer_calc_timeout(struct lb_tw_timer_wheel *tw,
                         struct lb_tw_timer *timer) {
    if (timer->slot_id == LB_TW_INVALID_SLOT_ID)
        return 0;
    return (timer->slot_id - tw->next_slot_id + LB_TW_SLOT_NUM) %
               LB_TW_SLOT_NUM * tw->timer_interval +
           timer->timeout / (tw->timer_interval * LB_TW_SLOT_NUM) *
               (tw->timer_interval * LB_TW_SLOT_NUM);
}