/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_TIMER_WHEEL_H__
#define __LB_TIMER_WHEEL_H__

#include <stdint.h>
#include <sys/queue.h>

#define LB_TW_SLOT_NUM (16 << 10)

struct lb_tw_timer;

typedef void (*lb_tw_timer_cb_t)(struct lb_tw_timer *, void *);

struct lb_tw_timer {
    TAILQ_ENTRY(lb_tw_timer) next;
    uint32_t timeout; /* ms */
    uint32_t slot_id;
    lb_tw_timer_cb_t callback;
    void *arg;
};

struct lb_tw_timer_wheel {
    TAILQ_HEAD(, lb_tw_timer) slots[LB_TW_SLOT_NUM];
    uint32_t next_slot_id;
    uint32_t timer_interval; /* ms */
};

void lb_tw_timer_init(struct lb_tw_timer *timer);
void lb_tw_timer_restart(struct lb_tw_timer_wheel *tw,
                         struct lb_tw_timer *timer, uint32_t timeout,
                         lb_tw_timer_cb_t cb, void *arg);
void lb_tw_timer_stop(struct lb_tw_timer_wheel *tw, struct lb_tw_timer *timer);
void lb_tw_timer_wheel_init(struct lb_tw_timer_wheel *tw,
                            uint32_t timer_interval);
void lb_tw_timer_wheel_expire(struct lb_tw_timer_wheel *tw);

uint32_t lb_tw_timer_calc_timeout(struct lb_tw_timer_wheel *tw,
                                  struct lb_tw_timer *timer);
#endif