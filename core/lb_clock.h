#ifndef __LB_CLOCK_H__
/* Copyright (c) 2018. TIG developer. */

#define __LB_CLOCK_H__

#include <rte_atomic.h>
#include <rte_cycles.h>

extern rte_atomic32_t lb_clock;

#define LB_CLOCK_HZ (100)

#define LB_CLOCK_PER_S LB_CLOCK_HZ

#define LB_CLOCK() ((uint32_t)rte_atomic32_read(&lb_clock))

/* MS_PER_S defined in rte_cycles.h */
#define MS_TO_CYCLES(a) ((rte_get_timer_hz() + MS_PER_S - 1) / MS_PER_S * (a))

#define SEC_TO_CYCLES(a) (rte_get_timer_hz() * (a))

#define SEC_TO_LB_CLOCK(a) (LB_CLOCK_PER_S * (a))

#define LB_CLOCK_TO_SEC(a) (((a) + LB_CLOCK_PER_S - 1) / LB_CLOCK_PER_S)

#endif

