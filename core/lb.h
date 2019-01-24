/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_H__
#define __LB_H__

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>

typedef int bool;

#undef TRUE
#define TRUE 1

#undef FALSE
#define FALSE 0

extern uint32_t lb_lcore_indexs[RTE_MAX_LCORE];

static inline uint32_t
lb_lcore_index(uint32_t lcore_id) {
    return lb_lcore_indexs[lcore_id];
}

#define LB_CLOCK_HZ (100)

#define LB_CLOCK_PER_S LB_CLOCK_HZ

extern rte_atomic32_t lb_clock;

#define LB_CLOCK() ((uint32_t)rte_atomic32_read(&lb_clock))

/* MS_PER_S defined in rte_cycles.h */
#define MS_TO_CYCLES(a) ((rte_get_timer_hz() + MS_PER_S - 1) / MS_PER_S * (a))

#define SEC_TO_CYCLES(a) (rte_get_timer_hz() * (a))

#define SEC_TO_LB_CLOCK(a) (LB_CLOCK_PER_S * (a))

#define LB_CLOCK_TO_SEC(a) (((a) + LB_CLOCK_PER_S - 1) / LB_CLOCK_PER_S)

static inline uint64_t
lb_time_now_ns(void) {
    static const uint64_t ns_per_sec = 1000 * 1000 * 1000;

    return rte_get_timer_cycles() /
           ((rte_get_timer_hz() + ns_per_sec - 1) / ns_per_sec);
}

static inline uint64_t
lb_time_now_us(void) {
    static const uint64_t us_per_sec = 1000 * 1000;

    return rte_get_timer_cycles() /
           ((rte_get_timer_hz() + us_per_sec - 1) / us_per_sec);
}

static inline uint64_t
lb_time_now_ms(void) {
    static const uint64_t ms_per_sec = 1000;

    return rte_get_timer_cycles() /
           ((rte_get_timer_hz() + ms_per_sec - 1) / ms_per_sec);
}

static inline uint64_t
lb_time_now_sec(void) {
    return rte_get_timer_cycles() / rte_get_timer_hz();
}

#define PKT_RX_BURST_MAX 32

typedef enum {
    LB_PROTO_TCP,
    LB_PROTO_UDP,
    LB_PROTO_MAX,
} lb_proto_t;

const char *lb_proto_str(lb_proto_t proto);

typedef enum {
    LB_DIR_OUT2IN,
    LB_DIR_IN2OUT,
    LB_DIR_MAX,
} lb_direction_t;

#define RTE_LOGTYPE_JUPITER RTE_LOGTYPE_USER1

#define log_err(...) RTE_LOG(ERR, JUPITER, __VA_ARGS__)
#define log_warning(...) RTE_LOG(WARNING, JUPITER, __VA_ARGS__)
#define log_info(...) RTE_LOG(INFO, JUPITER, __VA_ARGS__)
#define log_debug(...) RTE_LOG(DEBUG, JUPITER, __VA_ARGS__)

#endif