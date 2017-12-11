/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_RWLOCK_H__
#define __LB_RWLOCK_H__

#include <rte_rwlock.h>

extern rte_rwlock_t lb_thread_rwlock;

static inline void
thread_rwlock_init(void) {
    rte_rwlock_init(&lb_thread_rwlock);
}

static inline void
thread_read_lock(void) {
    rte_rwlock_read_lock(&lb_thread_rwlock);
}

static inline void
thread_read_unlock(void) {
    rte_rwlock_read_unlock(&lb_thread_rwlock);
}

static inline void
thread_write_lock(void) {
    rte_rwlock_write_lock(&lb_thread_rwlock);
}

static inline void
thread_write_unlock(void) {
    rte_rwlock_write_unlock(&lb_thread_rwlock);
}

#endif

