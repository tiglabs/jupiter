/* Copyright (c) 2017. TIG developer. */

#ifndef __LB_SCHEDULE_H__
#define __LB_SCHEDULE_H__

struct lb_real_service;
struct lb_virt_service;

struct lb_scheduler {
    const char *name;
    int (*construct)(struct lb_virt_service *);
    void (*destruct)(struct lb_virt_service *);
    int (*add)(struct lb_virt_service *, struct lb_real_service *);
    int (*del)(struct lb_virt_service *, struct lb_real_service *);
    struct lb_real_service *(*dispatch)(struct lb_virt_service *, uint32_t,
                                        uint16_t);
};

const struct lb_scheduler *lb_scheduler_lookup_by_name(const char *name);

#endif

