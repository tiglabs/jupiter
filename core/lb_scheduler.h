/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_SCHEDULER_H__
#define __LB_SCHEDULER_H__

struct lb_real_service;
struct lb_virt_service;

struct lb_scheduler {
    const char *name;
    int (*init)(struct lb_virt_service *);
    void (*fini)(struct lb_virt_service *);
    int (*add)(struct lb_virt_service *, struct lb_real_service *);
    int (*del)(struct lb_virt_service *, struct lb_real_service *);
	int (*update)(struct lb_virt_service *, struct lb_real_service *);
    struct lb_real_service *(*dispatch)(struct lb_virt_service *, uint32_t,
                                        uint16_t);
};

int lb_scheduler_lookup_by_name(const char *name,
                                const struct lb_scheduler **sched);

#endif

