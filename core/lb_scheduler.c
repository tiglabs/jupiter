/* Copyright (c) 2018. TIG developer. */

#include <string.h>

#include <rte_lcore.h>
#include <rte_malloc.h>

#include <conhash.h>

#include "lb_scheduler.h"
#include "lb_ip_address.h"

struct lb_sched_ops {
    const char *name;
    void *(*alloc_data)(void);
    void (*free_data)(void *);
    int (*add_node)(struct lb_scheduler *, struct lb_sched_node *);
    int (*del_node)(struct lb_scheduler *, struct lb_sched_node *);
    struct lb_sched_node *(*dispatch)(struct lb_scheduler *, void *, uint16_t, uint8_t);
};

#define mem_alloc(size) rte_zmalloc(NULL, (size), 0);
#define mem_free(p) rte_free((p))

#define CONHASH_MAX_REPLICA 256

static void *
conhash_sched_alloc_data(void) {
    return conhash_init(NULL);
}

static void
conhash_sched_free_data(void *data) {
    conhash_fini(data);
}

static int
conhash_sched_add_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    struct conhash_s *conhash = sched->data;
    struct node_s *connode;

    connode = mem_alloc(sizeof(struct node_s));
    if (connode) {
        node->conhash_node = connode;
        conhash_set_node(connode, (char *)node->ident, CONHASH_MAX_REPLICA, node);
        conhash_add_node(conhash, connode);
        TAILQ_INSERT_TAIL(&sched->nodes, node, next);
        return 0;
    }
    return -1;
}

static int
conhash_sched_del_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    struct conhash_s *conhash = sched->data;
    struct node_s *connode = node->conhash_node;

    conhash_del_node(conhash, connode);
    mem_free(connode);
    node->userdata = NULL;
    return 0;
}

static struct lb_sched_node *
conhash_sched_dispatch_ipport(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4) {
    struct conhash_s *conhash = sched->data;
    struct node_s *connode;
    uint16_t key[(IPV6_ADDR_LEN + 2) / sizeof(uint16_t)];

    memset(key, 0, sizeof(key));
    if (is_ip4) {
        memcpy(key, caddr, IPV4_ADDR_LEN);
        key[2] = cport;
    } else {
        memcpy(key, caddr, IPV6_ADDR_LEN);
        key[8] = cport;
    }
    connode = conhash_lookup(conhash, (char *)key, sizeof(key));
    return connode != NULL ? connode->userdata : NULL;
}

static struct lb_sched_node *
conhash_sched_dispatch_iponly(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4) {
    struct conhash_s *conhash = sched->data;
    struct node_s *connode;
    uint16_t key[IPV6_ADDR_LEN / sizeof(uint16_t)];

    (void)cport;
    memset(key, 0, sizeof(key));
    if (is_ip4)
        memcpy(key, caddr, IPV4_ADDR_LEN);
    else
        memcpy(key, caddr, IPV6_ADDR_LEN);
    connode = conhash_lookup(conhash, (char *)key, sizeof(key));
    return connode != NULL ? connode->userdata : NULL;
}

typedef struct {
    struct {
        struct lb_sched_node *node;
    } __attribute__((aligned(RTE_CACHE_LINE_SIZE))) per_workers[RTE_MAX_LCORE];
} rr_data_t;

static void *
rr_sched_alloc_data(void) {
    return mem_alloc(sizeof(rr_data_t));
}

static void
rr_sched_free_data(void *data) {
    mem_free(data);
}

static int
rr_sched_add_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    rr_data_t *rr = sched->data;
    uint32_t wid;

    TAILQ_INSERT_TAIL(&sched->nodes, node, next);
    RTE_LCORE_FOREACH_SLAVE(wid) { rr->per_workers[wid].node = TAILQ_FIRST(&sched->nodes); }
    return 0;
}

static int
rr_sched_del_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    rr_data_t *rr = sched->data;
    uint32_t wid;

    TAILQ_REMOVE(&sched->nodes, node, next);
    RTE_LCORE_FOREACH_SLAVE(wid) { rr->per_workers[wid].node = TAILQ_FIRST(&sched->nodes); }
    return 0;
}

static struct lb_sched_node *
rr_sched_dispatch(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4) {
    rr_data_t *rr = sched->data;
    uint32_t wid = rte_lcore_id();
    struct lb_sched_node *node;

    (void)caddr;
    (void)cport;
    (void)is_ip4;
    node = rr->per_workers[wid].node;
    if (node == NULL)
        return NULL;
    node = TAILQ_NEXT(node, next);
    if (node == NULL)
        node = TAILQ_FIRST(&sched->nodes);
    rr->per_workers[wid].node = node;
    return node;
}

typedef struct {
    struct {
        struct lb_sched_node *node;
        int cw;
    } __attribute__((aligned(RTE_CACHE_LINE_SIZE))) per_workers[RTE_MAX_LCORE];
    int mw;
    int dw;
} wrr_data_t;

static void *
wrr_sched_alloc_data(void) {
    return mem_alloc(sizeof(wrr_data_t));
}

static void
wrr_sched_free_data(void *data) {
    mem_free(data);
}

static inline int
wrr_max_weight(struct lb_scheduler *sched) {
    struct lb_sched_node *node;
    int max = 0;

    TAILQ_FOREACH(node, &sched->nodes, next) {
        if (max < node->weight)
            max = node->weight;
    }
    return max;
}

static inline int
gcd(int a, int b) {
    int c;

    while ((c = a % b)) {
        a = b;
        b = c;
    }
    return b;
}

static inline int
wrr_gcd_weight(struct lb_scheduler *sched) {
    struct lb_sched_node *node;
    int g = 0;

    TAILQ_FOREACH(node, &sched->nodes, next) {
        if (node->weight == 0)
            continue;
        if (g == 0)
            g = node->weight;
        else
            g = gcd(g, node->weight);
    }
    return g ? g : 1;
}

static inline void
wrr_update_weight(struct lb_scheduler *sched) {
    wrr_data_t *wrr = sched->data;
    struct lb_sched_node *node;
    int weight = 0;
    uint32_t i;

    wrr->mw = wrr_max_weight(sched);
    wrr->dw = wrr_gcd_weight(sched);
    TAILQ_FOREACH(node, &sched->nodes, next) {
        if (node->weight != 0) {
            weight = node->weight;
            break;
        }
    }

    RTE_LCORE_FOREACH_SLAVE(i) {
        wrr->per_workers[i].node = node;
        wrr->per_workers[i].cw = weight;
    }
}

static int
wrr_sched_add_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    struct lb_sched_node *p;

    TAILQ_FOREACH(p, &sched->nodes, next) {
        if (p->weight >= node->weight)
            break;
    }

    if (p != NULL)
        TAILQ_INSERT_BEFORE(p, node, next);
    else
        TAILQ_INSERT_TAIL(&sched->nodes, node, next);

    wrr_update_weight(sched);
    return 0;
}

static int
wrr_sched_del_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    TAILQ_REMOVE(&sched->nodes, node, next);
    wrr_update_weight(sched);
    return 0;
}

static struct lb_sched_node *
wrr_sched_dispatch(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4) {
    wrr_data_t *wrr = sched->data;
    struct lb_sched_node *node, *p;
    uint32_t wid = rte_lcore_id();
    int cw;

    (void)caddr;
    (void)cport;
    (void)is_ip4;
    cw = wrr->per_workers[wid].cw;
    node = wrr->per_workers[wid].node;
    if (node == NULL)
        return NULL;
    cw -= wrr->dw;
    if (cw >= 0)
        goto hit;
    p = node;
    do {
        node = TAILQ_NEXT(node, next);
        if (node == NULL)
            node = TAILQ_FIRST(&sched->nodes);
        cw = node->weight;
        cw -= wrr->dw;
        if (cw >= 0)
            goto hit;
    } while (node != p);
    return NULL;

hit:
    wrr->per_workers[wid].cw = cw;
    wrr->per_workers[wid].node = node;
    return node;
}

static struct lb_sched_ops sched_ops[] = {
    {
        .name = "ipport",
        .alloc_data = conhash_sched_alloc_data,
        .free_data = conhash_sched_free_data,
        .add_node = conhash_sched_add_node,
        .del_node = conhash_sched_del_node,
        .dispatch = conhash_sched_dispatch_ipport,
    },
    {
        .name = "iponly",
        .alloc_data = conhash_sched_alloc_data,
        .free_data = conhash_sched_free_data,
        .add_node = conhash_sched_add_node,
        .del_node = conhash_sched_del_node,
        .dispatch = conhash_sched_dispatch_iponly,
    },
    {
        .name = "rr",
        .alloc_data = rr_sched_alloc_data,
        .free_data = rr_sched_free_data,
        .add_node = rr_sched_add_node,
        .del_node = rr_sched_del_node,
        .dispatch = rr_sched_dispatch,
    },
    {
        .name = "wrr",
        .alloc_data = wrr_sched_alloc_data,
        .free_data = wrr_sched_free_data,
        .add_node = wrr_sched_add_node,
        .del_node = wrr_sched_del_node,
        .dispatch = wrr_sched_dispatch,
    },
};

static struct lb_sched_ops *
sched_ops_lookup(const char *name) {
    uint32_t i;

    for (i = 0; i < RTE_DIM(sched_ops); i++) {
        if (strcasecmp(name, sched_ops[i].name) == 0) {
            return sched_ops + i;
        }
    }
    return NULL;
}

int
lb_scheduler_init(struct lb_scheduler *sched, const char *name) {
    struct lb_sched_ops *ops;
    void *data;

    if ((ops = sched_ops_lookup(name)) == NULL) {
        return -1;
    }
    if ((data = ops->alloc_data()) == NULL) {
        return -1;
    }
    strncpy(sched->name, name, LB_SCHED_NAMESIZE);
    sched->ops = ops;
    sched->data = data;
    TAILQ_INIT(&sched->nodes);
    return 0;
}

void
lb_scheduler_uninit(struct lb_scheduler *sched) {
    sched->ops->free_data(sched->data);
}

int
lb_scheduler_add_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    return sched->ops->add_node(sched, node);
}

int
lb_scheduler_del_node(struct lb_scheduler *sched, struct lb_sched_node *node) {
    return sched->ops->del_node(sched, node);
}

struct lb_sched_node *
lb_scheduler_dispatch(struct lb_scheduler *sched, void *caddr, uint16_t cport, uint8_t is_ip4) {
    return sched->ops->dispatch(sched, caddr, cport, is_ip4);
}