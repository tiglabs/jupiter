/* Copyright (c) 2018. TIG developer. */

#include <rte_cycles.h>
#include <rte_random.h>

#include "lb_md5.h"
#include "lb_tcp_secret_seq.h"

#ifndef __rte_cache_aligned
#define __rte_cache_aligned __rte_aligned(RTE_CACHE_LINE_SIZE)
#endif

static uint32_t seq_secret[MD5_MESSAGE_BYTES / 4] __rte_cache_aligned;

static void
seq_secret_init(void) {
    int i;
    static uint8_t inited = 0;

    if (likely(inited))
        return;

    for (i = 0; i < MD5_MESSAGE_BYTES / 4; i++) {
        seq_secret[i] = rte_rand();
    }

    inited = 1;
}

uint32_t
tcp_secret_new_seq(uint32_t saddr, uint32_t daddr, uint16_t sport,
                   uint16_t dport) {
    uint32_t hash[MD5_DIGEST_WORDS];
    uint64_t ns;

    seq_secret_init();

    hash[0] = saddr;
    hash[1] = daddr;
    hash[2] = (sport << 16) + dport;
    hash[3] = seq_secret[15];

    md5_transform(hash, seq_secret);
    ns = rte_get_tsc_cycles() / ((rte_get_tsc_hz() + NS_PER_S - 1) / NS_PER_S);
    return hash[0] + (uint32_t)(ns >> 6);
}

