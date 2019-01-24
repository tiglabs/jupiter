/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_IP_ADDRESS_H__
#define __LB_IP_ADDRESS_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include <rte_byteorder.h>

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

typedef union {
    uint8_t as_u8[4];
    uint32_t as_u32;
} ip4_address_t;

typedef union {
    uint8_t as_u8[16];
    uint32_t as_u32[4];
    uint64_t as_u64[2];
} ip6_address_t;

typedef union {
    ip4_address_t ip4;
    ip6_address_t ip6;
    uint8_t as_u8[16];
    uint32_t as_u32[4];
    uint64_t as_u64[2];
} ip46_address_t;

static inline int
ip46_address_is_ip4(ip46_address_t *ip46) {
    return (ip46->as_u32[1] | ip46->as_u32[2] | ip46->as_u32[3]) == 0;
}

static inline void
ip46_address_set_ip4(ip46_address_t *ip46, ip4_address_t *ip4) {
    ip46->ip4.as_u32 = ip4->as_u32;
    ip46->as_u32[1] = 0;
    ip46->as_u32[2] = 0;
    ip46->as_u32[3] = 0;
}

static inline void
ip46_address_set_ip6(ip46_address_t *ip46, ip6_address_t *ip6) {
    ip46->ip6.as_u64[0] = ip6->as_u64[0];
    ip46->ip6.as_u64[1] = ip6->as_u64[1];
}

static inline void
ip46_address_reset(ip46_address_t *ip46) {
    ip46->as_u64[0] = 0;
    ip46->as_u64[1] = 0;
}

static inline int
ip46_address_cmp(ip46_address_t *a1, ip46_address_t *a2) {
    return memcmp(a1, a2, sizeof(ip46_address_t));
}

static inline void
ip46_address_copy(ip46_address_t *dst, ip46_address_t *src) {
    dst->as_u64[0] = src->as_u64[0];
    dst->as_u64[1] = src->as_u64[1];
}

static inline void
ip4_address_copy(ip4_address_t *dst, ip4_address_t *src) {
    dst->as_u32 = src->as_u32;
}

static inline void
ip6_address_copy(ip6_address_t *dst, ip6_address_t *src) {
    dst->as_u64[0] = src->as_u64[0];
    dst->as_u64[1] = src->as_u64[1];
}

static inline int
ip6_address_cmp(ip6_address_t *a1, ip6_address_t *a2) {
    return memcmp(a1, a2, sizeof(ip6_address_t));
}

static inline int
ip4_address_is_equal_masked(const ip4_address_t *addr1,
                            const ip4_address_t *addr2,
                            const ip4_address_t *netmask) {
    return (addr1->as_u32 & netmask->as_u32) ==
           (addr2->as_u32 & netmask->as_u32);
}

static inline int
ip6_address_is_equal_masked(const ip6_address_t *addr1,
                            const ip6_address_t *addr2,
                            const ip6_address_t *netmask) {
    return ((addr1->as_u64[0] & netmask->as_u64[0]) ==
            (addr2->as_u64[0] & netmask->as_u64[0])) &&
           ((addr1->as_u64[1] & netmask->as_u64[1]) ==
            (addr2->as_u64[1] & netmask->as_u64[1]));
}

static inline void
ip6_address_bswap(ip6_address_t *ip6) {
    uint64_t tmp;

    tmp = rte_bswap64(ip6->as_u64[0]);
    ip6->as_u64[0] = rte_bswap64(ip6->as_u64[1]);
    ip6->as_u64[1] = tmp;
}

static inline const char *
ip4_address_format(ip4_address_t *ip4, char *s) {
    return inet_ntop(AF_INET, ip4, s, INET_ADDRSTRLEN);
}

static inline const char *
ip6_address_format(ip6_address_t *ip6, char *s) {
    return inet_ntop(AF_INET6, ip6, s, INET6_ADDRSTRLEN);
}

static inline const char *
ip46_address_format(ip46_address_t *ip46, char *s) {
    if (ip46_address_is_ip4(ip46)) {
        return inet_ntop(AF_INET, &ip46->ip4, s, INET_ADDRSTRLEN);
    } else {
        return inet_ntop(AF_INET6, &ip46->ip6, s, INET6_ADDRSTRLEN);
    }
    return NULL;
}

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr)                                                       \
    (uint8_t)((addr)&0xFF), (uint8_t)(((addr) >> 8) & 0xFF),                   \
        (uint8_t)(((addr) >> 16) & 0xFF), (uint8_t)(((addr) >> 24) & 0xFF)
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT                                                         \
    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"                                     \
    "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr)                                                       \
    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],    \
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14],    \
        addr[15]
#endif

#endif
