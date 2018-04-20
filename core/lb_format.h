/* Copyright (c) 2018. TIG developer. */

#ifndef __LB_FORMAT_H__
#define __LB_FORMAT_H__

#define JSON_KV_S_FMT(K, D)  "\"" K "\"" ":" "\"" "%s" "\"" D
#define JSON_KV_64_FMT(K, D) "\"" K "\"" ":" "%" PRIu64 D
#define JSON_KV_32_FMT(K, D) "\"" K "\"" ":" "%" PRIu32 D

#define NORM_KV_S_FMT(K, D)  K ": %s" D
#define NORM_KV_64_FMT(K, D) K ": %" PRIu64 D
#define NORM_KV_32_FMT(K, D) K ": %" PRIu32 D

#define IPv4_BE_FMT	    "%u.%u.%u.%u"
#define IPv4_BE_ARG(ip)	(ip & 0xff),((ip & 0xff00) >> 8),((ip & 0xff0000) >> 16),((ip & 0xff000000) >> 24)

#define IPv4_BE(a, b, c, d) IPv4(d, c, b, a)

#define IPv4_FMT     "%u.%u.%u.%u"
#define IPv4_ARG(ip) ((ip & 0xff000000) >> 24),((ip & 0xff0000) >> 16),((ip & 0xff00) >> 8),(ip & 0xff)

#endif
