# Copyright (c) 2018. TIG developer.

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
LIB = libcryptohash.a

# all source are stored in SRCS-y
SRCS-y := md5.c sha1.c
SYMLINK-y-include += cryptohash.h

CFLAGS += $(WERROR_FLAGS) -g -O2

include $(RTE_SDK)/mk/rte.extlib.mk
