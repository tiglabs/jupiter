# Copyright (c) 2018. TIG developer.

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = libcjson.a

# all source are stored in SRCS-y
SRCS-y := cjson.c
SYMLINK-y-include += cjson.h

CFLAGS += $(WERROR_FLAGS) -g -O2

include $(RTE_SDK)/mk/rte.extlib.mk
