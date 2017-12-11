/* Copyright (c) 2017. TIG developer. */

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
LIB = libcmd.a

# all source are stored in SRCS-y
SRCS-y := unixctl_command.c
SYMLINK-y-include += unixctl_command.h

CFLAGS += $(WERROR_FLAGS) -O3

include $(RTE_SDK)/mk/rte.extlib.mk
