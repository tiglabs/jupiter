# Copyright (c) 2018. TIG developer.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = jupiter-ctl

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += $(WERROR_FLAGS) -g -O3

CFLAGS += -I$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/include
LDLIBS += -L$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/lib -lcmd

include $(RTE_SDK)/mk/rte.extapp.mk
