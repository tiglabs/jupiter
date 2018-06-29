# Copyright (c) 2018. TIG developer.

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = jupiter-ctl

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += $(WERROR_FLAGS) -g -O3

CFLAGS += -I$(LB_DIR)/lib/libcmd/$(RTE_TARGET)/include
LDLIBS += -L$(LB_DIR)/lib/libcmd/$(RTE_TARGET)/lib -lcmd

include $(RTE_SDK)/mk/rte.extapp.mk
