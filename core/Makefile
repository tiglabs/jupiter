# Copyright (c) 2017. TIG developer.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = jupiter-service

# all source are stored in SRCS-y
SRCS-y := main.c parser.c lb_config.c lcore_event.c lb_device.c lb_arp.c \
		  lb_service.c lb_schedule.c lb_connection.c lb_checksum.c lb_conntrack_tcp.c \
		  lb_proto_tcp.c lb_proto_udp.c lb_proto_icmp.c lb_cql.c

CFLAGS += $(WERROR_FLAGS) -O3

CFLAGS += -I$(SRCDIR)/../lib/libconhash/$(RTE_TARGET)/include
LDLIBS += -L$(SRCDIR)/../lib/libconhash/$(RTE_TARGET)/lib -lconhash

CFLAGS += -I$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/include
LDLIBS += -L$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/lib -lcmd

include $(RTE_SDK)/mk/rte.extapp.mk
