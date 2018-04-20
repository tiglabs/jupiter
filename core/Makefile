# Copyright (c) 2018. TIG developer.

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

ifeq ($(RTE_TARGET),)
$(error "Please define RTE_TARGET environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = jupiter-service

# all source are stored in SRCS-y
SRCS-y := main.c lb_device.c lb_arp.c lb_parser.c lb_service.c lb_scheduler.c \
          lb_conn.c lb_proto.c lb_proto_tcp.c lb_toa.c lb_synproxy.c \
          lb_proto_udp.c lb_proto_icmp.c lb_tcp_secret_seq.c \
          lb_config.c

CFLAGS += $(WERROR_FLAGS) -g -O3

CFLAGS += -I$(SRCDIR)/../lib/libconhash/$(RTE_TARGET)/include
LDLIBS += -L$(SRCDIR)/../lib/libconhash/$(RTE_TARGET)/lib -lconhash

CFLAGS += -I$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/include
LDLIBS += -L$(SRCDIR)/../lib/libcmd/$(RTE_TARGET)/lib -lcmd

include $(RTE_SDK)/mk/rte.extapp.mk
