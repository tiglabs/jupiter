# Copyright (c) 2018. TIG developer.

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = jupiter-service

# all source are stored in SRCS-y
SRCS-y := lb.c lb_scheduler.c lb_fnat_laddr.c lb_service.c  lb_connection.c \
          lb_timer_wheel.c lb_parser.c lb_config.c lb_device.c lb_ip_neighbour.c \
          lb_arp.c lb_icmp6.c lb_icmp.c lb_tcp.c lb_tcp_synproxy.c lb_udp.c \
          lb_mib.c

CFLAGS += $(WERROR_FLAGS) -g -O2

CFLAGS += -I$(LB_DIR)/lib/libconhash/$(RTE_TARGET)/include
LDLIBS += -L$(LB_DIR)/lib/libconhash/$(RTE_TARGET)/lib -lconhash

CFLAGS += -I$(LB_DIR)/lib/libcmd/$(RTE_TARGET)/include
LDLIBS += -L$(LB_DIR)/lib/libcmd/$(RTE_TARGET)/lib -lcmd

CFLAGS += -I$(LB_DIR)/lib/libcjson/$(RTE_TARGET)/include
LDLIBS += -L$(LB_DIR)/lib/libcjson/$(RTE_TARGET)/lib -lcjson

CFLAGS += -I$(LB_DIR)/lib/libcryptohash/$(RTE_TARGET)/include
LDLIBS += -L$(LB_DIR)/lib/libcryptohash/$(RTE_TARGET)/lib -lcryptohash

include $(RTE_SDK)/mk/rte.extapp.mk
