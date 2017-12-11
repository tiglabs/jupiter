ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
LIB = libconhash.a

# all source are stored in SRCS-y
SRCS-y := conhash.c conhash_inter.c conhash_util.c md5.c util_rbtree.c
SYMLINK-y-include += conhash.h configure.h

CFLAGS += $(WERROR_FLAGS) -O3

include $(RTE_SDK)/mk/rte.extlib.mk
