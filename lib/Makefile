/* Copyright (c) 2017. TIG developer. */

ifdef V
Q =
else
Q = @
endif

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

.PHONY: all
all:
	$(Q)cd libcmd && $(MAKE) O=$(RTE_TARGET)
	$(Q)cd libconhash && $(MAKE) O=$(RTE_TARGET)

.PHONY: clean
clean:
	$(Q)cd libcmd && $(MAKE) O=$(RTE_TARGET) clean
	$(Q)cd libconhash && $(MAKE) O=$(RTE_TARGET) clean