# Copyright (c) 2017. TIG developer.

ifdef V
Q =
else
Q = @
endif

ifeq ($(machine),)
machine = native
endif

RTE_SDK = $(CURDIR)/dpdk-17.11
export RTE_SDK

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-$(machine)-linuxapp-gcc
export RTE_TARGET

ifeq ($(bindir),)
bindir = /usr/local/jupiter/bin
endif

ifeq ($(tooldir),)
tooldir = /usr/local/jupiter/tool
endif

ifeq ($(kmoddir),)
kmoddir = /usr/local/jupiter/kmod
endif

ifeq ($(confdir),)
confdir = /usr/local/jupiter
endif

VERSION ?= 0.1

.PHONY: all
all: dpdk jupiter

.PHONY: dpdk
dpdk:
	$(Q)cd $(RTE_SDK) && $(MAKE) O=$(RTE_TARGET) T=$(RTE_TARGET) config
	$(Q)cd $(RTE_SDK) && sed -ri 's,(RTE_MACHINE=).*,\1$(machine),' $(RTE_TARGET)/.config
	$(Q)cd $(RTE_SDK) && sed -ri 's,(RTE_APP_TEST=).*,\1n,'         $(RTE_TARGET)/.config
	$(Q)cd $(RTE_SDK) && sed -ri 's,(RTE_LIBRTE_PMD_PCAP=).*,\1y,'  $(RTE_TARGET)/.config
	$(Q)cd $(RTE_SDK) && sed -ri 's,(RTE_KNI_KMOD_ETHTOOL=).*,\1n,' $(RTE_TARGET)/.config
	$(Q)cd $(RTE_SDK) && $(MAKE) O=$(RTE_TARGET)

.PHONY: jupiter
jupiter:
	$(Q)cd lib && $(MAKE) O=$(RTE_TARGET)
	$(Q)cd cmd && $(MAKE) O=$(RTE_TARGET)
	$(Q)cd core && $(MAKE) O=$(RTE_TARGET)

.PHONY: install
install:
	@echo ================== Installing $(DESTDIR)/
	$(Q)test -d $(DESTDIR)/$(bindir) || mkdir -p $(DESTDIR)/$(bindir)
	$(Q)cp -a cmd/$(RTE_TARGET)/jupiter-ctl $(DESTDIR)/$(bindir)
	$(Q)cp -a core/$(RTE_TARGET)/jupiter-service $(DESTDIR)/$(bindir)
	$(Q)cp -a $(RTE_SDK)/$(RTE_TARGET)/app/dpdk-pdump $(DESTDIR)/$(bindir)/jupiter-pdump
	
	$(Q)test -d $(DESTDIR)/$(tooldir) || mkdir -p $(DESTDIR)/$(tooldir)
	$(Q)cp -a $(RTE_SDK)/usertools/cpu_layout.py $(DESTDIR)/$(tooldir)/cpu_layout.py
	$(Q)cp -a $(RTE_SDK)/usertools/dpdk-devbind.py $(DESTDIR)/$(tooldir)/dpdk-devbind.py
	
	$(Q)test -d $(DESTDIR)/$(kmoddir) || mkdir -p $(DESTDIR)/$(kmoddir)
	$(Q)cp -a $(RTE_SDK)/$(RTE_TARGET)/kmod/igb_uio.ko $(DESTDIR)/$(kmoddir)/igb_uio.ko
	$(Q)cp -a $(RTE_SDK)/$(RTE_TARGET)/kmod/rte_kni.ko $(DESTDIR)/$(kmoddir)/rte_kni.ko

	$(Q)test -d $(DESTDIR)/$(confdir) || mkdir -p $(DESTDIR)/$(confdir)
	$(Q)cp -a jupiter.cfg $(DESTDIR)/$(confdir)
	@echo ================== Installation in $(DESTDIR)/ complete

.PHONY: uninstall
uninstall:
	@echo ================== Uninstalling $(DESTDIR)/
	$(Q)$(if test -d $(DESTDIR)/$(bindir)/jupiter-ctl, rm -rf $(DESTDIR)/$(bindir)/jupiter-ctl,)
	$(Q)$(if test -d $(DESTDIR)/$(bindir)/jupiter-service, rm -rf $(DESTDIR)/$(bindir)/jupiter-service,)
	$(Q)$(if test -d $(DESTDIR)/$(bindir)/jupiter-pdump, rm -rf $(DESTDIR)/$(bindir)/jupiter-pdump,)
	$(Q)$(if test -d $(DESTDIR)/$(tooldir)/cpu_layout.py, rm -rf $(DESTDIR)/$(tooldir)/cpu_layout.py,)
	$(Q)$(if test -d $(DESTDIR)/$(tooldir)/dpdk-devbind.py, rm -rf $(DESTDIR)/$(tooldir)/dpdk-devbind.py,)
	$(Q)$(if test -d $(DESTDIR)/$(kmoddir)/igb_uio.ko, rm -rf $(DESTDIR)/$(kmoddir)/igb_uio.ko,)
	$(Q)$(if test -d $(DESTDIR)/$(kmoddir)/rte_kni.ko, rm -rf $(DESTDIR)/$(kmoddir)/rte_kni.ko,)
	$(Q)$(if test -d $(DESTDIR)/$(confdir)/jupiter.cfg, rm -rf $(DESTDIR)/$(confdir)/jupiter.cfg,)
	@echo ================== Uninstallation in $(DESTDIR)/ complete

.PHONY: rpm-pkg
rpm-pkg:
	$(Q)$(if test -d rpmbuild, rm -rf rpmbuild,)
	$(Q)$(if test -e jupiter-$(VERSION).tar.xz, rm -rf jupiter-$(VERSION).tar.xz,)
	$(Q)tar -cf jupiter-$(VERSION).tar.xz --xform 's#^#jupiter-$(VERSION)/#' *
	$(Q)mkdir -p rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS}
	$(Q)mv jupiter-$(VERSION).tar.xz rpmbuild/SOURCES/jupiter-$(VERSION).tar.xz
	$(Q)cp rpm.spec rpmbuild/SPECS
	$(Q)rpmbuild -bb \
		--define "_topdir $(PWD)/rpmbuild" \
		--define "_version $(VERSION)" \
		--define "_machine $(machine)" \
		rpmbuild/SPECS/rpm.spec
	

.PHONY: clean
clean:
	$(Q)cd $(RTE_SDK) && $(MAKE) O=$(RTE_TARGET) clean
	$(Q)cd lib && $(MAKE) O=$(RTE_TARGET) clean
	$(Q)cd cmd && $(MAKE) O=$(RTE_TARGET) clean
	$(Q)cd core && $(MAKE) O=$(RTE_TARGET) clean
