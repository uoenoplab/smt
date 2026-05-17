# Makefile to build Homa as a Linux module.

HOMA_OBJS := homa_devel.o \
	homa_incoming.o \
	homa_interest.o \
	homa_outgoing.o \
	homa_peer.o \
	homa_pool.o \
	homa_plumbing.o \
	homa_rpc.o \
	homa_sock.o \
	homa_timer.o \
	homa_utils.o \
	timetrace.o

SMT_OBJS := smt_plumbing.o \
	smt_incoming.o \
	smt_sw.o \
	smt_utils.o

# HW offload (mlx5 ktls) is opt-in: pass SMT_CFLAGS=-DCONFIG_SMT_HW.
ifneq ($(findstring -DCONFIG_SMT_HW,$(SMT_CFLAGS)),)
SMT_OBJS += smt_device.o
endif

ifneq ($(__STRIP__),)
MY_CFLAGS += -D__STRIP__
else
HOMA_OBJS += homa_grant.o \
	homa_hijack.o \
	homa_metrics.o \
	homa_offload.o \
	homa_pacer.o \
	homa_qdisc.o \
	homa_skb.o
endif

CHECK_SRCS := $(patsubst %.o,%.c,$(filter-out homa_devel.o timetrace.o, $(HOMA_OBJS)))
CHECK_SRCS += $(filter-out homa_receiver.h homa_devel.h, $(wildcard *.h))

ifneq ($(KERNEL_SRC),)
# alternatively to variable KDIR accept variable KERNEL_SRC as used in
# PetaLinux/Yocto for example
KDIR ?= $(KERNEL_SRC)
endif

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build

LINUX_SRC_DIR ?= ../net-next

ifneq ($(KERNELRELEASE),)

obj-m += homa.o
ifeq ($(NO_CONFIG_SMT),)
homa-y = $(HOMA_OBJS) $(SMT_OBJS)
override SMT_CFLAGS += -DCONFIG_SMT
else
homa-y = $(HOMA_OBJS)
endif

MY_CFLAGS += -g
ccflags-y += $(MY_CFLAGS) $(SMT_CFLAGS)

THREADS ?= $(shell nproc)

else

all:
	$(MAKE) -j$(THREADS) -C $(KDIR) M=$(shell pwd) modules

info:
	$(MAKE) -j$(THREADS) -C $(KDIR) M=$(shell pwd) SMT_CFLAGS="-DCONFIG_SMT_INFO $(SMT_CFLAGS)" modules

debug:
	$(MAKE) -j$(THREADS) -C $(KDIR) M=$(shell pwd) SMT_CFLAGS="-DCONFIG_SMT_DEBUG -fno-reorder-functions $(SMT_CFLAGS)" modules

hw:
	$(MAKE) -j$(THREADS) -C $(KDIR) M=$(shell pwd) SMT_CFLAGS="-DCONFIG_SMT_HW $(SMT_CFLAGS)" modules

hw-debug:
	$(MAKE) -j$(THREADS) -C $(KDIR) M=$(shell pwd) SMT_CFLAGS="-DCONFIG_SMT_HW -DCONFIG_SMT_DEBUG -fno-reorder-functions $(SMT_CFLAGS)" modules

install:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules_install

kdoc:
	$(LINUX_SRC_DIR)/scripts/kernel-doc -none $(CHECK_SRCS)

checkpatch:
	$(LINUX_SRC_DIR)/scripts/checkpatch.pl --file --strict --codespell $(CHECK_SRCS)

checkpatch-net-next:
	$(LINUX_SRC_DIR)/scripts/checkpatch.pl --file --strict --codespell $(HOMA_TARGET)/*.[ch]

# Copy stripped source files to a Linux source tree
HOMA_TARGET ?= $(LINUX_SRC_DIR)/net/homa
CP_HDRS := homa_impl.h \
	   homa_interest.h \
	   homa_peer.h \
	   homa_pool.h \
	   homa_rpc.h \
	   homa_sock.h \
	   homa_stub.h \
	   homa_wire.h \
	   murmurhash3.h
CP_SRCS := $(patsubst %.o,%.c,$(filter-out homa_devel.o homa_grant.o \
		homa_hijack.o homa_metrics.o homa_offload.o homa_pacer.o \
		homa_qdisc.o homa_skb.o timetrace.o, $(HOMA_OBJS)))
CP_EXTRAS := Kconfig \
	     Makefile
CP_TARGETS := $(patsubst %,$(HOMA_TARGET)/%,$(CP_HDRS) $(CP_SRCS) $(CP_EXTRAS))
net-next: $(HOMA_TARGET) $(CP_TARGETS) $(LINUX_SRC_DIR)/include/uapi/linux/homa.h
$(HOMA_TARGET):
	mkdir $(HOMA_TARGET)
$(HOMA_TARGET)/%: % util/strip.py
	util/strip.py $< > $@
$(HOMA_TARGET)/%.txt: %.txt
	cp $< $@
$(HOMA_TARGET)/Makefile: Makefile.upstream
	cp $< $@
$(HOMA_TARGET)/strip_decl.py: util/strip_decl.py
	cp $< $@
$(LINUX_SRC_DIR)/include/uapi/linux/homa.h: homa.h util/strip.py
	util/strip.py $< > $@

help:
	@echo "Homa/SMT Build Targets:"
	@echo "  make              - Build with default SMT config (SW crypto only)"
	@echo "  make info         - Build with SMT info logging"
	@echo "  make debug        - Build with SMT debug logging"
	@echo "  make hw           - Build with HW offload (mlx5 ktls) enabled"
	@echo "  make hw-debug     - Build with HW offload + debug logging"
	@echo ""
	@echo "SMT Config Options (pass via SMT_CFLAGS):"
	@echo "  CONFIG_SMT_HW             - Enable HW TX offload path (mlx5 ktls); requires patched mlx5_core"
	@echo "  CONFIG_SMT_NOCRYPTO       - Disable crypto (use 0xFF fillers for testing)"
	@echo "  CONFIG_HOMA_SMT_PROFILING - Enable SMT profiling/timetrace"
	@echo "  CONFIG_SMT_HEXDUMP        - Enable hexdump helpers (requires CONFIG_SMT_DEBUG, i.e. make debug)"
	@echo ""
	@echo "Examples:"
	@echo "  make SMT_CFLAGS=\"-DCONFIG_SMT_NOCRYPTO\""
	@echo "  make SMT_CFLAGS=\"-DCONFIG_HOMA_SMT_PROFILING\""
	@echo "  make debug SMT_CFLAGS=\"-DCONFIG_SMT_HEXDUMP\""
	@echo "  make hw SMT_CFLAGS=\"-DCONFIG_HOMA_SMT_PROFILING\""

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean

# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)

printBuild-%:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

printClean-%:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $@

endif
