# Makefile to build Homa as a Linux module.

obj-m += smt.o
smt-y = homa_incoming.o \
			homa_offload.o \
			homa_outgoing.o \
			homa_peertab.o \
			homa_pool.o \
			homa_plumbing.o \
			homa_socktab.o \
			homa_timer.o \
			homa_utils.o \
			timetrace.o \
			smt_main.o \
			smt_sw.o \
			smt_device.o \
			smt_outgoing.o \
			smt_incoming.o

MY_CFLAGS += -g
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

debug: MY_CFLAGS += -DSMT_DEBUG
debug:
	make -C $(KDIR) M=$(PWD) MY_CFLAGS="$(MY_CFLAGS)" modules

info: MY_CFLAGS += -DSMT_INFO
info:
	make -C $(KDIR) M=$(PWD) MY_CFLAGS="$(MY_CFLAGS)" modules

install:
	make -C $(KDIR) M=$(PWD) modules_install

check:
	../homaLinux/scripts/kernel-doc -none *.c

clean:
	make -C $(KDIR) M=$(PWD) clean

# The following targets are useful for debugging Makefiles; they
# print the value of a make variable in one of several contexts.
print-%:
	@echo $* = $($*)

printBuild-%:
	make -C $(KDIR) M=$(PWD) $@

printClean-%:
	make -C $(KDIR) M=$(PWD) $@
