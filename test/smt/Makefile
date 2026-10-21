# Makefile to run the unit tests of SMT. It builds Homa with CONFIG_SMT in
# this directory, with the mocks and helpers of the Homa unit tests in ..,
# and mock_smt.c in place of smt_sw.c (no AES-GCM).

LINUX_VERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(LINUX_VERSION)/build
CC ?= gcc
CXX ?= g++

all: test

KERN_INCLUDES := \
	    -I$(KDIR)/arch/x86/include \
	    -I$(KDIR)/arch/x86/include/generated \
	    -I$(KDIR)/include \
	    -I$(KDIR)/arch/x86/include/uapi \
	    -I$(KDIR)/arch/x86/include/generated/uapi \
	    -I$(KDIR)/include/uapi \
	    -I$(KDIR)/include/generated/uapi
CINCLUDES := -I. -I.. -I../.. $(KERN_INCLUDES) \
	    -include $(KDIR)/include/linux/kconfig.h

DEFS :=      -D__KERNEL__ \
	     -D__UNIT_TEST__ \
	     -D KBUILD_MODNAME='"homa"' \
	     -DCC_USING_FENTRY \
	     -DCONFIG_SMT

WARNS :=     -Wall -Wundef -Wno-trigraphs -Wno-sign-compare -Wuninitialized \
		-Wno-strict-aliasing -Wunused-but-set-variable -Werror
LINUX_CFLAGS := -std=gnu11 $(WARNS) -Wstrict-prototypes -MD -no-pie -g \
		$(CINCLUDES) $(DEFS) -fno-omit-frame-pointer -fms-extensions
CFLAGS :=    $(LINUX_CFLAGS) -fsanitize=address -include smt_test.h
CCFLAGS :=   -std=c++11 $(WARNS) -MD -g -I. -I.. -I../.. $(DEFS) \
		-fsanitize=address -fno-omit-frame-pointer

TEST_SRCS := unit_smt_utils.c

HOMA_SRCS := homa_devel.c \
	     homa_grant.c \
	     homa_hijack.c \
	     homa_incoming.c \
	     homa_interest.c \
	     homa_metrics.c \
	     homa_offload.c \
	     homa_outgoing.c \
	     homa_peer.c \
	     homa_plumbing.c \
	     homa_pool.c \
	     homa_qdisc.c \
	     homa_rpc.c \
	     homa_sock.c \
	     homa_timer.c \
	     homa_tx_pool.c \
	     homa_utils.c \
	     timetrace.c

SMT_SRCS :=  smt_plumbing.c \
	     smt_utils.c

LINUX_OBJS := $(shell ../linux_objs $(KDIR)/include/generated/uapi/linux/version.h)

OBJS := $(patsubst %.c,%.o,$(TEST_SRCS) $(HOMA_SRCS) $(SMT_SRCS)) \
	$(LINUX_OBJS) ccutils.o main.o mock.o mock_smt.o utils.o

.SUFFIXES:

%.o: ../../%.c
	$(CC) -c $(CFLAGS) $< -o $@
%.o: ../%.c
	$(CC) -c $(CFLAGS) $< -o $@
%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@
%.o: ../%.cc
	$(CXX) -c $(CCFLAGS) $< -o $@

# main.c defines __NO_KSELFTEST__ before its includes.
main.o: ../main.c
	$(CC) -c $(LINUX_CFLAGS) -fsanitize=address $< -o $@

# Without -O2 these fail with 'asm operand 2 probably does not match
# constraints'.
rhashtable%.o: ../rhashtable%.c
	$(CC) -c $(LINUX_CFLAGS) -O2 $< -o $@
xxhash%.o: ../xxhash%.c
	$(CC) -c $(LINUX_CFLAGS) -O2 $< -o $@

unit: $(OBJS)
	$(CXX) $(LINUX_CFLAGS) -fsanitize=address -Wl,--wrap=queue_work_on \
		$^ -o $@

test: unit
	./unit

clean:
	rm -f unit *.o *.d

-include $(wildcard *.d)

.PHONY: all test clean
