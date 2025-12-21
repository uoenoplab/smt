.PHONY: all clean

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -I..
LDFLAGS ?=

all:
	@echo "No aggregate build. Run 'make smt_setkey'." >&2
	@false

smt_setkey_SRCS = smt_setkey.c ../smt_uapi.c
smt_setkey_DEPS = ../homa.h ../smt_uapi.h

smt_setkey: $(smt_setkey_SRCS) $(smt_setkey_DEPS)
	$(CC) $(CFLAGS) -o $@ $(smt_setkey_SRCS) $(LDFLAGS)

clean:
	rm -f smt_setkey
