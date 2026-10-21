.PHONY: all clean help

outputs = simple_client simple_server

objects = echo_simple.o rtts.o smt_uapi.o log.o utils.o

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2
LDFLAGS = -lpthread -lm
CFLAGS_OBJ = $(CFLAGS) -Wno-unused-function -Wno-unused-variable

# make DEBUG=1 for debugging symbols
ifeq ($(DEBUG), 1)
	CFLAGS += -g
endif

# make CC=clang MSAN=1 for Memory Sanitizer
ifeq ($(MSAN), 1)
	ifeq ($(CC), clang)
		CFLAGS += -fsanitize=memory -fsanitize-memory-track-origins
	else
$(error Memory Sanitizer is only supported with Clang)
	endif
endif

all: $(outputs)

$(outputs): %: %.c $(objects)
	$(CC) $< $(objects) $(CFLAGS_OUTPUT) $(LDFLAGS) -o $@

%.o:
	$(CC) $< $(CFLAGS_OBJ) -c -o $@

echo_simple.o: echo_simple.c echo_simple.h

rtts.o: ../util/rtts.c ../util/rtts.h utils.o

utils.o: ../util/utils.c ../util/utils.h log.o

smt_uapi.o: ../../smt_uapi.c ../../smt_uapi.h

log.o: CFLAGS_OBJ += -DLOG_USE_COLOR
log.o: ../util/log_c/log.c ../util/log_c/log.h

help:
	@echo "  make TARGET [OPTIONS]"
	@echo "  TARGET"
	@echo "    all: Default target, builds simple_client and simple_server."
	@echo "    help"
	@echo "    clean"
	@echo "  [OPTIONS]"
	@echo "    DEBUG=1 - Add debug symbols and disable optimizations."
	@echo "    MSAN=1 - Enable MemorySanitizer (Clang only)."
	@echo "  Examples:"
	@echo "    make"
	@echo "    make DEBUG=1"
	@echo "    make DEBUG=1 CC=clang MSAN=1"

clean:
	rm -f $(objects) $(outputs)
