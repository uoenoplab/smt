.PHONY: all clean help

outputs = simple_client simple_server

objects = rtts.o homa_api.o smt_api.o log.o utils.o

CC ?= gcc
CFLAGS = -Wall -Wextra
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

$(outputs): %: %.c echo_simple.c echo_simple.h $(objects)
	$(CC) $^ $(CFLAGS_OUTPUT) $(LDFLAGS) -o $@

# rule for objects
%.o:
	$(CC) $< $(CFLAGS_OBJ) -c -o $@

rtts.o: ../util/rtts.c ../util/rtts.h utils.o

utils.o: ../util/utils.c ../util/utils.h log.o homa_api.o smt_api.o

log.o: CFLAGS_OBJ += -DLOG_USE_COLOR
log.o: ../util/log_c/log.c ../util/log_c/log.h

homa_api.o: CFLAGS_OBJ += -Wno-missing-field-initializers
homa_api.o: ../../module/homa_api.c ../../module/homa.h

smt_api.o: ../../module/smt_api.c ../../module/smt.h

help:
	@echo "  make TARGET [OPTIONS]"
	@echo "  TARGET"
	@echo "    all: Default target, builds simple_client and simple_server."
	@echo "    help"
	@echo "    clean"
	@echo "  [OPTIONS]"
	@echo "    CC=<compiler> - Compiler to use (default gcc, use CC=clang for Clang)."
	@echo "    DEBUG=1 - Add debug symbols and disable optimizations."
	@echo "    MSAN=1 - Enable MemorySanitizer (Clang only)."
	@echo "  Examples:"
	@echo "    make"
	@echo "    make DEBUG=1"
	@echo "    make DEBUG=1 CC=clang MSAN=1"

clean:
	rm -f $(objects) $(outputs)
