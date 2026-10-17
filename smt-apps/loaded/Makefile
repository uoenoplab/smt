.PHONY: all clean help

outputs = loaded_client loaded_server

objects = echo_loaded.o rtts.o smt_uapi.o log.o utils.o

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2
LDFLAGS = -lpthread -lm
CFLAGS_OBJ = $(CFLAGS) -Wno-unused-function -Wno-unused-variable

ifeq ($(DEBUG), 1)
	CFLAGS += -g
endif

ifeq ($(MSAN), 1)
	ifeq ($(CC), clang)
		CFLAGS += -fsanitize=memory -fsanitize-memory-track-origins
	else
$(error Memory Sanitizer is only supported with Clang)
	endif
endif

all: $(outputs)

$(outputs): %: %.c $(objects)
	$(CC) $< $(objects) $(CFLAGS) $(LDFLAGS) -o $@

%.o:
	$(CC) $< $(CFLAGS_OBJ) -c -o $@

echo_loaded.o: echo_loaded.c echo_loaded.h

rtts.o: ../util/rtts.c ../util/rtts.h utils.o

utils.o: ../util/utils.c ../util/utils.h log.o

smt_uapi.o: ../../smt_uapi.c ../../smt_uapi.h

log.o: CFLAGS_OBJ += -DLOG_USE_COLOR
log.o: ../util/log_c/log.c ../util/log_c/log.h

help:
	@echo "  make TARGET [OPTIONS]"
	@echo "  TARGET"
	@echo "    all: Default, builds loaded_client and loaded_server."
	@echo "    help"
	@echo "    clean"
	@echo "  OPTIONS"
	@echo "    DEBUG=1 - Add debug symbols, keep optimizations."
	@echo "    MSAN=1  - Enable MemorySanitizer (Clang only)."
	@echo "  Examples:"
	@echo "    make"
	@echo "    make DEBUG=1"

clean:
	rm -f $(objects) $(outputs)
