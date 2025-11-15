.PHONY: all tcpls homa_csum help clean

C_END = \033[0m
C_GREENBOLD = \033[1;32m
C_REDBOLD = \033[1;31m

outputs = echo_client echo_server

objects = rtts.o homa_api.o smt_api.o log.o utils.o

CC ?= gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpthread -lm
CFLAGS_OBJ = $(CFLAGS) -Wno-unused-function -Wno-unused-variable
CFLAGS_OUTPUT = $(CFLAGS)
CFLAGS_OUTPUT_CLIENT ?=
CFLAGS_OUTPUT_SERVER ?=

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

tcpls: CFLAGS_OUTPUT += -DBUILD_TCPLS
tcpls: CFLAGS_OUTPUT += -I tcpls/include -L tcpls -lpicotls-core -lpicotls-minicrypto -lpicotls-fusion -lpicotls-openssl -lssl -lcrypto
tcpls: all tcpls/tcpls.h

homa_csum: CFLAGS += -DBUILD_HOMA_CSUM
homa_csum: all

echo_client: echo_client.c echo.c echo.h $(objects)
	$(eval CFLAGS_OUTPUT_CLIENT += -DMAKE_EPOLL)
	@echo "$(C_GREENBOLD)client: epoll$(C_END)"
	$(CC) $^ $(CFLAGS_OUTPUT) $(CFLAGS_OUTPUT_CLIENT) $(LDFLAGS) -o $@

echo_server: echo_server.c echo.c echo.h $(objects)
	$(eval CFLAGS_OUTPUT_SERVER += -DMAKE_EPOLL)
	@echo "$(C_GREENBOLD)server: tcp_epoll_homa_onesock$(C_END)"
	$(CC) $^ $(CFLAGS_OUTPUT) $(CFLAGS_OUTPUT_SERVER) $(LDFLAGS) -o $@

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
	@echo "    all: Default target, compiles main outputs (echo_client and echo_server)."
	@echo "    tcpls: Builds with TCPLS."
	@echo "    homa_csum: Builds with HOMA userspace checksum."
	@echo "    help"
	@echo "    clean"
	@echo "  [OPTIONS]"
	@echo "    CC=<compiler> - Specifies the compiler to use. Default is gcc. Use CC=clang for Clang compiler."
	@echo "    DEBUG=1 - Compiles the code with debugging symbols and disables optimizations."
	@echo "    MSAN=1 - Enables the Memory Sanitizer to detect memory errors. Only supported when CC=clang."
	@echo "  Examples:"
	@echo "    make"
	@echo "    make DEBUG=1"
	@echo "    make DEBUG=1 CC=clang MSAN=1"

clean:
	rm -f $(objects) $(outputs)
