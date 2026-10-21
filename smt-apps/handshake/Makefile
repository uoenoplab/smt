CFLAGS = -std=gnu11 -Wall -Wextra -O2 -I../..
GO ?= go

all: smt_handshake

# The same program with Go's crypto/tls (needs a Go toolchain).
go: smt_handshake_go

smt_handshake_go: go/main.go go/go.mod
	cd go && CGO_ENABLED=0 $(GO) build -o ../smt_handshake_go .

smt_handshake: smt_handshake.c ../../homa.h ../../smt_uapi.h
	$(CC) $(CFLAGS) $< -o $@ -lssl -lcrypto -lpthread

# A self-signed certificate for the server, named smt-server; give the
# client cert.pem.
cert:
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout key.pem -out cert.pem -days 365 -subj /CN=smt-server \
		-addext subjectAltName=DNS:smt-server

clean:
	rm -f smt_handshake smt_handshake_go

.PHONY: all go cert clean
