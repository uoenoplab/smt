CFLAGS = -std=gnu11 -Wall -Wextra -O2 -I../..

all: smt_handshake

smt_handshake: smt_handshake.c ../../homa.h ../../smt_uapi.h
	$(CC) $(CFLAGS) $< -o $@ -lssl -lcrypto -lpthread

# A CA that both ends trust, and a certificate from it for each end; the
# server's is named smt-server.
CERT = -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365
LEAF = $(CERT) -CA ca.pem -CAkey ca-key.pem -addext basicConstraints=critical,CA:FALSE
cert:
	openssl req -x509 $(CERT) -keyout ca-key.pem -out ca.pem -subj /CN=smt-ca
	openssl req -x509 $(LEAF) -keyout server-key.pem -out server.pem -subj /CN=smt-server \
		-addext subjectAltName=DNS:smt-server -addext extendedKeyUsage=serverAuth
	openssl req -x509 $(LEAF) -keyout client-key.pem -out client.pem -subj /CN=smt-client \
		-addext extendedKeyUsage=clientAuth

clean:
	rm -f smt_handshake

.PHONY: all cert clean
