CARGO ?= cargo

# One binary under both names: it serves when its name ends in "server".
all: simple_server simple_client

simple_server: src/*.rs Cargo.toml Cargo.lock
	$(CARGO) build --release && cp target/release/simple_server $@

simple_client: simple_server
	ln -f $< $@

# ca.pem and both certificates, for --handshake (see handshake-c/).
cert:
	$(MAKE) -f ../handshake-c/Makefile cert

clean:
	rm -f simple_server simple_client

.PHONY: all cert clean
