# SMT

TLS-based secure messaging layer integrated into Homa data packets, with
software AES-GCM and mlx5 hardware-offloaded variants.

Built on top of [Homa](https://github.com/PlatformLab/HomaModule). The
upstream Homa project's README is preserved at [README-homa.md](README-homa.md).

## Prerequisites

Linux **6.17.8** (can download from
<https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.17.8.tar.xz>); kernel
headers expected at `/lib/modules/$(uname -r)/build` after compiling and
installing the kernel.

## Build the kernel module

From the repo root:

```
make
```

See `make help` for more details.

## Build the unloaded microbenchmark apps

```
cd smt-apps/unloaded
make
```

This produces two binaries in `smt-apps/unloaded/`: `simple_server` and
`simple_client`.

## Run

Run SMT with 64-byte payloads for 10000 round trips:

```
# server
./simple_server --proto smt -p 2000 -l 64

# client
./simple_client --proto smt -a <server-ip> -p 2000 -l 64 -n 10000
```

The client stops after `-n` RPCs if specified, otherwise runs until
interrupted with Ctrl-C (SIGINT); for a timed run, use `timeout`,
e.g. `timeout -s SIGINT 10 ./simple_client ...`.

Run `./simple_client --help` or `./simple_server --help` for the full
option list.
