# SMT — FreeBSD prototype

This repo contains an implementation of the SMT transport protocol as a FreeBSD kernel module.

Related talk at BSDCan 2026: [FreeBSD Implementation of the SMT transport protocol](https://www.bsdcan.org/2026/timetable/timetable-FreeBSD-Implementation-of.html).

## Build

The module reuses FreeBSD's in-kernel TLS (kTLS) for encryption. A stock kernel does not
expose the kTLS internals it needs, so building the module requires patching the kernel
first: check out the FreeBSD source at base commit `<TBD>`, apply the patch in `patches/`,
and rebuild and install the kernel.

To build:

```sh
make
```

Load the module:

```sh
sudo kldload ./sdtp.ko
```

Unload it with:

```sh
sudo kldunload sdtp
```

## Benchmark

`bench/unloaded/` builds `simple_client` / `simple_server`, a single-RPC-in-flight latency
test speaking `--proto homa|sdtp|smt`. Measured numbers:

| Payload size (bytes) | Avg RTT latency (us) |
| --- | --- |
| 64 | 25.84 |
| 128 | 25.86 |
| 256 | 26.28 |
| 512 | 27.12 |
| 1024 | 28.70 |
| 2048 | 37.91 |
| 4096 | 49.41 |
| 8192 | 77.39 |

## Status

Early prototype. Future work:

- Timer retransmission
- Grant scheduling
- IPv6
- Hardware TLS offload
