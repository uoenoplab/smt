# SMT (secure-message-transport)

Modern datacenter networks increasingly rely on high-bandwidth links and
message-oriented transports such as Homa to support RPC-style workloads with
low latency and high fan-out. At the same time, operators have widely deployed
TLS over TCP to protect tenant traffic from eavesdropping and tampering in the
network infrastructure.

However, simply stacking TLS on top of a message-based transport breaks key
properties: TLS assumes an in-order bytestream and does not map cleanly onto
unordered messages, and existing TLS offload engines in commodity NICs are
tightly integrated with TCP.

**SMT (Secure Message Transport)** is a transport-level encryption
architecture for message-based datacenter transports (e.g., Homa) that:

1. provides TLS-equivalent security (confidentiality, integrity, replay
   protection) for message transport;
2. preserves Homa's socket-level message abstraction, host-stack parallelism
   and data center congestion control;
3. remains compatible with existing commodity TLS/TCP hardware offloads.

This repository is the **next-generation SMT implementation** built on the
upstream Homa module tree. The original Homa README is preserved at
[README-homa.md](README-homa.md).

The S&P'26 paper "Designing Transport-Level Encryption for Datacenter
Networks" describes the design and evaluation of SMT in detail.

## Directory overview

- `homa_*.c / *.h`: SMT kernel module (Homa + SMT record layer);
- `smt-apps/unloaded/`: single-thread, single-socket SMT/Homa/TCPkTLS/TCP
  client/server;
- `smt-apps/loaded/`: multi-socket, multi-threaded SMT/Homa/TCPkTLS/TCP
  client/server;
- `smt-apps/util/`: configuration scripts, common header files.

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

## Load the module

```
insmod homa.ko
```

For virtio, run `sudo sysctl net.homa.gso_force_software=1` to force GSO
instead of TSO.

## Unloaded microbenchmark (single-socket, single-thread)

Build:

```
cd smt-apps/unloaded
make
```

Produces `simple_server` and `simple_client` in `smt-apps/unloaded/`.

Run SMT with 64-byte payloads for 10000 round trips:

```
# server
./simple_server --proto smt -p 2000 -l 64

# client
./simple_client --proto smt -a <server-ip> -p 2000 -l 64 -n 10000
```

The client stops after `-n` RPCs if specified, otherwise runs until
interrupted with Ctrl-C (SIGINT); for a timed run, use `timeout`, e.g.
`timeout -s SIGINT 10 ./simple_client ...`.

Run `./simple_client --help` or `./simple_server --help` for the full option
list.

## Loaded microbenchmark (multi-socket, multi-thread)

Build:

```
cd smt-apps/loaded
make
```

Produces `loaded_server` and `loaded_client` in `smt-apps/loaded/`.

Before running, configure the host's NIC / CPU / sysctl with the helper
script (one-time per boot, requires root):

```
sudo smt-apps/util/config_loaded \
  -i <IFNAME> \
  -a <server_ip1>/<prefix> \
  -b <server_ip2>/<prefix> \
  -m smt-sw
```

SMT/Homa require two IPs on the experiment NIC to multi-home flows and work
around [Homa's lack of RSS](#rss); TCP/kTLS can use a single IP.

Run server and client (example: 12 ports, 12 threads, varied message size /
concurrency):

- SMT/Homa:
  ```
  HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 ./loaded_server --proto smt -p 2000-2011 -n 12 -t 12 -l <msg-size>
  HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 timeout -s SIGINT 8s ./loaded_client --proto smt -a <server_ip1> -b <server_ip2> -p 2000-2011 -n <concurrency> -s 1 -m 0.0 -t 12 -l <msg-size>
  ```
- TCP/kTLS:
  ```
  HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 ./loaded_server --proto tcp -p 2000 -n 144 -t 12 -l <msg-size>
  HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 timeout -s SIGINT 8s ./loaded_client --proto tcp -a <server_ip> -p 2000 -n <concurrency> -s 12 -m 0.0 -t 12 -l <msg-size>
  ```

## Known limitations

### RSS

Homa lacks RSS support (as also observed by the [eTran](https://minlanyu.seas.harvard.edu/writeup/nsdi25-etran.pdf)
paper, section D.2). For SMT/Homa loaded runs, use two IPs on the experiment
NIC to multi-home flows; `smt-apps/util/config_loaded` accepts `-a <ip1>` and
`-b <ip2>` to set them up.

## Contact

[Tianyi Gao](https://tianyigao.net), [Michio Honda](https://micchie.net/)
