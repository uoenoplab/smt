# SMT (secure-message-transport)

Modern datacenter networks increasingly rely on high-bandwidth links and message-oriented transports such as Homa to support RPC-style workloads with low latency and high fan-out. At the same time, operators have widely deployed TLS over TCP to protect tenant traffic from eavesdropping and tampering in the network infrastructure.

However, simply stacking TLS on top of a message-based transport breaks key properties: TLS assumes an in-order bytestream and does not map cleanly onto unordered messages, and existing TLS offload engines in commodity NICs are tightly integrated with TCP.

**SMT (Secure Message Transport)** is a transport-level encryption architecture for message-based datacenter transports (e.g., Homa) that:

1. provides TLS-equivalent security (confidentiality, integrity, replay protection) for message trasnport;
2. preserves Homa’s socket-level message abstraction, host-stack parallelism and data center congetsion control;
3. remains compatible with existing commodity TLS/TCP hardware offloads (e.g., NVIDIA ConnectX-6/7 kTLS AO);

Our [S&P'26 paper](smt-oakland26.pdf) “Designing Transport-Level Encryption for Datacenter Networks” describes the design and evaluation of SMT in detail.

## Directory Overview

This repository contains the SMT kernel implementation and the user-space tools used for evaluation. The list below identifies each major subdirectory and its role.

- `module/`: SMT kernel module;
- `mlx5-smt-patch/`: Nvidia/Mellanox NIC driver patch for SMT TLS offload;
- `bench/unloaded/`: single-thread, single-socket SMT/Homa/TCPkTLS/TCP client/server;
- `bench/loaded/`: multi-sockets, multi-threads SMT/Homa/TCPkTLS/TCP client/server;
- `bench/util/`: configuration scripts, common header files;

## Environment preparation

The instructions below provision a minimal environment for building and running SMT, which currently targets the 6.2 kernel series.

1. Prepare an Ubuntu 22.04 (Jammy)
1. Refresh package metadata and install build/debug tools
   ```
   sudo apt-get update
   # build tools
   sudo apt-get install -y git build-essential bison flex ccache
   # kernel build deps
   sudo apt-get install -y libncurses5-dev libssl-dev libelf-dev dwarves bc
   # system/libs
   sudo apt-get install -y uuid-dev gettext libpopt-dev liburing-dev
   ```
1. Install the 6.2 kernel and headers
   ```
   sudo apt-get install -y \
     linux-image-unsigned-6.2.0-39-generic \
     linux-modules-6.2.0-39-generic \
     linux-modules-extra-6.2.0-39-generic \
     linux-headers-6.2.0-39-generic \
     linux-tools-6.2.0-39-generic linux-tools-common
   ```
1. Reboot into the new kernel and confirm
   ```
   uname -r  # expect 6.2.0-39-generic
   ```

## Building and running SMT

SMT is implemented as a kernel module that extends Homa/Linux. To run SMT minimally, we will load the SMT kernel module and then use the demo client/server in `bench/unloaded/` to test SMT; on capable NICs, we can additionally enable crypto offload with driver patch.

### Build and load the SMT kernel module

On each host that will run SMT, build the kernel module and insert it into the running kernel

```
cd module
make
sudo insmod smt.ko
```

### Run minimal client/server

Use the lightweight echo programs in `bench/unloaded/` to check that SMT works end to end.

1. Build the unloaded server and client (from repo root)
   ```
   cd bench/unloaded
   make
   ```
1. Run server to listen at 0.0.0.0:2000 and ready to receive message with 1024B size with SMT then reply echo, more details are on `-h`
   ```
   ./simple_server --proto smt --listen-port 2000 --payload-size 1024
   ```
1. Run client to send SMT message with size 1024B then receive echo, run Ctrl-C to terminate and print metrics, more details are on `-h`
   ```
   ./simple_client --proto smt --server-address <server_ip> --server-port 2000 --payload-size 1024
   ```
   You can also use `timeout` to limit the run duration, for example:
   ```
   timeout -s SIGINT 8s ./simple_client ...
   ```

### TLS offloading with mlx5

On systems with supported NVIDIA/Mellanox ConnectX-6/7 Crypto NICs, you can apply the NIC driver patch which enable hardware TLS offload for SMT.

1. Install kernel source:
   ```
   sudo apt-get install -y linux-source-6.2.0
   ```
1. Unpack and prepare for external module builds:
   ```
   cd /usr/src/linux-source-6.2.0
   tar xvf linux-source-6.2.0.tar.bz2

   cd /usr/src/linux-source-6.2.0/linux-source-6.2.0
   cp /boot/config-$(uname -r) .config
   cp /lib/modules/$(uname -r)/build/Module.symvers .
   make olddefconfig
   make prepare modules_prepare
   ```
1. Apply the SMT TLS offload patch and build the mlx5 driver (from repo root):
   ```
   cd mlx5-smt-patch
   ./install.sh 0001-net-mlx5e-generic-TLS-offload-support-for-TX-for-SMT.patch /usr/src/linux-source-6.2.0/linux-source-6.2.0
   ```
1. Reload the patched driver (from repo root):
   ```
   cd mlx5-smt-patch
   ./reload.sh /usr/src/linux-source-6.2.0/linux-source-6.2.0
   ```
1. Enable TLS offloading:
   - Enable NIC TLS TX offload:
      ```
      sudo ethtool -K <IFNAME> tls-hw-tx-offload on
      ```
   - Configure TLS offload interface name in SMT `sysctl`:
      ```
      sudo sysctl net.homa.smt_hardware_interface=<if>
      ```
      > **_Note: SMT haven't implementd auto-detect the TLS-offload interface and need set the `sysctl` to explicitly. This is temporary and will improve later._**

## Reproducing the S&P'26 paper evaluation(s)

Testbed used in the paper: two identical hosts (Intel Xeon Silver 4314 @ 2.40GHz, 128 GB RAM) with ConnectX-7 NICs cabled back-to-back, SMT/Hyper-Threading disabled, and booted with `intel_pstate=no_hwp` kernel arg.

### unloaded (Fig. 6)

Run the helper script ([`bench/util/config_unloaded`](bench/util/config_unloaded)) from repo root to configure the machines, the script will ask about necessary info to configure, then follow the instructions in the [Run minimal client/server](#run-minimal-clientserver) section above.

### loaded (Fig. 7)

For the loaded experiments we pinned softirq/IRQ to cores 0-3 and app threads to cores 4-15 for reproducibility; for SMT/Homa we added two IPs to the NIC to multi-home traffic and compensate for [lack of RSS](#rss), while TCP/kTLS used one IP.

1. Build loaded echo binaries:
   ```
   cd bench/loaded
   make
   ```
2. Run the helper script ([`bench/util/config_loaded`](bench/util/config_loaded)) from repo root
3. Run `echo_server` and `echo_client` binaries with commands below with varied the message sizes and message concurrencies in the placeholder:
   - SMT/Homa
     ```
     HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 ./echo_server --proto homals -p 2000-2011 -n 12 -t 12 -l <message-size>
     HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 timeout -s SIGINT 8s ./echo_client --proto homals -a <server_ip1> -b <server_ip2> -p 2000-2011 -n <num-concurrent-messages> -s 1 -m 0.0 -t 12 -l <message-size>
     ```
   - TCP/kTLS
     ```
     HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 ./echo_server --proto tcp -p 2000 -n 144 -t 12 -l <message-size>
     HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 timeout -s SIGINT 8s ./echo_client --proto tcp -a <server_ip> -p 2000 -n <num-concurrent-messages> -s 12 -m 0.0 -t 12 -l <message-size>
     ```

### Redis (Fig. 8)

This evaluation uses a ported version of **Redis** and a ported **YCSB-C** as client to measure SMT’s performance in a real-world key-value store scenario (Workload A).

#### 1. Redis Setup

Clone the ported [Redis repository](https://github.com/uoenoplab/smt-redis) and build it following its instructions. The Redis server listens on separate ports for each transport:

| Protocol | Port | Notes |
| --- | --- | --- |
| **Homa** | `5001` | Baseline message transport |
| **SMT** | `6001` | Secure message transport |
| **TCP** | `7001` | Standard kernel TCP |
| **OpenSSL-TLS** | `8001` | Userspace OpenSSL TLS |

#### 2. YCSB-C Setup

Clone the ported [YCSB-C repository](https://github.com/uoenoplab/smt-YCSB-C) and build it following its instructions.

#### 3. System Tuning

Before running the benchmark, run the system configuration script [`bench/util/config_redis`](bench/util/config_redis).

> **Note:** For **Userspace TLS**, use the "TCP" protocol / mode in the script.

#### 4. Running the Benchmark

The following example runs Workload A with a 64B payload.

To achieve a specific payload size, configure the field count and length. For 64B: `FIELD_COUNT (8) * FIELD_LENGTH (8 bytes) = 64 Bytes`

```bash
# Define payload size (8 fields * 8 bytes = 64B)
export FIELD_COUNT=8
export FIELD_LENGTH=8

# Run client with 32 threads pinned to cores 0-31
taskset -c 0-31 ./ycsbc -db redis -threads 32 \
  -P ./workloads/workloada.spec \
  -host <REDIS_SERVER_IP> \
  -port <REDIS_SERVER_PORT> \
  -slaves 0
```

There is a example script `run_redis_many_homa.sh` which can help run
multiple data points.

#### 5. kTLS (Kernel TLS)

- To test Kernel-level TLS, you must switch branch to `ktls` in both the Redis and YCSB repositories;
- Use the TCP port **7001** (the `ktls` branch repurposes this port for kTLS);
- Before run YCSB-C, use `ktls-sw` or `ktls-hw` mode in [`bench/util/config_redis`](bench/util/config_redis), to tune the system.

## Known limitations and future work

### RSS

Homa lacks RSS support, as [eTran](https://minlanyu.seas.harvard.edu/writeup/nsdi25-etran.pdf) paper also stated in D.2. For SMT/SDP loaded runs, use two IPs on the experiment NIC to multi-home flows; `bench/util/config_loaded` now accepts `-a <ip1>` and `-b <ip2>` to set them up. We are trying to find a better workload;

### TLS offload interface `sysctl`

SMT haven't implemented auto-detect which NIC to use for TLS offload, will be improved soon.

## Contributing to SMT

Feel free to experiment with SMT and send a PR, we are actively developing the next version of SMT now. We welcome contributions of all kinds, whether it's fixing bugs, improving documentation, or adding new features. Your input and feedback are invaluable to the growth and improvement of SMT. Join our community of developers and help shape **the future of secure message transport**!

## Contact and support

[Tianyi Gao](https://tianyigao.net) and [Michio Honda](https://micchie.net/)
