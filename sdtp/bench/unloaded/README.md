# SDTP unloaded benchmark

It measures unloaded latency with one RPC in flight. Build on FreeBSD:

```sh
make
```

Run a server:

```sh
./simple_server --proto homa -p 2000 -l 64
```

Run 100,000 measured RTTs:

```sh
./simple_client --proto homa -a 192.0.2.2 -p 2000 -l 64 -n 100000
```
