# SDTP

This repo contains an implementation of the SMT transport protocol as a FreeBSD kernel module.
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
