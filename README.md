# mlx5e driver patch for SMT-NG TLS offload

> [!CAUTION]
> We rebase the SMT-NG branches, this one included, often and force-push them.
> Be prepared to get reset.

This branch is the `mlx5_core` driver of Linux 6.17 (`drivers/net/ethernet/mellanox/mlx5/core`)
with the changes that let SMT offload TX TLS records of Homa messages to the NIC. Use it with the
[`smt-ng-tls-offload`](https://github.com/uoenoplab/smt/tree/smt-ng-tls-offload) branch. The
software-only [`smt-ng`](https://github.com/uoenoplab/smt/tree/smt-ng) branch does not need it.

```
./install.sh   # copy to /lib/modules/$(uname -r)/build/drivers/net/ethernet/mellanox/mlx5-smt/core and build mlx5_core.ko
./reload.sh    # replace the loaded mlx5_core with the patched one (the NIC link bounces)
```
