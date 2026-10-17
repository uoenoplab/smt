#!/usr/bin/env bash
# Reload the mlx5 NIC driver for the upcoming bench mode.
#
#   reload_mlx5.sh smt-hw     -> load the SMT-patched mlx5 (HW TLS-offload).
#                                SMT's tls_dev_add uses a patched-driver hack
#                                format; the mainline driver returns -EOPNOTSUPP
#                                and every smt-hw cell goes NA.
#   reload_mlx5.sh mainline   -> load the vendored / in-tree mlx5 via modprobe.
#
# Called once per mode by config_{loaded,unloaded,loaded_oneip}. A reboot loads
# mainline, so smt-hw must reload the patched .ko before use.
#
# The patched .ko is built once by smt-mlx5e/install.sh; it lives under the
# install marker dir mlx5-smt/core/. Override discovery with $PATCHED_MLX5.
set -e

variant="${1:-}"

rmmod mlx5_ib 2>/dev/null || true
rmmod mlx5_core 2>/dev/null || true

case "$variant" in
  smt-hw)
    # build/ is a symlink to the kernel headers tree, so find must follow it (-L).
    : "${PATCHED_MLX5:=$(find -L "/lib/modules/$(uname -r)/build/drivers/net/ethernet/mellanox" -path '*/mlx5-smt/core/mlx5_core.ko' 2>/dev/null | head -1)}"
    if [[ -z "$PATCHED_MLX5" || ! -f "$PATCHED_MLX5" ]]; then
      echo "[!] patched mlx5 (mlx5-smt/core/mlx5_core.ko) not found — run smt-mlx5e/install.sh on this node, or set \$PATCHED_MLX5" >&2
      exit 1
    fi
    echo "[+] Loading SMT-patched mlx5: $PATCHED_MLX5"
    insmod "$PATCHED_MLX5"
    ;;
  mainline)
    echo "[+] Loading mainline mlx5 via modprobe"
    modprobe mlx5_core
    ;;
  *)
    echo "Usage: $0 <mainline|smt-hw>" >&2
    exit 1
    ;;
esac

modprobe mlx5_ib 2>/dev/null || true
echo "[+] Waiting for mlx5 to settle"
sleep 10
