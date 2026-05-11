#!/usr/bin/env bash
set -e

KERNEL_VER="$(uname -r)"
MOD_PATH="/lib/modules/$KERNEL_VER/build/drivers/net/ethernet/mellanox/mlx5-smt/core/mlx5_core.ko"

if [[ ! -f "$MOD_PATH" ]]; then
  echo "[!] $MOD_PATH not found. Run install.sh first." >&2
  exit 1
fi

echo "[+] Reloading mlx5 modules from $MOD_PATH"
sudo rmmod mlx5_ib 2>/dev/null || true
sudo rmmod mlx5_core
sudo insmod "$MOD_PATH"
sudo modprobe mlx5_ib 2>/dev/null || true
echo "[+] Done. NIC link may have bounced."
