#!/usr/bin/env bash
set -e

REQUIRED_KERNEL_PREFIX="6.2"

usage() {
  echo "Usage: $0 --modprobe | <kernel-src-dir>"
  exit 1
}

if [[ $# -lt 1 ]]; then
  usage
fi

if [[ "$1" == "--modprobe" ]]; then
  echo "[+] Reloading mlx5_core via modprobe"
  sudo rmmod mlx5_ib || true
  sudo rmmod mlx5_core || true
  sudo modprobe -v mlx5_core
  exit 0
fi

KERNEL_SRC="$1"

if [[ ! -d "$KERNEL_SRC" ]]; then
  echo "[!] Kernel source directory not found: $KERNEL_SRC"
  exit 1
fi

if [[ ! -f "$KERNEL_SRC/Makefile" ]]; then
  echo "[!] $KERNEL_SRC does not look like a kernel tree (Makefile not found)"
  exit 1
fi

if [[ ! -d "$KERNEL_SRC/include/linux" ]]; then
  echo "[!] $KERNEL_SRC does not look like a kernel tree (include/linux missing)"
  exit 1
fi

get_mk_var() {
  awk -v key="$1" '
    $1 == key && $2 == "=" {
      print $3
      exit
    }
  ' "$KERNEL_SRC/Makefile"
}

V=$(get_mk_var VERSION)
P=$(get_mk_var PATCHLEVEL)
S=$(get_mk_var SUBLEVEL)
E=$(get_mk_var EXTRAVERSION)

if [[ -z "$V" || -z "$P" || -z "$S" ]]; then
  echo "[!] Failed to parse VERSION/PATCHLEVEL/SUBLEVEL from $KERNEL_SRC/Makefile"
  exit 1
fi

KERNEL_VER="${V}.${P}.${S}${E}"

echo "[+] Detected kernel version from source: $KERNEL_VER"

if [[ "$KERNEL_VER" != ${REQUIRED_KERNEL_PREFIX}* ]]; then
  echo "[!] Kernel version mismatch. Required prefix: $REQUIRED_KERNEL_PREFIX, from source: $KERNEL_VER"
  exit 1
fi

MOD_PATH="$KERNEL_SRC/drivers/net/ethernet/mellanox/mlx5-smt/core/mlx5_core.ko"

if [ ! -f "$MOD_PATH" ]; then
  echo "[!] Module $MOD_PATH does not exist. Please run install.sh first."
  exit 1
fi

echo "[+] Reloading mlx5 modules..."
sudo rmmod mlx5_ib || true
sudo rmmod mlx5_core || true
sudo insmod "$MOD_PATH"

echo "[+] Module reloaded."
