#!/usr/bin/env bash
set -e

REQUIRED_KERNEL_PREFIX="6.17"

REPO_PATH="$(realpath "$(dirname "$0")")"
KERNEL_VER="$(uname -r)"
KERNEL_SRC="/lib/modules/$KERNEL_VER/build"
TARGET_DIR="$KERNEL_SRC/drivers/net/ethernet/mellanox/mlx5-smt/core"

if [[ "$KERNEL_VER" != ${REQUIRED_KERNEL_PREFIX}* ]]; then
  echo "[!] This tree targets kernel ${REQUIRED_KERNEL_PREFIX}.*. Running kernel: $KERNEL_VER" >&2
  exit 1
fi

if [[ "$REPO_PATH" != "$TARGET_DIR" ]]; then
  if [[ -d "$TARGET_DIR" ]]; then
    read -p "[!] Target exists: $TARGET_DIR. Remove and reinstall? [y/N] " yn
    case "$yn" in
      [yY]*) sudo rm -rf "$TARGET_DIR" ;;
      *) echo "[!] Aborted"; exit 1 ;;
    esac
  fi
  echo "[+] Staging source -> $TARGET_DIR"
  sudo mkdir -p "$TARGET_DIR"
  sudo cp -ar "$REPO_PATH/." "$TARGET_DIR/"
fi

echo "[+] Building mlx5_core.ko"
cd "$TARGET_DIR"
sudo make -j"$(getconf _NPROCESSORS_ONLN)" -C "$KERNEL_SRC" M="$TARGET_DIR"

echo "[+] Built: $TARGET_DIR/mlx5_core.ko"
