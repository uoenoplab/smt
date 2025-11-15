#!/usr/bin/env bash
set -e

REQUIRED_KERNEL_PREFIX="6.2"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <patch-file.patch> <kernel-src-dir>"
  exit 1
fi

PATCH_FILE="$1"
KERNEL_SRC="$2"

if [[ ! -f "$PATCH_FILE" ]]; then
  echo "[!] Patch file not found: $PATCH_FILE"
  exit 1
fi

PATCH_FILE="$(readlink -f -- "$PATCH_FILE")"
echo "[+] Using patch: $PATCH_FILE"

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

MLX5_CORE="$KERNEL_SRC/drivers/net/ethernet/mellanox/mlx5"
TARGET_DIR="$KERNEL_SRC/drivers/net/ethernet/mellanox/mlx5-smt"
BACKUP_DIR="$KERNEL_SRC/drivers/net/ethernet/mellanox/mlx5-backup"

echo "[+] Kernel:"
echo "    Version:    $KERNEL_VER"
echo "    Kernel src: $KERNEL_SRC"
echo "    MLX5 core:  $MLX5_CORE"
echo "    Target dir: $TARGET_DIR"

# --------------------------
# BACKUP ORIGINAL MLX5
# --------------------------
if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "[+] Creating backup of original mlx5 → $BACKUP_DIR"
  sudo cp -a "$MLX5_CORE" "$BACKUP_DIR"
else
  echo "[+] Backup already exists: $BACKUP_DIR"
fi

# --------------------------
# PREPARE WORK DIRECTORY
# --------------------------
if [[ -d "$TARGET_DIR" ]]; then
  echo "[!] Existing patched directory found: $TARGET_DIR"
  read -p "Remove it and reapply patch? [y/N] " YN
  case "$YN" in
    [yY]) sudo rm -rf "$TARGET_DIR";;
    *) echo "[!] Aborted"; exit 1;;
  esac
fi

echo "[+] Copying mlx5-backup → working directory..."
sudo mkdir -p "$TARGET_DIR"
sudo cp -a "$BACKUP_DIR/." "$TARGET_DIR/"

cd "$TARGET_DIR"

# --------------------------
# APPLY PATCH
# --------------------------
echo "[+] Applying patch..."

STRIP_LEVEL=6  # strip drivers/net/ethernet/mellanox/mlx5/core
if patch -p"$STRIP_LEVEL" --dry-run < "$PATCH_FILE" > /dev/null 2>&1; then
  echo "[+] Patch applies cleanly."
  sudo patch -p"$STRIP_LEVEL" < "$PATCH_FILE"
else
  echo "[!] Patch does NOT apply cleanly, showing diff:"
  patch -p"$STRIP_LEVEL" --dry-run < "$PATCH_FILE"
  exit 1
fi

echo "[+] Patch applied successfully."

# --------------------------
# BUILD
# --------------------------
echo "[+] Building mlx5-sdp module..."

sudo make -j"$(getconf _NPROCESSORS_ONLN)" -C "$KERNEL_SRC" M="$TARGET_DIR/core"

echo "[+] Build complete."

# --------------------------
# CLEANUP BACKUP
# --------------------------
echo "[+] Removing backup directory: $BACKUP_DIR"
sudo rm -rf "$BACKUP_DIR"

echo "[+] Done. Final patched module is in:"
echo "    $TARGET_DIR"
