#!/usr/bin/env bash
# bench_sizes.sh - Sweep payload sizes across protocols.
# Usage: ./bench_sizes.sh [duration_secs] [csv_path]
set -euxo pipefail

REPO=/root/SMT-NG
DUR=${1:-8}
CSV=${2:-bench_results.csv}
SIZES=(64 128 256 512 1024 2048 4096 8192 16384 32768 65536 100000 320000 500000 640000)

declare -A PROTO=([tcp]=tcp [ktls-sw]=tcp_ktls [homa]=homa [smt-sw]=smt [smt-nocrypto]=smt [smt-hw]=smt)

# Map a (sweep) mode to the config_unloaded -m argument. The nocrypto
# build short-circuits both SW and HW encrypt paths in homa_outgoing.c,
# so a single 'smt-nocrypto' run is enough — no separate sw/hw variants.
config_mode_for() {
  case "$1" in
    smt-sw|smt-nocrypto)  echo "smt-sw" ;;
    smt-hw)               echo "smt-hw" ;;
    *)                    echo "$1" ;;
  esac
}

echo "mode,size,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us" > "$CSV"

cleanup_apps() {
  for h in n08 n09; do
    ssh "$h" 'pkill -9 -x simple_server 2>/dev/null; pkill -9 -x simple_client 2>/dev/null; true'
  done
  sleep 1
}

run_sweep() {
  local mode=$1 proto=${PROTO[$1]}
  local cmode
  cmode=$(config_mode_for "$mode")
  cleanup_apps
  ssh n08 "$REPO/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.1/24 -m $cmode" >&2
  ssh n09 "$REPO/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.2/24 -m $cmode" >&2
  for size in "${SIZES[@]}"; do
    echo "=== $mode size=$size ===" >&2
    ssh n08 "pkill -x simple_server 2>/dev/null; true"
    ssh -f n08 "cd $REPO/smt-apps/unloaded && ./simple_server --proto $proto -p 2000 -l $size >/dev/null 2>&1 </dev/null"
    sleep 1
    out=$(ssh n09 "cd $REPO/smt-apps/unloaded && timeout -s INT $DUR ./simple_client --proto $proto -a 192.168.12.1 -p 2000 -l $size 2>&1" || true)
    ssh n08 "pkill -x simple_server 2>/dev/null; true"
    printf '%s\n' "$out" >&2

    json=$(awk '/--- RESULT ---/{f=!f; next} f' <<<"$out" | sed 's/-\{0,1\}nan/null/g')
    jq -r --arg mode "$mode" --arg size "$size" '
      [$mode, $size, .total_rpcs, .kops_per_second,
       .tx_throughput_mbps, .rx_throughput_mbps,
       .average_rtt_us, .p50_median_rtt_us, .p95_rtt_us, .p99_rtt_us]
      | map(tostring) | join(",")' <<<"$json" >> "$CSV"
    echo >&2
  done
}

rebuild_module() {
  local target=$1 cflags=$2
  ssh n08 "cd $REPO && make clean && make $target SMT_CFLAGS='$cflags' -j\$(nproc)" >&2
}

echo "=== Rebuilding SW-only SMT ===" >&2
rebuild_module "all" ""

for mode in tcp ktls-sw homa smt-sw; do
  run_sweep "$mode"
done

echo "=== Rebuilding with CONFIG_SMT_NOCRYPTO ===" >&2
# CONFIG_SMT_NOCRYPTO bypasses both SW and HW encrypt paths, so a single
# 'smt-nocrypto' sweep stands in for both flavors.
rebuild_module "all" "-DCONFIG_SMT_NOCRYPTO"
run_sweep "smt-nocrypto"

echo "=== Rebuilding HW-enabled SMT ===" >&2
rebuild_module "hw" ""
run_sweep "smt-hw"

echo >&2
echo "=== CSV ($CSV) ===" >&2
cat "$CSV" >&2
