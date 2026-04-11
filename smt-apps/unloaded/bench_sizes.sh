#!/usr/bin/env bash
# bench_sizes.sh - Sweep payload sizes across protocols.
# Usage: ./bench_sizes.sh [duration_secs] [csv_path]
set -euxo pipefail

REPO=/root/SMT-NG
KDIR=/usr/src/linux-headers-6.17.8-mainline-fab
DUR=${1:-8}
CSV=${2:-bench_results.csv}
SIZES=(64 256 1024 2048 4096)

declare -A PROTO=([tcp]=tcp [ktls-sw]=tcp_ktls [homa]=homa [smt-sw]=smt [smt-sw-nocrypto]=smt)

echo "mode,size,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us" > "$CSV"

run_sweep() {
  local mode=$1 proto=${PROTO[$1]}
  ssh n08 "$REPO/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.1/24 -k $KDIR -m ${mode%-nocrypto}" >&2
  ssh n09 "$REPO/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.2/24 -k $KDIR -m ${mode%-nocrypto}" >&2
  for size in "${SIZES[@]}"; do
    echo "=== $mode size=$size ===" >&2
    ssh n08 "pkill -x simple_server 2>/dev/null; true"
    ssh -f n08 "cd $REPO/smt-apps/unloaded && ./simple_server --proto $proto -p 2000 -l $size >/dev/null 2>&1 </dev/null"
    sleep 1
    out=$(ssh n09 "cd $REPO/smt-apps/unloaded && timeout -s INT $DUR ./simple_client --proto $proto -a 192.168.12.1 -p 2000 -l $size 2>&1" || true)
    ssh n08 "pkill -x simple_server 2>/dev/null; true"
    printf '%s\n' "$out" >&2

    json=$(sed -n '/--- RESULT ---/,/--- RESULT ---/{/--- RESULT ---/d; p}' <<<"$out" | sed 's/-\?nan/null/g')
    jq -r --arg mode "$mode" --arg size "$size" '
      [$mode, $size, .total_rpcs, .kops_per_second,
       .tx_throughput_mbps, .rx_throughput_mbps,
       .average_rtt_us, .p50_median_rtt_us, .p95_rtt_us, .p99_rtt_us]
      | map(tostring) | join(",")' <<<"$json" >> "$CSV"
    echo >&2
  done
}

rebuild_module() {
  local cflags=$1
  ssh n08 "cd $REPO && make clean && make SMT_CFLAGS='$cflags' -j\$(nproc)" >&2
}

echo "=== Rebuilding normal SMT ===" >&2
rebuild_module ""

for mode in tcp ktls-sw homa smt-sw; do
  run_sweep "$mode"
done

echo "=== Rebuilding with CONFIG_SMT_NOCRYPTO ===" >&2
rebuild_module "-DCONFIG_SMT_NOCRYPTO"
run_sweep "smt-sw-nocrypto"

echo >&2
echo "=== CSV ($CSV) ===" >&2
cat "$CSV" >&2
