#!/usr/bin/env bash
# Minimal loaded sweep: rebuild homa with N configs, run a (size, rate) matrix
# per config. No git checkout, no fancy. Run from a host that ssh's into
# both n08 (server) and n09 (client) — typically duck or galaday.
#
# Usage: loaded_sweep_min.sh <out.csv> [duration_secs]
# Edit CONFIGS / SIZES / RATES below.
set -euo pipefail

OUT=${1:-bench_results.csv}
DUR=${2:-8}
REPO=/root/SMT-NG
N1_IP=192.168.12.1
IFNAME=ens1f1np1

# label : SMT_CFLAGS : config_unloaded mode : proto
CONFIGS=(
  "hw:-DCONFIG_SMT_HW:smt-hw:smt"
  "sw::smt-sw:smt"
  "nc:-DCONFIG_SMT_NOCRYPTO:smt-sw:smt"
  "homa::homa:homa"
)
SIZES=(64 1024 8192 65536 640000)
RATES=(1 50 100 150)         # -m argument
SOCKETS=4
THREADS=4

echo "config,size,rate,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us" > "$OUT"

cleanup() {
  for h in n08 n09; do
    ssh "$h" 'pkill -9 -x loaded_server 2>/dev/null; pkill -9 -x loaded_client 2>/dev/null; true' || true
  done
  sleep 1
}

build_and_load() {
  local cflags=$1
  local target=all
  # make hw target adds KBUILD_EXTRA_SYMBOLS for the patched mlx5
  # symvers; required when CONFIG_SMT_HW is set so modpost can resolve
  # mlx5e_smt_tx_attach.
  if [[ "$cflags" == *"-DCONFIG_SMT_HW"* ]]; then
    target=hw
    cflags=${cflags//-DCONFIG_SMT_HW/}  # make hw already adds it
  fi
  echo "=== build target=$target SMT_CFLAGS='$cflags' ==="
  ssh n08 "cd $REPO && make clean >/dev/null && make $target SMT_CFLAGS='$cflags' 2>&1 | tail -3"
  # Reload homa.ko on both nodes (NFS-shared)
  for h in n08 n09; do
    ssh "$h" "sudo rmmod homa 2>/dev/null; sudo insmod $REPO/homa.ko"
  done
}

configure() {
  local mode=$1
  for h_ip in n08:$N1_IP n09:192.168.12.2; do
    local h=${h_ip%:*} ip=${h_ip#*:}
    ssh "$h" "$REPO/smt-apps/util/config_loaded_oneip -i $IFNAME -a $ip/24 -m $mode" >/dev/null
  done
}

run_cell() {
  local label=$1 size=$2 rate=$3 proto=$4
  cleanup
  ssh n08 "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_OFFSET=4 nohup $REPO/smt-apps/loaded/loaded_server \
    --proto $proto -p 2000-$((2000 + THREADS - 1)) -n 1 -t $THREADS -l $size \
    > /tmp/srv.log 2>&1 & disown"
  sleep 2
  out=$(ssh n09 "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_OFFSET=4 \
    timeout -s SIGINT ${DUR}s $REPO/smt-apps/loaded/loaded_client \
    --proto $proto -a $N1_IP -p 2000-$((2000 + THREADS - 1)) \
    -n $rate -s $SOCKETS -m 0 -t $THREADS -l $size 2>&1" || true)
  cleanup
  json=$(awk '/--- RESULT ---/{f=!f; next} f' <<<"$out" | sed 's/-\{0,1\}nan/null/g')
  row=$(jq -r --arg c "$label" --arg s "$size" --arg r "$rate" '
    [$c, $s, $r, .total_rpcs, .kops_per_second,
     .tx_throughput_mbps, .rx_throughput_mbps,
     .average_rtt_us, .p50_median_rtt_us, .p95_rtt_us, .p99_rtt_us]
    | map(tostring) | join(",")' <<<"$json" 2>/dev/null || echo "$label,$size,$rate,EMPTY")
  printf '%s\n' "$row" >> "$OUT"
  echo "  $label size=$size rate=$rate: $(awk -F, '{print "rpcs="$4" tput="$6" Mbps avg="$8"µs p99="$11"µs"}' <<<"$row")"
}

for cfg in "${CONFIGS[@]}"; do
  IFS=':' read -r label cflags mode proto <<< "$cfg"
  build_and_load "$cflags"
  configure "$mode"
  for size in "${SIZES[@]}"; do
    for rate in "${RATES[@]}"; do
      run_cell "$label" "$size" "$rate" "$proto"
    done
  done
done

echo "=== sweep complete; CSV: $OUT ==="
