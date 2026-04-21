#!/usr/bin/env bash
# bench_sweep.sh - Sweep payload x rpcs x proto for the loaded bench.
# Usage: ./bench_sweep.sh [duration_secs] [csv_path] [trials]
set -euxo pipefail

REPO=/root/SMT-NG
script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DUR=${1:-8}
CSV=${2:-$script_dir/bench_loaded.csv}
TRIALS=${3:-3}

mkdir -p "$(dirname "$CSV")"

IFNAME=ens1f1np1
N1_IP=192.168.12.1      # server on n08 (primary)
N1_IP_ALT=192.168.13.1  # server on n08 (secondary, smt multi-home)
N2_IP=192.168.12.2      # client on n09 (primary)
N2_IP_ALT=192.168.13.2  # client on n09 (secondary)

CLIENT_THREADS=12
SERVER_THREADS=12
SERVER_PORTS_HOMA="2000-2011"   # 12 ports, one per server thread
SERVER_PORTS_TCP="2000"

SIZES=(${SIZES:-64 1024 8192})
RPCS=(${RPCS:-1 25 50 75 100 125 150})

declare -A PROTO=([smt]=smt [tcp]=tcp)

echo "mode,size,rpcs,trial,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us" > "$CSV"

config_hosts() {
  local mode=$1
  if [[ "$mode" == "smt" ]]; then
    ssh n08 "$REPO/smt-apps/util/config_loaded -i $IFNAME -a $N1_IP/24 -b $N1_IP_ALT/24 -m smt-sw" >&2
    ssh n09 "$REPO/smt-apps/util/config_loaded -i $IFNAME -a $N2_IP/24 -b $N2_IP_ALT/24 -m smt-sw" >&2
  else
    ssh n08 "$REPO/smt-apps/util/config_loaded -i $IFNAME -a $N1_IP/24 -m tcp" >&2
    ssh n09 "$REPO/smt-apps/util/config_loaded -i $IFNAME -a $N2_IP/24 -m tcp" >&2
  fi
}

server_cmd() {
  local mode=$1 size=$2
  local ports nmax
  if [[ "$mode" == "smt" ]]; then
    ports=$SERVER_PORTS_HOMA
    nmax=1
  else
    ports=$SERVER_PORTS_TCP
    nmax=$((CLIENT_THREADS * CLIENT_THREADS))
  fi
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 \
    $REPO/smt-apps/loaded/loaded_server \
    --proto ${PROTO[$mode]} -p $ports -n $nmax -t $SERVER_THREADS -l $size"
}

client_cmd() {
  local mode=$1 size=$2 rpcs=$3
  local ports target_args sockets
  if [[ "$mode" == "smt" ]]; then
    ports=$SERVER_PORTS_HOMA
    target_args="-a $N1_IP -b $N1_IP_ALT"
    sockets=1
  else
    ports=$SERVER_PORTS_TCP
    target_args="-a $N1_IP"
    sockets=$CLIENT_THREADS
  fi
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c 4-15 \
    timeout -s SIGINT ${DUR}s $REPO/smt-apps/loaded/loaded_client \
    --proto ${PROTO[$mode]} $target_args -p $ports \
    -n $rpcs -s $sockets -m 0.0 -t $CLIENT_THREADS -l $size"
}

kill_server() {
  ssh n08 "pkill -9 -x loaded_server 2>/dev/null; sleep 0.2; \
    while pgrep -x loaded_server >/dev/null; do sleep 0.1; done; true"
}

run_one() {
  local mode=$1 size=$2 rpcs=$3 trial=$4
  echo "=== $mode size=$size rpcs=$rpcs trial=$trial ===" >&2
  kill_server
  ssh -f n08 "$(server_cmd "$mode" "$size") >/dev/null 2>&1 </dev/null"
  sleep 2
  local out
  out=$(ssh n09 "$(client_cmd "$mode" "$size" "$rpcs")" 2>&1 || true)
  kill_server
  printf '%s\n' "$out" >&2

  local json
  json=$(sed -n '/--- RESULT ---/,/--- RESULT ---/{/--- RESULT ---/d; p}' <<<"$out" | sed 's/-\?nan/null/g')
  if [[ -z "$json" ]]; then
    echo "$mode,$size,$rpcs,$trial,NA,NA,NA,NA,NA,NA,NA,NA" >> "$CSV"
    return
  fi
  jq -r --arg mode "$mode" --arg size "$size" --arg rpcs "$rpcs" --arg trial "$trial" '
    [$mode, $size, $rpcs, $trial,
     .total_rpcs, .kops_per_second,
     .tx_throughput_mbps, .rx_throughput_mbps,
     .average_rtt_us, .p50_median_rtt_us, .p95_rtt_us, .p99_rtt_us]
    | map(tostring) | join(",")' <<<"$json" >> "$CSV"
  echo >&2
}

MODES=${MODES:-smt tcp}
for mode in $MODES; do
  config_hosts "$mode"
  for size in "${SIZES[@]}"; do
    for rpcs in "${RPCS[@]}"; do
      for ((t = 1; t <= TRIALS; t++)); do
        run_one "$mode" "$size" "$rpcs" "$t"
      done
    done
  done
done

echo >&2
echo "=== CSV ($CSV) ===" >&2
cat "$CSV" >&2
