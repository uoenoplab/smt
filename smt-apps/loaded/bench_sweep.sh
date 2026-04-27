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

# Per-side IFNAME (the test fabric's 100G NIC may have different udev names
# on each node). Falls back to IFNAME if SRV_/CLI_ unset.
# Ntuple action numbers (RX queue) for SMT/Homa primary/secondary IP — pick
# queues whose IRQs land on cores OUTSIDE the taskset range (allnuma maps
# queue N -> core N within NUMA node).

# --- profile: n08/n09 (Silver 4314 x2) ---
IFNAME=ens1f1np1
SRV_HOST=n08
CLI_HOST=n09
N1_IP=192.168.12.1
N1_IP_ALT=192.168.13.1
N2_IP=192.168.12.2
N2_IP_ALT=192.168.13.2
CLIENT_THREADS=12
SERVER_THREADS=12
TASKSET_CORES=4-15
NTUPLE_PRI=0
NTUPLE_SEC=2

# --- profile: n15/n16 (Gold 5418N, 24 cores online, NUMA0=0-23) ---
# IFNAME=ens2f0np0
# SRV_HOST=n15; CLI_HOST=n16
# CLIENT_THREADS=13; SERVER_THREADS=13; TASKSET_CORES=6-18
# NTUPLE_PRI=4; NTUPLE_SEC=19

# --- profile: n17 server / n15 client (asymm hardware, asymm NIC names) ---
# SRV_HOST=n17; CLI_HOST=n15
# SRV_IFNAME=enp225s0f0np0; CLI_IFNAME=ens2f0np0
# CLIENT_THREADS=10; SERVER_THREADS=10; TASKSET_CORES=4-13
# NTUPLE_PRI=0; NTUPLE_SEC=2
SERVER_PORTS_HOMA="2000-$((2000 + SERVER_THREADS - 1))"   # one per server thread
SERVER_PORTS_TCP="2000"

SIZES=(${SIZES:-64 1024 8192})
RPCS=(${RPCS:-1 25 50 75 100 125 150})

declare -A PROTO=([smt]=smt [homa]=homa [tcp]=tcp [ktls]=tcp_ktls)
declare -A CONFIG_MODE=([smt]=smt-sw [homa]=homa [tcp]=tcp [ktls]=ktls-sw)
multihome_modes="smt homa"       # modes that use -b secondary IP for poor-man's RSS

echo "mode,size,rpcs,trial,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us" > "$CSV"

is_multihome() {
  [[ " $multihome_modes " == *" $1 "* ]]
}

config_hosts() {
  local mode=$1 cfg=${CONFIG_MODE[$mode]}
  if is_multihome "$mode"; then
    ssh "$SRV_HOST" "NTUPLE_PRI=$NTUPLE_PRI NTUPLE_SEC=$NTUPLE_SEC $REPO/smt-apps/util/config_loaded -i ${SRV_IFNAME:-$IFNAME} -a $N1_IP/24 -b $N1_IP_ALT/24 -m $cfg" >&2
    ssh "$CLI_HOST" "NTUPLE_PRI=$NTUPLE_PRI NTUPLE_SEC=$NTUPLE_SEC $REPO/smt-apps/util/config_loaded -i ${CLI_IFNAME:-$IFNAME} -a $N2_IP/24 -b $N2_IP_ALT/24 -m $cfg" >&2
  else
    ssh "$SRV_HOST" "$REPO/smt-apps/util/config_loaded -i ${SRV_IFNAME:-$IFNAME} -a $N1_IP/24 -m $cfg" >&2
    ssh "$CLI_HOST" "$REPO/smt-apps/util/config_loaded -i ${CLI_IFNAME:-$IFNAME} -a $N2_IP/24 -m $cfg" >&2
  fi
}

server_cmd() {
  local mode=$1 size=$2
  local ports nmax
  if is_multihome "$mode"; then
    ports=$SERVER_PORTS_HOMA
    nmax=1
  else
    ports=$SERVER_PORTS_TCP
    nmax=$((CLIENT_THREADS * CLIENT_THREADS))
  fi
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c $TASKSET_CORES \
    $REPO/smt-apps/loaded/loaded_server \
    --proto ${PROTO[$mode]} -p $ports -n $nmax -t $SERVER_THREADS -l $size"
}

# Per-size aggregate Mbps cap (reqlen-based; 0 = no rate limit).
# Override via RATE_MBPS_OVERRIDE env to force a specific rate (regardless of size).
client_rate_mbps() {
  if [[ -n "${RATE_MBPS_OVERRIDE:-}" ]]; then
    echo "$RATE_MBPS_OVERRIDE"; return
  fi
  case "$1" in
    64)    echo 512  ;;   # ~1000 kops
    65536) echo 7864 ;;   # ~15 kops (cliff floor 17 kops × 0.85)
    *)     echo 0    ;;
  esac
}

client_cmd() {
  local mode=$1 size=$2 rpcs=$3
  local ports target_args sockets rate
  if is_multihome "$mode"; then
    ports=$SERVER_PORTS_HOMA
    target_args="-a $N1_IP -b $N1_IP_ALT"
    sockets=1
  else
    ports=$SERVER_PORTS_TCP
    target_args="-a $N1_IP"
    sockets=$CLIENT_THREADS
  fi
  rate=$(client_rate_mbps "$size")
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=1 taskset -c $TASKSET_CORES \
    timeout -s SIGINT ${DUR}s $REPO/smt-apps/loaded/loaded_client \
    --proto ${PROTO[$mode]} $target_args -p $ports \
    -n $rpcs -s $sockets -m $rate -t $CLIENT_THREADS -l $size"
}

kill_server() {
  ssh "$SRV_HOST" "pkill -9 -x loaded_server 2>/dev/null; sleep 0.2; \
    while pgrep -x loaded_server >/dev/null; do sleep 0.1; done; true"
}

run_one() {
  local mode=$1 size=$2 rpcs=$3 trial=$4
  local max_attempts=${NA_RETRIES:-3} attempt=1 out json
  while (( attempt <= max_attempts )); do
    echo "=== $mode size=$size rpcs=$rpcs trial=$trial attempt=$attempt ===" >&2
    kill_server
    ssh -f "$SRV_HOST" "$(server_cmd "$mode" "$size") >/dev/null 2>&1 </dev/null"
    sleep 2
    out=$(ssh "$CLI_HOST" "$(client_cmd "$mode" "$size" "$rpcs")" 2>&1 || true)
    kill_server
    printf '%s\n' "$out" >&2
    json=$(awk '/--- RESULT ---/{f=!f; next} f' <<<"$out" | sed -E 's/-?nan/null/g')
    [[ -n "$json" ]] && break
    echo "=== NA on attempt=$attempt, retrying ===" >&2
    (( attempt++ ))
  done
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
