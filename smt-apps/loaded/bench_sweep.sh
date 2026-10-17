#!/usr/bin/env bash
# bench_sweep.sh - Sweep payload x rpcs x proto for the loaded bench.
#
# Modes:
#   Default (legacy):   MODES="smt homa tcp ktls" [NOCRYPTO_MODES=...]
#   Multi-config sweep: CONFIGS="LABEL,REF,CFLAGS,PROTO,MODE;..."  (overrides MODES)
#
# Toggles:
#   ONEIP=1     Use config_loaded_oneip (no -b alt-IP). For pin-core single-IP runs.
#   POWER_CYCLE_ON_PANIC=1
#               If dmesg shows BUG/Oops/call-trace, ssh duck "tm power restart"
#               and reload module before continuing. Default: detect+mark only.
#
# Usage: ./bench_sweep.sh [duration_secs] [csv_path] [trials]
set -euxo pipefail

LOCAL_REPO=${LOCAL_REPO:-$HOME/repos/HomaModule}
REPO=${REPO:-/root/SMT-NG}
script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Self-copy guard. If we're going to git-checkout LOCAL_REPO and we're running
# from inside it, the script file would mutate under us — re-exec from /tmp.
# Do this BEFORE any SIZES=(...) etc array assignments so the re-exec'd bash
# still has the original env-var SIZES/RPCS (array assignment unexports them).
if [[ -n "${CONFIGS:-}" \
      && "${BENCH_SWEEP_REEXEC:-0}" != "1" \
      && "$(realpath "$0")" == "$(realpath "$LOCAL_REPO")/"* ]]; then
  tmp_self=/tmp/bench_sweep_$$.sh
  cp "$0" "$tmp_self"
  export BENCH_SWEEP_REEXEC=1
  exec bash "$tmp_self" "$@"
fi

ENTRY_ARGS=("$@")
DUR=${1:-8}
CSV=${2:-$script_dir/bench_loaded.csv}
TRIALS=${3:-3}

mkdir -p "$(dirname "$CSV")"

# --- profile: n08/n09 (Silver 4314 x2) ---
IFNAME=ens1f1np1
SRV_HOST=n08
CLI_HOST=n09
N1_IP=192.168.12.1
N1_IP_ALT=192.168.13.1
N2_IP=192.168.12.2
N2_IP_ALT=192.168.13.2
CLIENT_THREADS=${CLIENT_THREADS:-12}
SERVER_THREADS=${SERVER_THREADS:-12}
TASKSET_CORES=${TASKSET_CORES-4-15}
NTUPLE_PRI=0
NTUPLE_SEC=2

# Pin-core path (single-IP, no taskset wrapper) — bench_sweep_oneip.sh shape.
ONEIP=${ONEIP:-0}
if [[ "$ONEIP" = "1" ]]; then
  CLIENT_THREADS=4
  SERVER_THREADS=4
  TASKSET_CORES=  # taskset disabled; rely on HOMA_ECHO_PIN_CORE_OFFSET
fi

SERVER_PORTS_HOMA="2000-$((2000 + SERVER_THREADS - 1))"
SERVER_PORTS_TCP="2000"

SIZES=(${SIZES:-64 1024 8192})
RPCS=(${RPCS:-1 25 50 75 100 125 150})

declare -A PROTO=([smt]=smt [homa]=homa [tcp]=tcp [ktls]=tcp_ktls [ktls-hw]=tcp_ktls [nocrypto]=smt [smt-hw]=smt)
declare -A CONFIG_MODE=([smt]=smt-sw [homa]=homa [tcp]=tcp [ktls]=ktls-sw [ktls-hw]=ktls-hw [nocrypto]=smt-sw [smt-hw]=smt-hw)
multihome_modes="smt homa nocrypto smt-hw"

# CSV header. config column is empty when CONFIGS unset (backward-compat).
echo "config,mode,size,rpcs,trial,total_rpcs,kops_per_second,tx_mbps,rx_mbps,avg_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us,sha,note" > "$CSV"

PANIC_DIR="$(dirname "$CSV")/panic-events"
mkdir -p "$PANIC_DIR"

is_multihome() {
  [[ " $multihome_modes " == *" $1 "* ]]
}

config_hosts() {
  local mode=$1
  local cfg=${CONFIG_MODE[$mode]}
  local cmd_util="$REPO/smt-apps/util/config_loaded"
  [[ "$ONEIP" = "1" ]] && cmd_util="$REPO/smt-apps/util/config_loaded_oneip"

  if [[ "$ONEIP" = "1" ]] || ! is_multihome "$mode"; then
    ssh "$SRV_HOST" "$cmd_util -i ${SRV_IFNAME:-$IFNAME} -a $N1_IP/24 -m $cfg" >&2
    ssh "$CLI_HOST" "$cmd_util -i ${CLI_IFNAME:-$IFNAME} -a $N2_IP/24 -m $cfg" >&2
  else
    ssh "$SRV_HOST" "NTUPLE_PRI=$NTUPLE_PRI NTUPLE_SEC=$NTUPLE_SEC $cmd_util -i ${SRV_IFNAME:-$IFNAME} -a $N1_IP/24 -b $N1_IP_ALT/24 -m $cfg" >&2
    ssh "$CLI_HOST" "NTUPLE_PRI=$NTUPLE_PRI NTUPLE_SEC=$NTUPLE_SEC $cmd_util -i ${CLI_IFNAME:-$IFNAME} -a $N2_IP/24 -b $N2_IP_ALT/24 -m $cfg" >&2
  fi
}

server_cmd() {
  local mode=$1 size=$2
  local ports nmax taskset_pfx=""
  if is_multihome "$mode"; then
    ports=$SERVER_PORTS_HOMA
    nmax=1
  else
    ports=$SERVER_PORTS_TCP
    nmax=$((CLIENT_THREADS * CLIENT_THREADS))
  fi
  [[ -n "$TASKSET_CORES" ]] && taskset_pfx="taskset -c $TASKSET_CORES"
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=${HOMA_ECHO_PIN_CORE_DISABLE:-1} HOMA_ECHO_PIN_CORE_OFFSET=${HOMA_ECHO_PIN_CORE_OFFSET:-4} $taskset_pfx \
    $REPO/smt-apps/loaded/loaded_server \
    --proto ${PROTO[$mode]} -p $ports -n $nmax -t $SERVER_THREADS -l $size"
}

client_rate_mbps() {
  echo "${RATE_MBPS_OVERRIDE:-0}"
}

client_cmd() {
  local mode=$1 size=$2 rpcs=$3
  local ports target_args sockets rate taskset_pfx=""
  if is_multihome "$mode"; then
    ports=$SERVER_PORTS_HOMA
    if [[ "$ONEIP" = "1" ]]; then
      target_args="-a $N1_IP"
    else
      target_args="-a $N1_IP -b $N1_IP_ALT"
    fi
    sockets=1
  else
    ports=$SERVER_PORTS_TCP
    target_args="-a $N1_IP"
    sockets=$CLIENT_THREADS
  fi
  rate=$(client_rate_mbps "$size")
  [[ -n "$TASKSET_CORES" ]] && taskset_pfx="taskset -c $TASKSET_CORES"
  echo "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_DISABLE=${HOMA_ECHO_PIN_CORE_DISABLE:-1} HOMA_ECHO_PIN_CORE_OFFSET=${HOMA_ECHO_PIN_CORE_OFFSET:-4} $taskset_pfx \
    timeout -s SIGINT ${DUR}s $REPO/smt-apps/loaded/loaded_client \
    --proto ${PROTO[$mode]} $target_args -p $ports \
    -n $rpcs -s $sockets -m $rate -t $CLIENT_THREADS -l $size"
}

kill_server() {
  ssh "$SRV_HOST" "pkill -9 -x loaded_server 2>/dev/null; sleep 0.2; \
    while pgrep -x loaded_server >/dev/null; do sleep 0.1; done; true"
}

# Returns 0 if dmesg is clean, 1 if BUG/Oops/call-trace seen.
check_panic() {
  local h=$1
  ssh "$h" "dmesg | tail -200 | grep -iqE 'BUG:|Oops:|call trace|kernel panic'"
}

snapshot_dmesg() {
  local h=$1 dest=$2
  ssh "$h" "dmesg -T | tail -500" > "$dest" 2>/dev/null || true
}

power_cycle_recover() {
  local mode=$1
  echo "=== POWER CYCLE: n08 then n09 ===" >&2
  ssh duck "tm power restart n08" >&2 || true
  ssh duck "tm power restart n09" >&2 || true
  local deadline=$(( $(date +%s) + 240 ))
  while (( $(date +%s) < deadline )); do
    if timeout 3 ssh -o ConnectTimeout=2 -o BatchMode=yes "$SRV_HOST" true 2>/dev/null \
       && timeout 3 ssh -o ConnectTimeout=2 -o BatchMode=yes "$CLI_HOST" true 2>/dev/null; then
      echo "=== both nodes back ===" >&2
      sleep 5
      config_hosts "$mode"
      return 0
    fi
    sleep 5
  done
  echo "=== POWER CYCLE TIMEOUT — bailing ===" >&2
  return 1
}

CURRENT_CONFIG=""

run_one() {
  local mode=$1 size=$2 rpcs=$3 trial=$4
  local max_attempts=${NA_RETRIES:-3} attempt=1 out json note=""
  local sha=${CURRENT_SHA:-}

  while (( attempt <= max_attempts )); do
    echo "=== cfg=$CURRENT_CONFIG mode=$mode size=$size rpcs=$rpcs trial=$trial attempt=$attempt ===" >&2
    kill_server
    ssh -f "$SRV_HOST" "$(server_cmd "$mode" "$size") >/dev/null 2>&1 </dev/null"
    sleep 2
    out=$(ssh "$CLI_HOST" "$(client_cmd "$mode" "$size" "$rpcs")" 2>&1 || true)
    kill_server
    printf '%s\n' "$out" >&2
    json=$(awk '/--- RESULT ---/{f=!f; next} f' <<<"$out" | sed -E 's/-?nan/null/g')

    # Panic check, regardless of result.
    local panic_host=""
    for h in "$SRV_HOST" "$CLI_HOST"; do
      if check_panic "$h"; then
        panic_host=$h
        local snap="$PANIC_DIR/${CURRENT_CONFIG}_${size}_${rpcs}_t${trial}_${h}.log"
        snapshot_dmesg "$h" "$snap"
        echo "=== PANIC on $h, snapshot $snap ===" >&2
        break
      fi
    done

    if [[ -n "$panic_host" ]]; then
      note="PANIC:$panic_host"
      if [[ "${POWER_CYCLE_ON_PANIC:-0}" = "1" ]]; then
        if ! power_cycle_recover "$mode"; then
          break
        fi
      fi
      # Don't retry the same panicking cell.
      json=""
      break
    fi

    [[ -n "$json" ]] && break
    echo "=== NA on attempt=$attempt, retrying ===" >&2
    (( attempt++ ))
  done

  if [[ -z "$json" ]]; then
    echo "$CURRENT_CONFIG,$mode,$size,$rpcs,$trial,NA,NA,NA,NA,NA,NA,NA,NA,$sha,$note" >> "$CSV"
    return
  fi
  jq -r --arg cfg "$CURRENT_CONFIG" --arg mode "$mode" --arg size "$size" --arg rpcs "$rpcs" \
        --arg trial "$trial" --arg sha "$sha" --arg note "$note" '
    [$cfg, $mode, $size, $rpcs, $trial,
     .total_rpcs, .kops_per_second,
     .tx_throughput_mbps, .rx_throughput_mbps,
     .average_rtt_us, .p50_median_rtt_us, .p95_rtt_us, .p99_rtt_us,
     $sha, $note]
    | map(tostring) | join(",")' <<<"$json" >> "$CSV"
  echo >&2
}

rebuild_module() {
  local target=$1 cflags=$2
  local envs=""
  [[ -n "${NO_CONFIG_SMT:-}" ]] && envs+="NO_CONFIG_SMT=1 "
  ssh "$SRV_HOST" "cd $REPO && make clean && ${envs}make $target SMT_CFLAGS='$cflags' -j\$(nproc)" >&2
}

sync_repo_to_n08() {
  # Sync kernel sources + util scripts. Exclude only the compiled bench
  # binaries so per-config git-checkout to old refs doesn't downgrade
  # n08's loaded_server/client (rebuilt rarely, not part of git history).
  rsync -az --delete \
    --exclude='.git' --exclude='*.o' --exclude='*.ko' --exclude='*.mod*' \
    --exclude='.*.cmd' --exclude='modules.order' --exclude='Module.symvers' \
    --exclude='smt-apps/loaded/loaded_server' \
    --exclude='smt-apps/loaded/loaded_client' \
    "$LOCAL_REPO/" "$SRV_HOST:$REPO/" >&2
}

run_size_rpc_trials() {
  local mode=$1
  for size in "${SIZES[@]}"; do
    for rpcs in "${RPCS[@]}"; do
      for ((t = 1; t <= TRIALS; t++)); do
        run_one "$mode" "$size" "$rpcs" "$t"
      done
    done
  done
}

run_modes() {
  local modes=$1
  for mode in $modes; do
    config_hosts "$mode"
    run_size_rpc_trials "$mode"
  done
}

SAVED_BRANCH=""
restore_branch() {
  if [[ -n "$SAVED_BRANCH" ]]; then
    git -C "$LOCAL_REPO" checkout "$SAVED_BRANCH" >&2 || true
    SAVED_BRANCH=""
  fi
}
trap restore_branch EXIT

run_configs() {
  SAVED_BRANCH=$(git -C "$LOCAL_REPO" rev-parse --abbrev-ref HEAD)
  if ! git -C "$LOCAL_REPO" diff --quiet || ! git -C "$LOCAL_REPO" diff --cached --quiet; then
    echo "ERROR: $LOCAL_REPO has uncommitted changes; refuse to checkout. Stash first." >&2
    exit 1
  fi

  local IFS_save=$IFS
  IFS=';' read -ra ENTRIES <<< "$CONFIGS"
  IFS=$IFS_save

  local build_info="$(dirname "$CSV")/build-info.txt"
  : > "$build_info"

  for entry in "${ENTRIES[@]}"; do
    [[ -z "$entry" ]] && continue
    IFS=',' read -r LABEL REF CFLAGS PROTO_LBL CONFIG_MODE_LBL <<< "$entry"
    [[ -z "$LABEL" || -z "$REF" || -z "$PROTO_LBL" || -z "$CONFIG_MODE_LBL" ]] && {
      echo "ERROR: malformed CONFIGS entry: $entry" >&2; exit 2
    }
    echo "===== CONFIG $LABEL  ref=$REF  cflags=$CFLAGS  proto=$PROTO_LBL  mode=$CONFIG_MODE_LBL =====" >&2

    git -C "$LOCAL_REPO" checkout "$REF" >&2
    CURRENT_SHA=$(git -C "$LOCAL_REPO" rev-parse --short=12 HEAD)
    echo "$LABEL  ref=$REF  sha=$CURRENT_SHA  cflags=$CFLAGS  proto=$PROTO_LBL  mode=$CONFIG_MODE_LBL" >> "$build_info"

    sync_repo_to_n08
    rebuild_module "all" "$CFLAGS"

    CURRENT_CONFIG=$LABEL
    PROTO[$PROTO_LBL]=$PROTO_LBL
    CONFIG_MODE[$PROTO_LBL]=$CONFIG_MODE_LBL
    config_hosts "$PROTO_LBL"
    run_size_rpc_trials "$PROTO_LBL"
  done

  restore_branch
  sync_repo_to_n08
}

# --- Entry ---
if [[ -n "${CONFIGS:-}" ]]; then
  run_configs
else
  NORMAL_MODES=${MODES:-smt homa tcp ktls}
  NOCRYPTO_MODES=${NOCRYPTO_MODES:-}

  sync_repo_to_n08
  echo "=== Rebuilding SW-only SMT (SMT_CFLAGS=${SMT_CFLAGS:-}) ===" >&2
  rebuild_module "all" "${SMT_CFLAGS:-}"
  CURRENT_CONFIG=""
  CURRENT_SHA=$(ssh "$SRV_HOST" "sha256sum $REPO/homa.ko" 2>/dev/null | cut -c1-12 || echo unknown)
  run_modes "$NORMAL_MODES"

  if [[ -n "$NOCRYPTO_MODES" ]]; then
    echo "=== Rebuilding with CONFIG_SMT_NOCRYPTO ===" >&2
    sync_repo_to_n08
    rebuild_module "all" "-DCONFIG_SMT_NOCRYPTO ${SMT_CFLAGS:-}"
    CURRENT_SHA=$(ssh "$SRV_HOST" "sha256sum $REPO/homa.ko" 2>/dev/null | cut -c1-12 || echo unknown)
    run_modes "$NOCRYPTO_MODES"
    echo "=== Restoring SW-only SMT build ===" >&2
    sync_repo_to_n08
    rebuild_module "all" "${SMT_CFLAGS:-}"
    CURRENT_SHA=$(ssh "$SRV_HOST" "sha256sum $REPO/homa.ko" 2>/dev/null | cut -c1-12 || echo unknown)
  fi

  HW_MODES=${HW_MODES:-}
  if [[ -n "$HW_MODES" ]]; then
    echo "=== Rebuilding HW-enabled SMT (make hw) ===" >&2
    sync_repo_to_n08
    rebuild_module "hw" "${SMT_CFLAGS:-}"
    CURRENT_SHA=$(ssh "$SRV_HOST" "sha256sum $REPO/homa.ko" 2>/dev/null | cut -c1-12 || echo unknown)
    run_modes "$HW_MODES"
    echo "=== Restoring SW-only SMT build ===" >&2
    sync_repo_to_n08
    rebuild_module "all" "${SMT_CFLAGS:-}"
    CURRENT_SHA=$(ssh "$SRV_HOST" "sha256sum $REPO/homa.ko" 2>/dev/null | cut -c1-12 || echo unknown)
  fi
fi

echo >&2
echo "=== CSV ($CSV) ===" >&2
cat "$CSV" >&2
