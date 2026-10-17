#!/usr/bin/env bash
# Single-IP, pin-core (no taskset) loaded bench. Multi-trial.
# Builds once on n08, then loops: rmmod -> config -> server/client -> capture.
#
# Usage:
#   profile_oneip.sh [--trials N] [--honest] LABEL PROTO CONFIG_MODE [EXTRA_CFLAGS]
#
#   --trials N    Number of trials (default: 5).
#   --honest      Build without -DCONFIG_HOMA_SMT_PROFILING.
#                 (default: profiling on, gives cycles/call breakdown
#                 in /proc/net/homa_metrics but adds ~117 ns/RPC.)
#
#   LABEL         Output dir name under ~/repos/SMT-NG_benchs/profile-oneip/$LABEL/.
#   PROTO         smt | homa | tcp | tcp_ktls
#   CONFIG_MODE   smt-sw | homa | tcp | ktls-sw  (passed to config_loaded_oneip -m)
#   EXTRA_CFLAGS  extra make SMT_CFLAGS, e.g. -DCONFIG_SMT_NOCRYPTO (optional)
#
# Per-trial: stops apps + rmmods on both nodes, reconfigures, launches
# server (n08) and client (n09), tees client.log, then kills server.
set -uxo pipefail

TRIALS=5
HONEST=0
while [[ $# -gt 0 && "$1" == --* ]]; do
  case "$1" in
    --trials) TRIALS=$2; shift 2 ;;
    --honest) HONEST=1; shift ;;
    --) shift; break ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

LABEL=$1; PROTO=$2; CONFIG_MODE=$3; EXTRA=${4:-}
THREADS=4; RPCS=150
ROOT=~/repos/SMT-NG_benchs/profile-oneip

ports="2000-$((2000 + THREADS - 1))"
target_args="-a 192.168.12.1"
case "$PROTO" in
  homa|smt) nmax=1; sockets=1 ;;
  *)        nmax="$((THREADS * THREADS))"; sockets="$THREADS"; ports="2000" ;;
esac

PROFILING_FLAG="-DCONFIG_HOMA_SMT_PROFILING"
[[ $HONEST -eq 1 ]] && PROFILING_FLAG=""

# Build ONCE.
timeout 180 ssh n08 "cd /root/SMT-NG && make clean && make all SMT_CFLAGS='$PROFILING_FLAG $EXTRA' -j\$(nproc)" >&2

clean_apps_and_module() {
  local h=$1
  ssh "$h" "
    pkill -9 -x loaded_server 2>/dev/null
    pkill -9 -x loaded_client 2>/dev/null
    sleep 0.3
    while pgrep -x loaded_server >/dev/null || pgrep -x loaded_client >/dev/null; do sleep 0.2; done
    for i in 1 2 3 4 5; do
      lsmod | grep -q '^homa ' || break
      rmmod homa 2>/dev/null && break
      sleep 0.5
    done
    true
  "
}

for trial in $(seq 1 "$TRIALS"); do
  OUT=$ROOT/$LABEL/t$trial
  mkdir -p "$OUT"

  clean_apps_and_module n08
  clean_apps_and_module n09

  timeout 60 ssh n08 "NTUPLE_PRI=0 /root/SMT-NG/smt-apps/util/config_loaded_oneip -i ens1f1np1 -a 192.168.12.1/24 -m $CONFIG_MODE" >&2
  timeout 60 ssh n09 "NTUPLE_PRI=0 /root/SMT-NG/smt-apps/util/config_loaded_oneip -i ens1f1np1 -a 192.168.12.2/24 -m $CONFIG_MODE" >&2

  # Server: pin core ON (default), offset=4 -> threads pin cores 4..(4+THREADS-1).
  # No taskset -- pin makes it redundant.
  ssh -f n08 "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_OFFSET=4 \
    /root/SMT-NG/smt-apps/loaded/loaded_server \
      --proto $PROTO -p $ports -n $nmax -t $THREADS -l 64 \
      >/dev/null 2>&1 </dev/null"
  sleep 2

  timeout 30 ssh n09 "ulimit -n 1048576; HOMA_ECHO_PIN_CORE_OFFSET=4 \
    timeout -s SIGINT 10s /root/SMT-NG/smt-apps/loaded/loaded_client \
      --proto $PROTO $target_args -p $ports \
      -n $RPCS -s $sockets -m 0 -t $THREADS -l 64" 2>&1 | tee "$OUT/client.log" || true

  ssh n08 "pkill -9 -x loaded_server 2>/dev/null; while pgrep -x loaded_server >/dev/null; do sleep 0.1; done; true" >&2
  K=$(grep -oP '"kops_per_second":\s*\K[\d.]+' "$OUT/client.log" 2>/dev/null || echo NA)
  echo "TRIAL $trial: $LABEL kops=$K" >&2
done
echo "ALL_TRIALS_DONE: $LABEL" >&2
