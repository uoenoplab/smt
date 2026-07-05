#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

SERVER_HOST=${SERVER_HOST:-duck-n08}
CLIENT_HOST=${CLIENT_HOST:-duck-n09}
SERVER_IP=${SERVER_IP:-192.168.11.77}
PORT=${PORT:-2000}
PROTO=${PROTO:-smt}
DURATION=${DURATION:-8}
REMOTE_SRC=${REMOTE_SRC:-/usr/src/sys/modules/smt}
RESULTS_DIR=${RESULTS_DIR:-"$SCRIPT_DIR/bench/results/${PROTO}-unloaded-$(date +%Y%m%d-%H%M%S)"}

case "$PROTO" in
tcp|ktls-sw)
	SERVER_BIN=tcp_simple_server
	CLIENT_BIN=tcp_simple_client
	NEED_SMT=0
	;;
homa|smt)
	SERVER_BIN=smt_simple_server
	CLIENT_BIN=smt_simple_client
	NEED_SMT=1
	;;
*)
	echo "Unsupported PROTO: $PROTO" >&2
	exit 2
	;;
esac

#PAYLOAD_SIZES=(
#	64
#)

PAYLOAD_SIZES=(
    64 128 256 512 1024 2048 4096 8192
)

SERVER_LOG=

cleanup()
{
	ssh "$SERVER_HOST" \
	    "pkill -x '$SERVER_BIN' >/dev/null 2>&1 || true" \
	    >/dev/null 2>&1 || true
	ssh "$CLIENT_HOST" \
	    "pkill -x '$CLIENT_BIN' >/dev/null 2>&1 || true" \
	    >/dev/null 2>&1 || true

	if [[ -n "$SERVER_LOG" ]]; then
		scp "$SERVER_HOST:$SERVER_LOG" "$RESULTS_DIR/" \
		    >/dev/null 2>&1 || true
		ssh "$SERVER_HOST" "rm -f '$SERVER_LOG'" \
		    >/dev/null 2>&1 || true
	fi
}

sync_and_build()
{
	local host=$1

	echo "=== Syncing SMT sources to $host ==="
	rsync --progress -avz --delete \
	    --exclude 'bench/results/' \
	    "$SCRIPT_DIR/" "$host:$REMOTE_SRC/"

	if [[ "$NEED_SMT" -eq 1 ]]; then
		echo "=== Building and loading SMT on $host ==="
		ssh "$host" \
		    "pkill -x '$SERVER_BIN' >/dev/null 2>&1 || true
		     pkill -x '$CLIENT_BIN' >/dev/null 2>&1 || true
		     cd '$REMOTE_SRC' &&
		     (make unload >/dev/null 2>&1 || true) &&
		     make clean &&
		     make &&
		     make load &&
		     make -C '$REMOTE_SRC/bench/unloaded' clean &&
		     make -C '$REMOTE_SRC/bench/unloaded' &&
		     objdir=\$(make -C '$REMOTE_SRC/bench/unloaded' -V .OBJDIR) &&
		     test -x \"\$objdir/$SERVER_BIN\" &&
		     test -x \"\$objdir/$CLIENT_BIN\" &&
		     echo \"=== Unloaded benchmark binaries: \$objdir ===\""
	else
		echo "=== Building TCP benchmark on $host ==="
		ssh "$host" \
		    "pkill -x '$SERVER_BIN' >/dev/null 2>&1 || true
		     pkill -x '$CLIENT_BIN' >/dev/null 2>&1 || true
		     if [ '$PROTO' = ktls-sw ]; then
		         sysctl kern.ipc.tls.enable=1 >/dev/null &&
		         sysctl kern.ipc.tls.ifnet.permitted=0 >/dev/null
		     fi &&
		     make -C '$REMOTE_SRC/bench/unloaded' clean &&
		     make -C '$REMOTE_SRC/bench/unloaded' &&
		     objdir=\$(make -C '$REMOTE_SRC/bench/unloaded' -V .OBJDIR) &&
		     test -x \"\$objdir/$SERVER_BIN\" &&
		     test -x \"\$objdir/$CLIENT_BIN\" &&
		     echo \"=== Unloaded benchmark binaries: \$objdir ===\""
	fi
}

start_server()
{
	local payload=$1

	cleanup
	SERVER_LOG="/tmp/${PROTO}-unloaded-server-${payload}-$$.log"

	echo "=== Starting server: payload=$payload bytes ==="
	ssh "$SERVER_HOST" \
	    "objdir=\$(make -C '$REMOTE_SRC/bench/unloaded' -V .OBJDIR) &&
	     cd \"\$objdir\" &&
	     nohup ./'$SERVER_BIN' \
	         --proto '$PROTO' \
	         -p '$PORT' \
	         -l '$payload' \
	         >'$SERVER_LOG' 2>&1 </dev/null &"

	sleep 1
	if ! ssh "$SERVER_HOST" "pgrep -x '$SERVER_BIN' >/dev/null"; then
		echo "Server failed to start; remote log follows:" >&2
		ssh "$SERVER_HOST" "cat '$SERVER_LOG'" >&2 || true
		return 1
	fi
}

json_value()
{
	local key=$1
	local file=$2

	awk -F ': ' -v key="\"$key\"" '
	    $1 ~ key {
	        value = $2
	        gsub(/[",]/, "", value)
	        print value
	        exit
	    }
	' "$file"
}

run_experiment()
{
	local payload=$1
	local log="$RESULTS_DIR/payload-${payload}.log"

	echo "=== Running: payload=$payload bytes, duration=${DURATION}s ==="
	ssh "$CLIENT_HOST" \
	    "objdir=\$(make -C '$REMOTE_SRC/bench/unloaded' -V .OBJDIR) &&
	     cd \"\$objdir\" || exit 1
	     set +e
	     timeout -s SIGINT '${DURATION}s' \
	         ./'$CLIENT_BIN' \
	         --proto '$PROTO' \
	         -a '$SERVER_IP' \
	         -p '$PORT' \
	         -l '$payload'
	     status=\$?
	     if [ \"\$status\" -ne 0 ] && [ \"\$status\" -ne 124 ]; then
	         exit \"\$status\"
	     fi" |
	    tee "$log"

	printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
	    "$payload" \
	    "$DURATION" \
	    "$(json_value total_rpcs "$log")" \
	    "$(json_value kops_per_second "$log")" \
	    "$(json_value tx_throughput_mbps "$log")" \
	    "$(json_value rx_throughput_mbps "$log")" \
	    "$(json_value average_rtt_us "$log")" \
	    "$(json_value p50_median_rtt_us "$log")" \
	    "$(json_value p95_rtt_us "$log")" \
	    "$(json_value p99_rtt_us "$log")" \
	    >>"$RESULTS_DIR/summary.csv"
}

mkdir -p "$RESULTS_DIR"
trap cleanup EXIT INT TERM

cat >"$RESULTS_DIR/summary.csv" <<EOF
payload_bytes,duration_seconds,total_rpcs,kops_per_second,tx_mbps,rx_mbps,average_rtt_us,p50_rtt_us,p95_rtt_us,p99_rtt_us
EOF

sync_and_build "$SERVER_HOST"
sync_and_build "$CLIENT_HOST"

for payload in "${PAYLOAD_SIZES[@]}"; do
	start_server "$payload"
	run_experiment "$payload"
done

echo "=== Benchmark complete: $RESULTS_DIR ==="
