#!/usr/libexec/atf-sh

COUNT=10000
CONCURRENT_COUNT=20000
CONCURRENT_WINDOW=32
PARALLEL_COUNT=20000
PARALLEL_THREADS=8
CLOSE_TEST_SOCKET_COUNT=3000
LARGE_TIMEOUT=180

require_tools()
{
    atf_require_prog ifconfig
    atf_require_prog jail
    atf_require_prog jexec
    atf_require_prog pkill
    atf_require_prog kldstat
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_send"
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_recv"
}

cleanup_state()
{
    epair_name=""
    [ -f "${HOME}/epair.name" ] && epair_name=$(cat "${HOME}/epair.name")

    jail -r sdtp_a 2>/dev/null || true
    jail -r sdtp_b 2>/dev/null || true
    pkill -9 -f sdtp_test_recv 2>/dev/null || true
    pkill -9 -f sdtp_test_send 2>/dev/null || true
    [ -n "${epair_name}" ] && ifconfig "${epair_name}" destroy 2>/dev/null || true
}

dump_logs_on_failure()
{
    [ -f "${HOME}/.success" ] && return 0

    for f in send.out send.err recv.out; do
        if [ -f "${HOME}/${f}" ]; then
            echo "===== ${f} =====" >&2
            cat "${HOME}/${f}" >&2 || true
        fi
    done
}

make_payload()
{
    awk -v n="$1" 'BEGIN { for (i = 0; i < n; i++) printf "x" }'
}

run_ping_pong_case()
{
    size="$1"
    count="$2"
    tls="$3"
    window="${4:-1}"
    threads="${5:-1}"

    require_tools
    cleanup_state

    rm -f "${HOME}/.success" \
          "${HOME}/send.out" \
          "${HOME}/send.err" \
          "${HOME}/recv.out" \
          "${HOME}/epair.name"

    # TODO: We want someway to load it automatically
    kldstat -n sdtp >/dev/null 2>&1 || atf_skip "sdtp module is not loaded"
    kldstat -n if_epair >/dev/null 2>&1 || atf_skip "if_epair module is not loaded"

    tls_flag=""
    if [ "$tls" = "tls" ]; then
        atf_require_prog sysctl
        ktls_enabled=$(sysctl -n kern.ipc.tls.enable 2>/dev/null) ||
            atf_skip "kernel does not support TLS offload"
        [ "$ktls_enabled" -ne 0 ] || atf_skip "Kernel TLS is disabled"
        tls_flag="-T"
    fi

    payload=$(make_payload "$size") || atf_fail "failed to build ${size}-byte payload"
    [ "${#payload}" -eq "$size" ] || atf_fail "payload size mismatch"

    epair=$(ifconfig epair create) || atf_fail "failed to create epair"
    echo "${epair}" > "${HOME}/epair.name"

    a=${epair%a}a
    b=${epair%a}b

    jail -c name=sdtp_a persist vnet || atf_fail "failed to create jail sdtp_a"
    jail -c name=sdtp_b persist vnet || atf_fail "failed to create jail sdtp_b"

    ifconfig "${a}" vnet sdtp_a || atf_fail "failed to move ${a} to sdtp_a"
    ifconfig "${b}" vnet sdtp_b || atf_fail "failed to move ${b} to sdtp_b"

    jexec sdtp_a ifconfig "${a}" inet 192.0.2.1/24 up || atf_fail "failed to configure ${a}"
    jexec sdtp_b ifconfig "${b}" inet 192.0.2.2/24 up || atf_fail "failed to configure ${b}"

    jexec sdtp_b "$(atf_get_srcdir)/sdtp_test_recv" \
        -a 192.0.2.2 -p 9000 -n "$count" -q $tls_flag \
        > "${HOME}/recv.out" 2>&1 &
    recv_pid=$!

    sleep 1

    if ! jexec sdtp_a "$(atf_get_srcdir)/sdtp_test_send" \
        -a 192.0.2.2 -p 9000 -n "$count" -w "$window" \
        -j "$threads" -m "$payload" $tls_flag \
        > "${HOME}/send.out" 2> "${HOME}/send.err"; then
        atf_fail "sender exited with failure"
    fi

    wait "$recv_pid" || atf_fail "receiver exited with failure"

    touch "${HOME}/.success"
}

common_head()
{
    atf_set "require.user" "root"
    atf_set "timeout" "${1:-60}"
}

atf_test_case small_v4 cleanup
small_v4_head()
{
    common_head
    atf_set "descr" "SDTP ping-pong over two VNET jails with 32-byte payloads"
}
small_v4_body()
{
    run_ping_pong_case 32 "$COUNT" plain
}
small_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case medium_v4 cleanup
medium_v4_head()
{
    common_head
    atf_set "descr" "SDTP ping-pong over two VNET jails with 1024-byte payloads"
}
medium_v4_body()
{
    run_ping_pong_case 1024 "$COUNT" plain
}
medium_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case large_v4 cleanup
large_v4_head()
{
    common_head
    atf_set "descr" "SDTP ping-pong over two VNET jails with 8192-byte payloads"
}
large_v4_body()
{
    run_ping_pong_case 8192 "$COUNT" plain
}
large_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case small_tls_v4 cleanup
small_tls_v4_head()
{
    common_head
    atf_set "descr" "TLS-encrypted SDTP ping-pong with 32-byte payloads"
}
small_tls_v4_body()
{
    run_ping_pong_case 32 "$COUNT" tls
}
small_tls_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case medium_tls_v4 cleanup
medium_tls_v4_head()
{
    common_head
    atf_set "descr" "TLS-encrypted SDTP ping-pong with 1024-byte payloads"
}
medium_tls_v4_body()
{
    run_ping_pong_case 1024 "$COUNT" tls
}
medium_tls_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case large_tls_v4 cleanup
large_tls_v4_head()
{
    common_head
    atf_set "descr" "TLS-encrypted SDTP ping-pong with 8192-byte payloads"
}
large_tls_v4_body()
{
    run_ping_pong_case 8192 "$COUNT" tls
}
large_tls_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case concurrent_v4 cleanup
concurrent_v4_head()
{
    common_head
    atf_set "descr" "SDTP handles multiple concurrent RPCs on one socket"
}
concurrent_v4_body()
{
    run_ping_pong_case 8192 "$CONCURRENT_COUNT" plain "$CONCURRENT_WINDOW"
}
concurrent_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case concurrent_tls_v4 cleanup
concurrent_tls_v4_head()
{
    common_head
    atf_set "descr" "TLS-encrypted SDTP handles concurrent RPCs on one socket"
}
concurrent_tls_v4_body()
{
    run_ping_pong_case 8192 "$CONCURRENT_COUNT" tls "$CONCURRENT_WINDOW"
}
concurrent_tls_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case parallel_v4 cleanup
parallel_v4_head()
{
    common_head
    atf_set "descr" "SDTP handles RPCs from parallel threads on one socket"
}
parallel_v4_body()
{
    run_ping_pong_case 8192 "$PARALLEL_COUNT" plain 1 "$PARALLEL_THREADS"
}
parallel_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case parallel_tls_v4 cleanup
parallel_tls_v4_head()
{
    common_head
    atf_set "descr" "TLS-encrypted SDTP handles parallel RPC threads"
}
parallel_tls_v4_body()
{
    run_ping_pong_case 8192 "$PARALLEL_COUNT" tls 1 "$PARALLEL_THREADS"
}
parallel_tls_v4_cleanup()
{
    dump_logs_on_failure
    cleanup_state
}

atf_test_case ipv6_unsupported
ipv6_unsupported_head()
{
    atf_set "descr" "SDTP rejects IPv6 sockets"
}
ipv6_unsupported_body()
{
    atf_require_prog kldstat
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_ipv6"

    kldstat -n sdtp >/dev/null 2>&1 || atf_skip "sdtp module is not loaded"

    atf_check -s exit:0 -o empty -e empty \
        "$(atf_get_srcdir)/sdtp_test_ipv6"
}

atf_test_case close_detach
close_detach_head()
{
    common_head
    atf_set "descr" "SDTP close releases bound ports and detaches socket state"
}
close_detach_body()
{
    atf_require_prog kldstat
    atf_require_prog sysctl
    atf_require_prog "$(atf_get_srcdir)/sdtp_test_close"

    kldstat -n sdtp >/dev/null 2>&1 || atf_skip "sdtp module is not loaded"

    opened_before=$(sysctl -n net.sdtp.opened_sockets) ||
        atf_fail "failed to read opened_sockets"
    closed_before=$(sysctl -n net.sdtp.closed_sockets) ||
        atf_fail "failed to read closed_sockets"
    destroyed_before=$(sysctl -n net.sdtp.destroyed_sockets) ||
        atf_fail "failed to read destroyed_sockets"

    atf_check -s exit:0 -o empty -e empty \
        "$(atf_get_srcdir)/sdtp_test_close"

    opened_after=$(sysctl -n net.sdtp.opened_sockets) ||
        atf_fail "failed to read opened_sockets"
    closed_after=$(sysctl -n net.sdtp.closed_sockets) ||
        atf_fail "failed to read closed_sockets"
    destroyed_after=$(sysctl -n net.sdtp.destroyed_sockets) ||
        atf_fail "failed to read destroyed_sockets"

    atf_check_equal "$((opened_before + CLOSE_TEST_SOCKET_COUNT))" \
        "${opened_after}"
    atf_check_equal "$((closed_before + CLOSE_TEST_SOCKET_COUNT))" \
        "${closed_after}"
    atf_check_equal "$((destroyed_before + CLOSE_TEST_SOCKET_COUNT))" \
        "${destroyed_after}"
}

atf_init_test_cases()
{
    atf_add_test_case small_v4
    atf_add_test_case medium_v4
    atf_add_test_case large_v4
    atf_add_test_case small_tls_v4
    atf_add_test_case medium_tls_v4
    atf_add_test_case large_tls_v4
    atf_add_test_case concurrent_v4
    atf_add_test_case concurrent_tls_v4
    atf_add_test_case parallel_v4
    atf_add_test_case parallel_tls_v4
    atf_add_test_case ipv6_unsupported
    atf_add_test_case close_detach
}
