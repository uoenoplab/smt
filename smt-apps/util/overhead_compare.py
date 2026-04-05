#!/usr/bin/env python3
"""
Compare Homa vs SMT per-RPC overhead from /proc/net/homa_metrics.

Usage:
  # Run both benches automatically and compare:
  overhead_compare.py <server> <client> [-l LEN] [-d DURATION]

  # Compare from pre-saved metric files:
  overhead_compare.py --files <homa_srv> <smt_srv> <homa_cli> <smt_cli>

Examples:
  overhead_compare.py n08 n09
  overhead_compare.py n08 n09 -l 1420 -d 10
  overhead_compare.py --files homa_n08.txt smt_n08.txt homa_n09.txt smt_n09.txt
"""

import argparse
import re
import subprocess
import sys
import time

CPU_MHZ = 2400


# ── SSH helpers ────────────────────────────────────────────────────────────────

def ssh(node, cmd, check=True, silent=False):
    print(f"  [ssh {node}] {cmd}", flush=True)
    r = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", node, f"bash -i -c '{cmd}'"],
        capture_output=True, text=True, check=check
    )
    if not silent:
        for line in r.stdout.strip().splitlines():
            print(f"  [stdout] {line}", flush=True)
    for line in r.stderr.strip().splitlines():
        if 'no job control' in line or 'cannot set terminal process group' in line:
            continue
        print(f"  [stderr] {line}", flush=True)
    return r

def ssh_out(node, cmd):
    return ssh(node, cmd, silent=True).stdout.strip()


# ── Metrics loading ────────────────────────────────────────────────────────────

def _parse_metrics(lines):
    totals = {}
    for line in lines:
        m = re.match(r'^(\S+)\s+(\d+)', line)
        if not m or m.group(1) == 'core':
            continue
        k, v = m.group(1), int(m.group(2))
        totals[k] = totals.get(k, 0) + v
    return totals

def load_file(path):
    print(f"  [load] {path}", flush=True)
    totals = _parse_metrics(open(path))
    rpcs = totals.get('server_responses_done', totals.get('client_requests_done', 0))
    print(f"  [load] {len(totals)} metrics, rpcs={rpcs:,}", flush=True)
    return totals

def fetch_metrics(node):
    print(f"  [fetch] /proc/net/homa_metrics from {node}", flush=True)
    raw = ssh_out(node, "cat /proc/net/homa_metrics")
    totals = _parse_metrics(raw.splitlines())
    rpcs = totals.get('server_responses_done', totals.get('client_requests_done', 0))
    print(f"  [fetch] {len(totals)} metrics, rpcs={rpcs:,}", flush=True)
    return totals


# ── Bench runner ───────────────────────────────────────────────────────────────

def reload_module(server, client):
    print("  reloading module (reset metrics)...", flush=True)
    for node in (server, client):
        ssh(node, "pkill -f simple_server; pkill -f simple_client; sleep 1", check=False)
    t0 = time.time()
    ssh(server, "homa-load")
    ssh(server, "/root/SMT-NG/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.1/24 -k /usr/src/linux-headers-6.14.0-fab/ -m homa", check=False)
    print(f"  [reload] {server} took {time.time()-t0:.1f}s", flush=True)
    t0 = time.time()
    ssh(client, "homa-load")
    ssh(client, "/root/SMT-NG/smt-apps/util/config_unloaded -i ens1f1np1 -a 192.168.12.2/24 -k /usr/src/linux-headers-6.14.0-fab/ -m homa", check=False)
    print(f"  [reload] {client} took {time.time()-t0:.1f}s", flush=True)
    print("  reload done", flush=True)

def run_bench(server, client, proto, msg_len, duration):
    server_cmd = f"stdbuf -oL /root/SMT-NG/smt-apps/unloaded/simple_server --proto {proto} -p 2000 -l {msg_len}"
    client_cmd = (f"/root/SMT-NG/smt-apps/unloaded/simple_client --proto {proto} "
                  f"-a 192.168.12.1 -p 2000 -n 500000 -l {msg_len}")

    print(f"  starting {proto} server (len={msg_len})...", end=" ", flush=True)
    print(f"  [server cmd] {server_cmd}", flush=True)
    server_proc = subprocess.Popen(
        ["ssh", "-o", "StrictHostKeyChecking=no", server, server_cmd],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # wait for SERVER CONFIG (stderr merged into stdout via STDOUT redirect)
    deadline = time.time() + 5
    while time.time() < deadline:
        line = server_proc.stdout.readline()
        print(f"  [server] {line.rstrip()}", flush=True)
        if "SERVER CONFIG" in line:
            break
    else:
        print("TIMEOUT waiting for SERVER CONFIG", file=sys.stderr)
    print("up")

    print(f"  running {proto} client ({duration}s)...", end=" ", flush=True)
    print(f"  [client cmd] {client_cmd}", flush=True)
    t0 = time.time()
    result = ssh(client, client_cmd, check=False)
    elapsed = time.time() - t0
    print(f"  [client] finished in {elapsed:.1f}s, exit={result.returncode}", flush=True)

    ssh(server, "pkill -f simple_server", check=False, silent=True)
    server_proc.wait()
    print(f"  [server] terminated", flush=True)

    # parse RESULT block
    stats = {}
    in_result = False
    for line in result.stdout.splitlines():
        if "RESULT" in line:
            in_result = not in_result
            continue
        if in_result:
            m = re.search(r'"(\w+)":\s*([\d.]+)', line)
            if m:
                stats[m.group(1)] = float(m.group(2))

    if not stats:
        print(f"\n  WARNING: no RESULT parsed. client stderr:")
        for line in result.stderr.splitlines():
            print(f"    {line}")
    else:
        print(f"done  ({stats.get('kops_per_second', 0):.1f} kops/s, "
              f"{stats.get('average_rtt_us', 0):.2f} µs avg RTT, "
              f"{stats.get('total_rpcs', 0):,.0f} RPCs)")
    return stats


# ── Comparison table ───────────────────────────────────────────────────────────


W = 80

def stamp(name, key, m, rpcs):
    cy    = m.get(f'{key}_cycles', 0)
    calls = m.get(f'{key}_calls', 0)
    cy_rpc = cy / rpcs if rpcs else 0
    ns_rpc = cy_rpc / (CPU_MHZ / 1000)
    print(f"  {name:<36} {calls:>15,} calls  {cy_rpc:>8.0f} cy  {ns_rpc:>7.0f} ns")

def section(label, name, key, hm, h_rpcs, sm, s_rpcs):
    hcy = hm.get(f'{key}_cycles', 0); hcalls = hm.get(f'{key}_calls', 0)
    scy = sm.get(f'{key}_cycles', 0); scalls = sm.get(f'{key}_calls', 0)
    h_cy_rpc = hcy / h_rpcs if h_rpcs else 0; h_ns = h_cy_rpc / (CPU_MHZ / 1000)
    s_cy_rpc = scy / s_rpcs if s_rpcs else 0; s_ns = s_cy_rpc / (CPU_MHZ / 1000)
    delta = s_ns - h_ns
    print(f"  [{label}]")
    print(f"  Homa: {name:<36} {hcalls:>15,} calls  {h_cy_rpc:>8.0f} cy  {h_ns:>7.0f} ns")
    print(f"  SMT:  {name:<36} {scalls:>15,} calls  {s_cy_rpc:>8.0f} cy  {s_ns:>7.0f} ns  ({delta:+.0f} ns)")

def generic_row(label, key, hm, h_rpcs, sm, s_rpcs):
    hcy = hm.get(f'{key}_cycles', 0); hcalls = hm.get(f'{key}_calls', 0)
    scy = sm.get(f'{key}_cycles', 0); scalls = sm.get(f'{key}_calls', 0)
    h_ns = (hcy / h_rpcs if h_rpcs else 0) / (CPU_MHZ / 1000)
    s_ns = (scy / s_rpcs if s_rpcs else 0) / (CPU_MHZ / 1000)
    delta = s_ns - h_ns
    print(f"  {label:<28}  Homa: {hcalls:>12,} calls  {h_ns:>7.0f} ns"
          f"    SMT: {scalls:>12,} calls  {s_ns:>7.0f} ns  ({delta:+.0f} ns)")

def count_row(label, key, hm, h_rpcs, sm, s_rpcs):
    hv = hm.get(key, 0); sv = sm.get(key, 0)
    h_per = hv / h_rpcs if h_rpcs else 0
    s_per = sv / s_rpcs if s_rpcs else 0
    delta = s_per - h_per
    print(f"  {label:<28}  Homa: {hv:>12,} total  {h_per:>7.2f}/rpc"
          f"    SMT: {sv:>12,} total  {s_per:>7.2f}/rpc  ({delta:+.2f}/rpc)")

def smt_stamp(name, key, m, rpcs):
    cy    = m.get(f'{key}_cycles', 0)
    calls = m.get(f'{key}_calls', 0)
    cy_rpc = cy / rpcs if rpcs else 0
    ns_rpc = cy_rpc / (CPU_MHZ / 1000)
    print(f"    {name:<32} {calls:>12,} calls  {cy_rpc:>8.0f} cy  {ns_rpc:>7.0f} ns")

def smt_count(name, key, m, rpcs):
    v = m.get(key, 0)
    per = v / rpcs if rpcs else 0
    print(f"    {name:<32} {v:>12,} total  {per:>7.2f}/rpc")

def print_smt_breakdown(ss, sc):
    s_rpcs   = ss.get('server_responses_done', 0)
    s_rpcs_c = sc.get('client_requests_done', 0)

    print()
    print("SMT BREAKDOWN (SMT run only)")
    print("=" * W)

    if s_rpcs:
        print(f"SERVER — {s_rpcs:,} SMT RPCs")
        print("-" * W)
        smt_stamp('smt_calc_rx_logical_info',  'smt_rx_calc',          ss, s_rpcs)
        smt_stamp('smt_record_complete',       'smt_record_complete',  ss, s_rpcs)
        smt_count('  returned true',           'smt_record_complete_true', ss, s_rpcs)
        smt_stamp('smt_rpc_ctx_init',          'smt_ctx_init',         ss, s_rpcs)
        smt_stamp('  smt_ctx_query',           'smt_ctx_query',        ss, s_rpcs)
        smt_stamp('  smt_ctx_clone',           'smt_ctx_clone',        ss, s_rpcs)
        smt_stamp('  dst_mtu',                 'smt_ctx_dst_mtu',      ss, s_rpcs)

    if s_rpcs_c:
        print()
        print(f"CLIENT — {s_rpcs_c:,} SMT RPCs")
        print("-" * W)
        smt_stamp('smt_calc_rx_logical_info',  'smt_rx_calc',          sc, s_rpcs_c)
        smt_stamp('smt_record_complete',       'smt_record_complete',  sc, s_rpcs_c)
        smt_count('  returned true',           'smt_record_complete_true', sc, s_rpcs_c)
        smt_stamp('smt_rpc_ctx_init',          'smt_ctx_init',         sc, s_rpcs_c)
        smt_stamp('  smt_ctx_query',           'smt_ctx_query',        sc, s_rpcs_c)
        smt_stamp('  smt_ctx_clone',           'smt_ctx_clone',        sc, s_rpcs_c)
        smt_stamp('  dst_mtu',                 'smt_ctx_dst_mtu',      sc, s_rpcs_c)
    print()

def print_generic_table(hs, ss, hc, sc):
    h_rpcs   = hs.get('server_responses_done', 0)
    s_rpcs   = ss.get('server_responses_done', 0)
    h_rpcs_c = hc.get('client_requests_done', 0)
    s_rpcs_c = sc.get('client_requests_done', 0)

    print()
    print(f"GENERIC METRICS")
    print("=" * W)
    print(f"SERVER — {h_rpcs:,} Homa RPCs  /  {s_rpcs:,} SMT RPCs")
    print("-" * W)
    generic_row('softirq',         'softirq',         hs, h_rpcs, ss, s_rpcs)
    generic_row('bypass_softirq',  'bypass_softirq',  hs, h_rpcs, ss, s_rpcs)
    count_row('gro_data_bypasses', 'gro_data_bypasses', hs, h_rpcs, ss, s_rpcs)
    generic_row('recvmsg',         'recv',             hs, h_rpcs, ss, s_rpcs)
    generic_row('reply sendmsg',   'reply',            hs, h_rpcs, ss, s_rpcs)

    print()
    print(f"CLIENT — {h_rpcs_c:,} Homa RPCs  /  {s_rpcs_c:,} SMT RPCs")
    print("-" * W)
    generic_row('sendmsg',         'send',             hc, h_rpcs_c, sc, s_rpcs_c)
    generic_row('softirq',         'softirq',          hc, h_rpcs_c, sc, s_rpcs_c)
    generic_row('bypass_softirq',  'bypass_softirq',   hc, h_rpcs_c, sc, s_rpcs_c)
    count_row('gro_data_bypasses', 'gro_data_bypasses', hc, h_rpcs_c, sc, s_rpcs_c)
    generic_row('recvmsg',         'recv',             hc, h_rpcs_c, sc, s_rpcs_c)
    generic_row('poll',            'poll',             hc, h_rpcs_c, sc, s_rpcs_c)
    generic_row('blocked',         'blocked',          hc, h_rpcs_c, sc, s_rpcs_c)
    print()

def print_comparison(hs, ss, hc, sc):
    h_rpcs   = hs.get('server_responses_done', 0)
    s_rpcs   = ss.get('server_responses_done', 0)
    h_rpcs_c = hc.get('client_requests_done', 0)
    s_rpcs_c = sc.get('client_requests_done', 0)

    print()
    print(f"{'':44} {'calls':>15}  {'cy/RPC':>8}  {'ns/RPC':>7}")
    print(f"SERVER — {h_rpcs:,} Homa RPCs  /  {s_rpcs:,} SMT RPCs")
    print("-" * W)
    section('RX: dispatch request',     'homa_dispatch_pkts',    'homa_dispatch_pkts',    hs, h_rpcs, ss, s_rpcs)
    section('RX: copy request to user', 'homa_copy_to_user',     'homa_copy_to_user',     hs, h_rpcs, ss, s_rpcs)
    section('TX: send response',        'homa_message_out_fill', 'homa_message_out_fill', hs, h_rpcs, ss, s_rpcs)

    print()
    print(f"CLIENT — {h_rpcs_c:,} Homa RPCs  /  {s_rpcs_c:,} SMT RPCs")
    print("-" * W)
    section('TX: alloc RPC',              'homa_rpc_alloc_client', 'homa_rpc_alloc_client', hc, h_rpcs_c, sc, s_rpcs_c)
    section('TX: fill & send request',    'homa_message_out_fill', 'homa_message_out_fill', hc, h_rpcs_c, sc, s_rpcs_c)
    section('RX: dispatch response',      'homa_dispatch_pkts',    'homa_dispatch_pkts',    hc, h_rpcs_c, sc, s_rpcs_c)
    section('RX: copy response to user',  'homa_copy_to_user',     'homa_copy_to_user',     hc, h_rpcs_c, sc, s_rpcs_c)
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--files', nargs=4,
                   metavar=('HOMA_SRV', 'SMT_SRV', 'HOMA_CLI', 'SMT_CLI'),
                   help='compare from pre-saved metric files')
    p.add_argument('server', nargs='?', help='server node hostname')
    p.add_argument('client', nargs='?', help='client node hostname')
    p.add_argument('-l', '--len', type=int, default=64, dest='msg_len',
                   help='message length in bytes (default: 64)')
    p.add_argument('-d', '--duration', type=int, default=8,
                   help='bench duration in seconds (default: 8)')
    args = p.parse_args()

    if args.files:
        print(f"  [files] {args.files}", flush=True)
        hs, ss, hc, sc = [load_file(f) for f in args.files]
    elif args.server and args.client:
        srv, cli = args.server, args.client
        print(f"  [config] server={srv}  client={cli}  len={args.msg_len}  duration={args.duration}s"
              f"  cpu_mhz={CPU_MHZ}", flush=True)

        print(f"\n[Homa bench — len={args.msg_len}, duration={args.duration}s]")
        reload_module(srv, cli)
        h_stats = run_bench(srv, cli, 'homa', args.msg_len, args.duration)
        print(f"  fetching metrics from {srv} and {cli}...", end=" ", flush=True)
        hs = fetch_metrics(srv)
        hc = fetch_metrics(cli)
        print("done")

        print(f"\n[SMT bench — len={args.msg_len}, duration={args.duration}s]")
        reload_module(srv, cli)
        s_stats = run_bench(srv, cli, 'smt', args.msg_len, args.duration)
        print(f"  fetching metrics from {srv} and {cli}...", end=" ", flush=True)
        ss = fetch_metrics(srv)
        sc = fetch_metrics(cli)
        print("done")

        print(f"\n  Homa: {h_stats.get('kops_per_second',0):.2f} kops/s  "
              f"{h_stats.get('average_rtt_us',0):.2f} µs avg  "
              f"p99={h_stats.get('p99_rtt_us',0):.2f} µs")
        print(f"  SMT:  {s_stats.get('kops_per_second',0):.2f} kops/s  "
              f"{s_stats.get('average_rtt_us',0):.2f} µs avg  "
              f"p99={s_stats.get('p99_rtt_us',0):.2f} µs  "
              f"(Δ avg {s_stats.get('average_rtt_us',0)-h_stats.get('average_rtt_us',0):+.2f} µs)")
    else:
        p.print_help()
        sys.exit(1)

    print_comparison(hs, ss, hc, sc)
    print_smt_breakdown(ss, sc)
    print_generic_table(hs, ss, hc, sc)


if __name__ == '__main__':
    main()
