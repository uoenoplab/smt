#!/usr/bin/env python3
# Pivot bench_results.csv into mode x size table of avg_rtt_us.
# Usage: ./pivot_avg_rtt.py [input.csv] [output.csv]
import csv, sys

inp = sys.argv[1] if len(sys.argv) > 1 else 'bench_results.csv'
out = sys.argv[2] if len(sys.argv) > 2 else 'avg_rtt_pivot.csv'

rows = list(csv.DictReader(open(inp)))
modes, sizes = [], []
for r in rows:
    if r['mode'] not in modes: modes.append(r['mode'])
    if r['size'] not in sizes: sizes.append(r['size'])
sizes.sort(key=int)

with open(out, 'w') as f:
    f.write('mode,' + ','.join(sizes) + '\n')
    for m in modes:
        vals = {r['size']: r['avg_rtt_us'] for r in rows if r['mode'] == m}
        f.write(m + ',' + ','.join(vals.get(s, 'NA') for s in sizes) + '\n')

print(open(out).read(), end='')
