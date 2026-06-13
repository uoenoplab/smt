#!/usr/bin/env python3
"""Classify Homa/SMT packets in a pcap by the Homa common-header `type` byte.

Homa common header mimics a TCP header; `type` sits at offset 11 from the
start of the Homa header (right after the IPv4 header). See homa_wire.h.
"""
import struct
import sys
from collections import Counter, defaultdict

TYPES = {
    0x10: "DATA", 0x11: "GRANT", 0x12: "RESEND", 0x13: "RPC_UNKNOWN",
    0x14: "BUSY", 0x15: "CUTOFFS", 0x16: "FREEZE", 0x17: "NEED_ACK",
    0x18: "ACK", 0x19: "BOGUS",
}

def frames(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            le = magic == b"\xd4\xc3\xb2\xa1"
            endian = "<" if le else ">"
            f.read(20)  # rest of global header
            nano = False
        else:
            raise SystemExit("not a classic pcap (pcapng? use editcap)")
        n = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_s, ts_u, caplen, origlen = struct.unpack(endian + "IIII", hdr)
            data = f.read(caplen)
            n += 1
            yield n, ts_s + ts_u / 1e6, data

def parse(path, csv_out=None):
    counts = Counter()
    first = {}            # type -> first frame number
    examples = defaultdict(list)
    total = 0
    csv = open(csv_out, "w") if csv_out else None
    if csv:
        csv.write("frame,time_s,type,type_hex,src_ip,src_port,dst_ip,dst_port,frame_len\n")
    t0 = None
    for num, ts, data in frames(path):
        total += 1
        if t0 is None:
            t0 = ts
        if len(data) < 14 + 20:
            continue
        eth_type = struct.unpack(">H", data[12:14])[0]
        off = 14
        if eth_type == 0x8100:  # VLAN
            off += 4
            eth_type = struct.unpack(">H", data[off-2:off])[0]
        if eth_type != 0x0800:
            continue
        ihl = (data[off] & 0x0f) * 4
        proto = data[off + 9]
        if proto != 146:
            continue
        src = ".".join(map(str, data[off+12:off+16]))
        dst = ".".join(map(str, data[off+16:off+20]))
        homa = off + ihl
        if len(data) < homa + 13:
            continue
        sport, dport = struct.unpack(">HH", data[homa:homa+4])
        t = data[homa + 11]
        name = TYPES.get(t, "UNKNOWN_0x%02x" % t)
        counts[name] += 1
        if name not in first:
            first[name] = num
        if len(examples[name]) < 3:
            examples[name].append((num, "%s:%d->%s:%d" % (src, sport, dst, dport), len(data)))
        if csv:
            csv.write("%d,%.6f,%s,0x%02x,%s,%d,%s,%d,%d\n" %
                      (num, ts - t0, name, t, src, sport, dst, dport, len(data)))
    if csv:
        csv.close()
    return total, counts, first, examples

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "smt_sw.pcap"
    csv_out = None
    if "--csv" in sys.argv:
        csv_out = sys.argv[sys.argv.index("--csv") + 1]
    total, counts, first, examples = parse(path, csv_out)
    if csv_out:
        print("wrote per-frame index: %s" % csv_out)
    print("file: %s   total frames: %d" % (path, total))
    print("%-14s %8s %10s   examples (frame, 5-tuple, framelen)" % ("type", "count", "first#"))
    for name in sorted(counts, key=lambda k: counts[k], reverse=True):
        ex = "; ".join("#%d %s len=%d" % e for e in examples[name])
        print("%-14s %8d %10d   %s" % (name, counts[name], first[name], ex))
