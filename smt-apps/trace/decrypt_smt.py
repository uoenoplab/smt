#!/usr/bin/env python3
"""Reference decoder for SMT DATA records (TLS 1.2 AES-128-GCM over Homa).

Decrypts every DATA packet in an SMT pcap and verifies the GCM tag. Keys are
the hard-coded values from smt_uapi.c (the non-`alter` set, tls13=0). Works on
smt_sw.pcap; on smt_nocrypto.pcap the records are plaintext with 0xFF nonce/tag
so decryption is skipped (use --raw to just dump them).

Requires: pip install cryptography

Usage:
  python3 decrypt_smt.py smt_sw.pcap            # decrypt + verify all DATA records
  python3 decrypt_smt.py smt_sw.pcap -n 5       # show first 5 plaintexts
"""
import argparse
import struct
import sys

# Direction -> (16B AES-128 key, 4B salt). See smt_uapi.c:14-17.
# Client (src 192.168.12.2) encrypts with the client key; server (192.168.12.1)
# with the server key. Identify the sender by the IPv4 source address.
CLIENT_KEY = bytes.fromhex("8DD230A77A05EB71159129BCBCF64230")
CLIENT_SALT = bytes.fromhex("87C635C8")
SERVER_KEY = bytes.fromhex("6CCF62FF4BE61485D8BA29FE2E847A7F")
SERVER_SALT = bytes.fromhex("B9FA5583")

SERVER_IP = "192.168.12.1"   # whoever owns this IP is "the server" side
DATA = 0x10


def iter_pcap(path):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            raise SystemExit("not a classic little/big-endian pcap")
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        f.read(20)
        n = 0
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            _, _, caplen, _ = struct.unpack(endian + "IIII", hdr)
            n += 1
            yield n, f.read(caplen)


def smt_data_record(frame):
    """Return (src_ip, smt_h, ciphertext_plus_tag, record_len) for a DATA
    packet, or None. smt_h is the 13 wire bytes [17 03 03 | len(2) | seq(8)]."""
    if len(frame) < 14 + 20 or struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0f) * 4
    if frame[14 + 9] != 146:                       # IPPROTO_HOMA
        return None
    src = ".".join(map(str, frame[14 + 12:14 + 16]))
    homa = 14 + ihl
    if len(frame) < homa + 13 or frame[homa + 11] != DATA:
        return None
    body = frame[homa:]
    j = body.find(b"\x17\x03\x03")                 # locate the SMT/TLS record
    if j < 0:
        return None
    rec = body[j:]
    rlen = struct.unpack(">H", rec[3:5])[0]
    smt_h = rec[:13]
    ct_and_tag = rec[13:13 + rlen - 8]
    return src, smt_h, ct_and_tag, rlen


def decrypt(src, smt_h, ct_and_tag, rlen):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, salt = (SERVER_KEY, SERVER_SALT) if src == SERVER_IP else (CLIENT_KEY, CLIENT_SALT)
    seq = smt_h[5:13]                              # explicit nonce == TLS rec seq
    plaintext_len = rlen - 8 - 16
    aad = seq + b"\x17\x03\x03" + struct.pack(">H", plaintext_len)
    nonce = salt + seq
    return AESGCM(key).decrypt(nonce, ct_and_tag, aad)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("-n", type=int, default=0, help="print first N plaintexts")
    args = ap.parse_args()

    ok = bad = 0
    shown = 0
    for num, frame in iter_pcap(args.pcap):
        rec = smt_data_record(frame)
        if rec is None:
            continue
        src, smt_h, ct, rlen = rec
        if smt_h[5:13] == b"\xff" * 8:             # NOCRYPTO pcap: plaintext
            if shown < args.n:
                print("frame %d %s NOCRYPTO plaintext: %s" % (num, src, ct[:-16].hex(' ')))
                shown += 1
            ok += 1
            continue
        try:
            pt = decrypt(src, smt_h, ct, rlen)
            ok += 1
            if shown < args.n:
                print("frame %d %s -> %dB plaintext (seg_hdr+data): %s"
                      % (num, src, len(pt), pt[:32].hex(' ')))
                shown += 1
        except Exception as e:
            bad += 1
            print("frame %d %s DECRYPT FAIL: %s" % (num, src, type(e).__name__))
    print("DATA records: %d decrypted/verified, %d failed" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
