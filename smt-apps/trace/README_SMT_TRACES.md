# SMT protocol traces — reference bundle for the tcpdump/Wireshark dissector

Two pcaps that together exercise **every SMT packet type**, plus the crypto key
material needed to interpret the encrypted payloads. Intended as the reference
input for an SMT dissector.

SMT is a secure transport built on **Homa**: the wire packets *are* Homa packets
(IP protocol **146**, `IPPROTO_HOMA`). Only **DATA** packets carry an encrypted
payload — it is framed as a **TLS 1.2 AES-128-GCM application_data record**.
All Homa control packets (GRANT, RESEND, …) are sent in the clear.

---

## 1. Files

| File | What it is |
|------|------------|
| `smt_sw.pcap`           | **Encrypted** trace (software crypto, real AES-128-GCM ciphertext + GCM tag). |
| `smt_nocrypto.pcap`     | **Plaintext** trace (`CONFIG_SMT_NOCRYPTO` build: identical framing, payload left in clear, nonce/tag are `0xFF` filler). |
| `smt_sw.index.csv`      | Per-frame index of `smt_sw.pcap`: `frame,time_s,type,type_hex,src,sport,dst,dport,len`. |
| `smt_nocrypto.index.csv`| Per-frame index of `smt_nocrypto.pcap`. |
| `classify.py`           | Tiny pcap classifier (no deps) that produced the indexes. |
| `README_SMT_TRACES.md`  | This file. |

The pre-existing `short_message.pcap` / `short_message.sh` are an older,
single-message SMT capture; kept for reference but superseded by the above.

---

## 2. Packet-type coverage

`type` is a single byte in the Homa common header (offset **+11**, see §4).

| Type | Hex | In `smt_sw.pcap` | In `smt_nocrypto.pcap` | Sent by |
|------|-----|------------------:|-----------------------:|---------|
| DATA        | `0x10` | 3910 | 3911 | both |
| GRANT       | `0x11` |   42 |   42 | receiver of a message |
| RESEND      | `0x12` |  729 |  751 | receiver (missing data) |
| RPC_UNKNOWN | `0x13` |    7 |   18 | either (packet for unknown RPC) |
| BUSY        | `0x14` |   55 |   56 | sender (in reply to RESEND, data not ready) |
| CUTOFFS     | `0x15` |    0 |    2 | sender (priority cutoffs at connection start) |
| NEED_ACK    | `0x17` |  115 |  149 | server (asks client to ACK a completed RPC) |
| ACK         | `0x18` |    8 |   20 | client (explicit acknowledgement) |

Every functional SMT type is present in **both** pcaps (CUTOFFS happened to fire
only in the nocrypto run; it is a normal Homa control packet with no payload).
To locate one of each quickly:

```bash
for t in DATA GRANT RESEND RPC_UNKNOWN BUSY CUTOFFS NEED_ACK ACK; do
  grep -m1 ",$t," smt_nocrypto.index.csv
done
```

---

## 3. Topology / 5-tuples

| Role | IP | Port | Notes |
|------|----|------|-------|
| Server | `192.168.12.1` | `2000` | runs `simple_server --proto smt` |
| Client | `192.168.12.2` | ephemeral (`32768`+) | runs `simple_client --proto smt` |

Homa is connectionless; an SMT *crypto context* is keyed by the peer 5-tuple, but
**which key encrypts a record depends on the sender, not the 5-tuple**:

* packets with **src `192.168.12.2`** (client → server)  → encrypted with the **client key**
* packets with **src `192.168.12.1`** (server → client)  → encrypted with the **server key**

---

## 4. Wire format

### 4.1 Encapsulation

```
Ethernet (14B) | IPv4 (20B, proto=146) | Homa header | [DATA only: SMT record]
```

### 4.2 Homa common header (mirrors a TCP header; offsets from start of Homa hdr)

| Off | Size | Field | Notes |
|----:|-----:|-------|-------|
| 0  | 2 | sport            | source Homa port |
| 2  | 2 | dport            | dest Homa port |
| 4  | 4 | sequence         | DATA: byte offset of first data byte |
| 8  | 3 | ack              | unused (TCP ack high bytes) |
| **11** | **1** | **type** | **packet type — table in §2** |
| 12 | 1 | doff             | DATA: homa_data_hdr length in 4-byte chunks; else 5 |
| 13 | 1 | flags            | TCP flags slot (unused) |
| 14 | 2 | window           | unused |
| 16 | 2 | checksum         | unused unless TCP hijacking |
| 18 | 2 | urgent           | carries `0xb97d` (`HOMA_HIJACK_URGENT`) on the wire |

Full definitions: `homa_wire.h` (`struct homa_common_hdr`, `enum homa_packet_type`,
and the per-type `homa_*_hdr` structs for GRANT/RESEND/ACK/…).

### 4.3 SMT record (DATA packets only)

After the Homa DATA + segment headers, the payload is one TLS-1.2-style
AES-128-GCM record. The 13-byte record header is what the code calls `smt_h`
(`SMT_RECORD_EXTRA_PRE_LENGTH = 13`), the trailer is the 16-byte tag
(`SMT_RECORD_EXTRA_POST_LENGTH = 16`):

```
+-------------------- smt_h (13 bytes) --------------------+----------- ... ----+--- 16B ---+
| 17 | 03 03 | len(2B, big-endian) | explicit_nonce (8B)   | ciphertext         |  GCM tag  |
+-----+------+---------------------+-----------------------+--------------------+-----------+
  ^      ^            ^                      ^
  |      |            |                      record sequence number, big-endian,
  |      |            |                      starts at 0 and +1 per record (this is also
  |      |            |                      the per-record part of the GCM nonce)
  |      |            on-wire record length = explicit_nonce(8) + ciphertext + tag(16)
  |      TLS version 1.2 (0x0303)
  TLS record type 0x17 = application_data
```

`explicit_nonce` on the wire equals the TLS **record sequence number** (8B,
big-endian), starting at 0 and incrementing by 1 per record **per direction**.

Observed first DATA record (`smt_sw.pcap` frame 1), bytes from `17 03 03`:

```
17 03 03 00 5c  00 00 00 00 00 00 00 00  69 a5 9a 0b 2b 67 c9 70 ...  <random 16B tag>
└── TLS hdr ──┘ └─ explicit nonce (seq0) ┘ └────────── ciphertext ──────────┘
```

**Control packets (GRANT/RESEND/BUSY/…) contain no SMT record** — verify by
grepping: they never contain the `17 03 03` marker.

### 4.4 NOCRYPTO trace differences

`smt_nocrypto.pcap` is byte-for-byte the same framing, but the crypto step is
skipped (`CONFIG_SMT_NOCRYPTO`):

* explicit nonce (8B) = `FF FF FF FF FF FF FF FF`
* payload = **plaintext** (captured with `HOMA_ECHO_PAYLOAD=mod`, i.e. bytes
  `00 01 02 03 …`, so record boundaries are obvious)
* GCM tag (16B) = `FF × 16`

Same first DATA record in `smt_nocrypto.pcap` frame 1:

```
17 03 03 00 5c  ff ff ff ff ff ff ff ff  00 01 02 03 04 05 06 07 ...  ff ff ...(16)
└── TLS hdr ──┘ └──── nonce = 0xFF ─────┘ └──── plaintext payload ───┘ └─ tag=0xFF ─┘
```

Use this trace to validate record/field parsing without needing to decrypt.

---

## 5. Keys (AES-128-GCM, TLS 1.2 framing)

Hard-coded in `smt_uapi.c` (lines 14–17, the non-`alter` set; the apps call the
helper with `tls13 = 0`). AES-128-GCM ⇒ key = 16B, salt = 4B, rec_seq/nonce
start at 0.

```
client key   (16B) : 8D D2 30 A7 7A 05 EB 71 15 91 29 BC BC F6 42 30
client salt  (4B)  : 87 C6 35 C8            # first 4 bytes of client_iv_hardcode
server key   (16B) : 6C CF 62 FF 4B E6 14 85 D8 BA 29 FE 2E 84 7A 7F
server salt  (4B)  : B9 FA 55 83            # first 4 bytes of server_iv_hardcode
initial rec_seq    : 00 00 00 00 00 00 00 00   (increments by 1 per record)
```

To decrypt a record (only if you want to; a dissector does not need to). This
is **standard TLS 1.2 AES-128-GCM**, verified against all 3910 DATA records in
`smt_sw.pcap`:

* **key** — chosen by sender direction (§3): client key for src `192.168.12.2`,
  server key for src `192.168.12.1`.
* **12-byte GCM nonce** = `salt (4B)` ‖ `explicit_nonce (8B read from the wire)`.
* **ciphertext+tag** = the `record_len − 8` bytes immediately after the 13-byte
  `smt_h` (i.e. skip the 8-byte explicit nonce); the last 16 bytes are the tag.
* **AAD** = the standard TLS 1.2 `additional_data`, reconstructed (NOT the bytes
  as laid out on the wire):
  `seq_num (8B = explicit_nonce)` ‖ `0x17` ‖ `0x0303` ‖ `plaintext_len (2B BE)`
  where `plaintext_len = record_len − 8 − 16`.
* The decrypted plaintext is `homa_seg_hdr(s) + segment data`, not bare payload.

A ready-to-run reference decoder is included: **`decrypt_smt.py`** (needs the
`cryptography` package) decrypts every DATA record in a pcap and verifies the
GCM tag on each. Wireshark's built-in TLS dissector will **not** decrypt these (the framing
is TLS-record-shaped but rides on Homa, with no TLS handshake) — use
`decrypt_smt.py`, or just read `smt_nocrypto.pcap` for plaintext structure.

(An alternate key set — `*_hardcode_alter` in `smt_uapi.c` — exists but was **not**
used for these captures.)

---

## 6. Reproducing / regenerating

Captured on the duck testbed, both nodes kernel `6.17.8-mainline-fab`, NIC
`ens1f1np1`:

1. Build + load: `make all` (encrypted) or `make all SMT_CFLAGS=-DCONFIG_SMT_NOCRYPTO`
   (plaintext), then `config_unloaded -i ens1f1np1 -a <ip>/24 -m smt-sw` on both.
2. For clean per-packet captures (no TSO super-frames, control packets visible):
   ```
   sysctl net.homa.gro_policy=0        # disable Homa GRO coalescing
   sysctl net.homa.max_gso_size=1400   # one segment per DATA packet
   ethtool -K ens1f1np1 tso off gso off gro off lro off
   ```
3. `tcpdump -i ens1f1np1 -s0 -w out.pcap 'ip proto 146'` on the server.
4. Drive traffic with `simple_server`/`simple_client --proto smt` over sizes
   64 / 2000 / 100000 B; to force RESEND/BUSY/RPC_UNKNOWN/NEED_ACK/ACK, add
   `tc qdisc replace dev ens1f1np1 root netem loss 25%` on **both** nodes during a
   second pass.

Re-run the classifier any time:

```bash
python3 classify.py smt_sw.pcap                       # summary table
python3 classify.py smt_sw.pcap --csv smt_sw.index.csv # per-frame index
```
