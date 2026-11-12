# SMT-NG design

This file describes the key interface, the wire format and the security properties of SMT-NG. The [README](README.md) has the build, the quick start and the evaluation.

## SMT APIs

A socket encrypts the traffic with a peer when it has keys for that peer.
A socket with keys refuses RPCs with a peer that has none: sendmsg fails
with ENOKEY, and the requests of that peer are dropped. A socket without
keys talks plain Homa. The two ends must use the same keys, the same TLS
version and the same build switches. An application gets the keys of a
peer from a handshake. For debugging, a built-in key can replace them:

1. **No handshake (debugging and benchmarks only)**:
   `setsockopt(fd, SOL_TLS, SMT_DEBUG_FIXED_KEY, &info, sizeof(info))`,
   with a `struct tls_crypto_info` of the kernel: `TLS_1_2_VERSION` or
   `TLS_1_3_VERSION`, and `TLS_CIPHER_AES_GCM_128` or `_256`. The socket
   then uses a built-in key for all peers that have no key of their own, in
   both directions. The key is in the source, so it protects nothing. The
   host must allow it with `sudo sysctl net.homa.debug_only_smt_fixed_key=1`,
   or the setsockopt fails with EPERM. Both ends must use the same version
   and cipher. A socket keeps the version and the cipher of its built-in
   key: another one fails with EINVAL.
2. **setsockopt** with the keys from a handshake, as for kTLS:
   `setsockopt(fd, SOL_TLS, TLS_TX or TLS_RX, &info, sizeof(info))`, with
   `struct smt_aes_gcm_128_info` or `smt_aes_gcm_256_info` from
   [smt_uapi.h](smt_uapi.h). This struct holds the IPv4 address and the Homa
   port of the peer (network order). SMT refuses a peer of 0/0 (EINVAL),
   also for `SMT_KEY_DEL`. Then comes the
   `tls12_crypto_info_aes_gcm_128` or `_256` of the kernel, with
   `TLS_1_2_VERSION` or `TLS_1_3_VERSION`. Set both directions for a peer.
   For TLS 1.2, `iv` must be equal to `rec_seq`.
   - A second key for a direction replaces the first. New RPCs use the new
     key, and the RPCs that already use the old key finish with it. A new
     RX key starts a new replay window.
   - `setsockopt(fd, SOL_TLS, SMT_KEY_DEL, &peer, sizeof(peer))`, with a
     `struct smt_info`, deletes the keys of a peer (ENOENT if it has none).
   - `net.homa.smt_key_idle_secs` deletes the keys of a peer after that
     many seconds without an RPC (counted from the install for keys that
     no RPC used).
   - The two ends replace keys independently. An RPC that crosses a
     replacement fails with EBADMSG, and the application retries it.
   - TODO: key replacement that does not fail RPCs. The packet header
     will carry a key id, and the receiver will keep the current and the
     next RX key. Then the two ends do not have to replace keys at the
     same time. Until then, the application manages the replacement.
3. **Handshake**: a minimal proof of concept in
   [smt-apps/handshake-c](smt-apps/handshake-c) (C, OpenSSL), and the
   `--handshake` option of the Go (crypto/tls) and Rust (rustls) `unloaded`
   programs. Homa RPCs to a server port without keys carry a TLS 1.3
   handshake. There are two RPCs. The first carries the ClientHello. The
   second carries the last flight of the client and its Homa port as TLS
   application data. The client checks the certificate of the server. The
   server checks the certificate of the client if the client presents one,
   or if the server requires one. The two ends derive the keys with the TLS
   exporter (RFC 8446 §7.5, label `EXPORTER-SMT-NG keys`). Each end installs
   them with setsockopt for that peer only. Any TLS library with the
   exporter can do this: `SSL_export_keying_material` (OpenSSL),
   `ConnectionState.ExportKeyingMaterial` (Go), `export_keying_material`
   (rustls).

## On the wire

The animation at the top of the [README](README.md) shows these steps. `uv run smt-apps/figures/smt-wire.py`
draws it with real AES-GCM bytes. For an interactive version of steps 2 to
9, open [smt-apps/figures/smt-wire.html](smt-apps/figures/smt-wire.html) in a browser. You can
change the RPC id, the record, the direction and the TLS version, or change
a packet on the wire.

- SMT changes only the DATA packets of Homa. The control packets (GRANT,
  RESEND, ACK and others) stay plain Homa.
- SMT cuts each message into records. A record fills whole segments: at
  most 20 segments, 16 KB of data and `net.homa.smt_record_segs` segments,
  if set. All records of a message hold the same number of bytes, except
  the last one. A TSO/GSO packet (at most `max_gso_size` bytes) carries as
  many whole records as fit.
- A record is a TLS record: the TLS header (`17 03 03`, length), the
  explicit nonce (TLS 1.2 only), the encrypted segments, the content type
  (TLS 1.3 only, encrypted) and the 16-byte tag. Each segment keeps its
  4-byte `homa_seg_hdr` inside the ciphertext.
- Record *i* of a message has the sequence number
  (RPC id ≫ 1) ≪ 17 | response bit ≪ 16 | *i*. The record index *i* has
  16 bits: a message has fewer than 2^16 records. The nonce is
  salt ‖ (iv XOR sequence number). The AAD is the TLS header (TLS 1.2: the
  sequence number, then the header).
- TSO/GSO cuts the packet into segments and copies the Homa header into
  each segment. The IP id counts the segments of the packet. The `pad` and
  `sequence` fields of the Homa header hold the offset of the first record
  in the message, and `reserved1` holds the number of segments in each
  record. A sender that leaves `reserved1` at 0 puts one record in each
  packet.
- The receiver finds the record and the position of each segment from the
  IP id, `reserved1` and `pad`. It puts the segments of a record together,
  then it authenticates and decrypts the whole record. If a record fails
  authentication, its RPC fails, and recvmsg returns EBADMSG.
- A retransmitted record is the same byte for byte, because its header and
  its nonce come from the record index.

## Security design

- AES-GCM seals each record. This gives confidentiality and integrity to the
  message data. The control packets of Homa (GRANT, RESEND, ACK and others)
  are not encrypted and not authenticated. They carry no application data.
- The nonces under a key are unique if the key serves one peer and the RPC
  ids of that peer do not repeat. All peers share the built-in key of
  `SMT_DEBUG_FIXED_KEY`, so that key is for debugging and benchmarks only.
- Replay guard: a server drops a request for an RPC that it authenticated
  before. It keeps a window of the last 65536 RPCs of each peer.
- A socket finds the keys of a peer by the IPv4 address and the Homa port of
  the peer. A socket that has keys refuses a peer without keys. A socket
  without keys talks plain Homa, and the application cannot see the
  difference.
- The handshake servers install the keys for the address that the RPCs come
  from and for the port that the client gives. A client that the server
  accepts can give any port on its host.
- Rekeying: an application replaces or deletes keys with setsockopt. There
  is no key update inside the protocol. The two ends coordinate, for
  example with a new handshake. `handshake-c` ends with a bye over SMT:
  the server deletes the keys of the client, and the client deletes its
  own. The handshake servers of the Go and Rust programs also accept the
  bye.
