SMT protocol traces
===================

SMT is a secure transport built on top of Homa. On the wire these are Homa
packets (IP protocol number 146). The DATA packets carry an encrypted payload;
the control packets do not.

Endpoints in all captures:
  server : 192.168.12.1  port 2000
  client : 192.168.12.2  (ephemeral source ports)

Files
-----
  smt_sw.pcap        Normal (encrypted) traffic. Exercises every SMT/Homa
                     packet type. The DATA payloads are encrypted.
  smt_nocrypto.pcap  Same traffic, but built with encryption turned off, so the
                     DATA payloads are in clear text. Useful for cross-checking
                     what the encrypted records contain. (Payload pattern is the
                     byte sequence 00 01 02 03 ...)
  smt_tso.pcap       A couple of large (20000-byte) messages, captured with TSO
                     enabled, so you can see how a large message looks both as a
                     single sender-side segmentation-offload frame and as the
                     individual packets that travel on the wire.

Crypto
------
AES-128-GCM. Per-direction keys (the side that SENDS a packet encrypts with its
own key):

  client key  : 8D D2 30 A7 7A 05 EB 71 15 91 29 BC BC F6 42 30
  client iv   : 87 C6 35 C8 17 87 DE 4A 88 1D D2 D5
  server key  : 6C CF 62 FF 4B E6 14 85 D8 BA 29 FE 2E 84 7A 7F
  server iv   : B9 FA 55 83 D5 8F 85 18 FF A6 3E 66

The record sequence number starts at 0 and increments by one per record, per
direction.
