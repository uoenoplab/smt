# /// script
# dependencies = ["cryptography"]
# ///
"""Draw figures/smt-wire.svg: how SMT protects a Homa message, as an animated
SVG (CSS keyframes, no script) that plays in a README. The client and the
server set up the keys in user space, then the client sends one message and
the server receives it.

    uv run figures/smt-wire.py

The handshake is the one of smt-apps/handshake-c. The bytes are real:
AES-GCM with the fixed client key of smt_uapi.c, the record layout of
smt_outgoing.c and the sequence number of smt_impl.h. Example: RPC id
0x1f2a4c6e, record 1 of 3, request, TLS 1.2. Sizes are shrunk to fit: a
segment holds 16 message bytes.
"""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smt-wire.svg")
T = 75.0  # seconds in one loop
END = T - 1.4  # everything fades out from here
STILL = 46.6  # the frame shown when the viewer asks for reduced motion
EASE = "cubic-bezier(.2,.8,.2,1)"
W, Y0, SH = 1200, 128, 740  # width, top of the stage, height of the stage
H = Y0 + SH + 46

# ---------------------------------------------------------------- the bytes
SEG, NSEG, NREC, REC_I = 16, 3, 3, 1
REC = SEG * NSEG
TEXT = ('POST /pay {"from":"acct-1021","to":"acct-7731","cents":25000,"memo":"October rent",'
        '"ts":1793050320,"ref":"inv-88214"}' + " " * 200)[:REC * NREC]
RPC, RESP = 0x1F2A4C6E, 0
KEY = bytes.fromhex("8dd230a77a05eb71159129bcbcf64230")
SALT = bytes.fromhex("87c635c8")  # the first 4 bytes of the client iv
SEQ = (((RPC & ((1 << 48) - 1)) >> 1) << 17) | (RESP << 16) | REC_I
NONCE = SALT + SEQ.to_bytes(8, "big")
segs = [((REC_I * REC + s * SEG).to_bytes(4, "big"), TEXT[REC_I * REC + s * SEG:][:SEG].encode()) for s in range(NSEG)]
PT = b"".join(h + d for h, d in segs)
TLS_LEN = 8 + len(PT) + 16
TLS_HDR = bytes([0x17, 3, 3]) + TLS_LEN.to_bytes(2, "big")
AAD = SEQ.to_bytes(8, "big") + bytes([0x17, 3, 3]) + len(PT).to_bytes(2, "big")
SEALED = AESGCM(KEY).encrypt(NONCE, PT, AAD)
assert AESGCM(KEY).decrypt(NONCE, SEALED, AAD) == PT
CT, TAG = SEALED[:-16], SEALED[-16:]


def hx(b, sep=" "):
    return sep.join(f"{x:02x}" for x in b)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def asc(b):
    return esc('"' + b.decode() + '"')


NOISE = [bytes((a * 37 + b * 101 + 13) % 256 for b in range(16)) for a in range(4)]  # flicker frames

# ---------------------------------------------------------- the animation
css, body, boxes, texts = [], [], [], []
ORIGIN = 0.0  # the times given to go(), layer() and show() count from here


def pct(t):
    return f"{100 * t / T:.3f}".rstrip("0").rstrip(".") + "%"


def keyframes(name, frames, sel=None):
    """frames: [(t, declarations)] in time order. Before the first frame and
    after the last, the element keeps that frame."""
    assert all(a[0] <= b[0] for a, b in zip(frames, frames[1:])), name
    frames = [(0, frames[0][1])] + frames + [(T, frames[-1][1])]
    kf = {}
    for t, v in frames:
        kf[pct(t)] = v  # a later frame at the same time wins
    css.append(f"@keyframes {name}{{{''.join(f'{p}{{{v}}}' for p, v in kf.items())}}}{sel or '#' + name}{{animation-name:{name}}}")


class Box:
    """A box that moves, fades and changes width. Its layers (a rect and its
    texts each) cross-fade, for example from plaintext to ciphertext."""

    def __init__(self, x, y, w, h, layers, op=0, w0=None, rx=4):
        self.id = f"b{len(boxes)}"
        self.h, self.rx, self.w0 = h, rx, w0 or w
        self.layers = layers  # {name: (rect class, [(text, class, dy)])}; the first one shows first
        self.st = [(0.0, dict(x=x, y=y, w=w, op=op))]
        self.lay = [(0.0, next(iter(layers)), 0.0)]
        self.linear = set()  # start times of the moves at constant speed
        boxes.append(self)

    def go(self, t0, t1, lin=False, **kw):
        t0, t1 = t0 + ORIGIN, t1 + ORIGIN
        cur = dict(self.st[-1][1])
        assert t0 >= self.st[-1][0], (self.id, t0)
        if t0 > self.st[-1][0]:
            self.st.append((t0, cur))
        self.st.append((t1, dict(cur, **kw)))
        if lin:
            self.linear.add(t0)
        return self

    def now(self, k):
        return self.st[-1][1][k]

    def layer(self, t, name, d=0.3):
        t += ORIGIN
        assert t >= self.lay[-1][0], (self.id, t)
        self.lay.append((t, name, d))
        return self

    def flicker(self, t, final, noise=("f1", "f2")):
        for i, name in enumerate(noise + (final,)):
            self.layer(t + i * 0.08, name, 0.02)
        return self

    def _ops(self, name):
        fr = [(0.0, 1 if self.lay[0][1] == name else 0)]
        for t, b, d in self.lay[1:]:
            want = 1 if b == name else 0
            if want != fr[-1][1]:
                fr += [(t, fr[-1][1]), (t + d, want)]
        return fr

    def emit(self):
        i, st, w0 = self.id, self.st, self.w0
        lin = lambda t: ";animation-timing-function:linear" if t in self.linear else ""
        keyframes(i, [(t, f"transform:translate({s['x'] + s['w'] / 2:.1f}px,{s['y'] + Y0:.1f}px);opacity:{s['op']:g}{lin(t)}") for t, s in st])
        scaled = any(s["w"] != w0 for _, s in st)
        if scaled:
            keyframes(i + "-w", [(t, f"transform:scaleX({s['w'] / w0:.4f}){lin(t)}") for t, s in st])
        rects, txts = [], []
        for name, (rcls, tl) in self.layers.items():
            ops = self._ops(name)
            if not any(v for _, v in ops):
                continue
            c = ""
            if any(v != 1 for _, v in ops):
                c = f" {i}{name}"
                keyframes(f"{i}{name}", [(t, f"opacity:{v}") for t, v in ops], f".{i}{name}")
            rects.append(f'<rect class="{rcls}{c}" x="{-w0 / 2:g}" width="{w0:g}" height="{self.h}" rx="{self.rx}"/>')
            ink = {"k-ct": " w", "k-ok": " w", "k-banner": " w", "k-ghost": " g", "k-app": " n", "k-hs": " n"}.get(rcls, "")
            txts += [f'<text class="{cls}{ink}{c}" y="{self.h / 2 + dy:g}">{txt}</text>' for txt, cls, dy in tl]
        g = f'<g id="{i}-w" class="sc">' if scaled else "<g>"
        body.append(f'<g id="{i}">{g}{"".join(rects)}</g>{"".join(txts)}</g>')


class Text:
    """A text that fades in and out in place."""

    def __init__(self, x, y, markup, cls="mono"):
        self.id = f"t{len(texts)}"
        self.x, self.y, self.markup, self.cls = x, y, markup, cls
        self.fr = [(0.0, 0)]
        texts.append(self)

    def show(self, t0, t1=None, d=0.35):
        t0 += ORIGIN
        self.fr += [(t0, 0), (t0 + d, 1)] + ([(t1 + ORIGIN, 1), (t1 + ORIGIN + d, 0)] if t1 is not None else [])
        return self

    def emit(self):
        keyframes(self.id, [(t, f"opacity:{o}") for t, o in self.fr])
        body.append(f'<text id="{self.id}" class="{self.cls}" x="{self.x:g}" y="{self.y + Y0:g}">{self.markup}</text>')


def lbl(s):  # the name in a box, upper line
    return esc(s), "lb", -2


def sub(s):  # the bytes in a box, lower line
    return s, "hx", 11


def one(s):  # a box with one line
    return esc(s), "lb", 4


def hl(x, y, w, h, t0, t1, cls="hl"):  # a frame that lights up around a box
    return Box(x - 3, y - 3, w + 6, h + 6, {"h": (cls, [])}, rx=6).go(t0, t0 + 0.35, op=1).go(t1, t1 + 0.4, op=0)


# the start of each step, then the end of the loop
S = [0, 15, 19, 24, 30, 42, 49, 55, 61.5, END]
CAPTIONS = [
    ("Client and server agree on keys in user space and give them to Homa",
     "The applications run a TLS 1.3 handshake in Homa RPCs to port 4433 (smt-apps/handshake-c; a client certificate is optional).",
     "Each takes 56 bytes from the TLS exporter and installs them on its data socket for this peer: TX its own key, RX the peer's key."),
    ("The client calls sendmsg()",
     "The client application sends one message on its Homa data socket. SMT works under the socket API, so the application",
     "does not change."),
    ("SMT cuts the message into records",
     "A record holds up to max_gso_data bytes of the message. One record is one TSO/GSO packet, so the server can authenticate",
     "each record alone."),
    ("Each record becomes a TLS record",
     "Each segment keeps its 4-byte Homa segment header (the offset of its data in the message). A TLS header leads the record:",
     "17 03 03 and the length. TLS 1.2 adds an 8-byte explicit nonce."),
    ("The nonce comes from the RPC id and the record index",
     "seq = (RPC id >> 1) << 17 | response bit << 16 | record index (16 bits). The nonce is salt ‖ (iv XOR seq).",
     "No counter is shared between RPCs, so the records of different RPCs need no order."),
    ("AES-GCM seals the record with the client's TX key",
     "The AAD is the TLS header (TLS 1.2: the sequence number first). The keystream encrypts the segments, and the 16-byte",
     "tag protects the header and the ciphertext."),
    ("TSO/GSO cuts the record into packets",
     "Each packet repeats the Homa data header: pad and sequence hold the offset of the record, and the IP id counts the packets.",
     "Only the first packet carries the TLS header."),
    ("The packets cross the wire",
     "Packets can arrive in any order. Control packets (GRANT, ACK and others) stay plain Homa: they carry no message data."),
    ("The server authenticates and decrypts the whole record",
     "It places each packet by record offset and IP id, checks the tag with its RX key for this client, decrypts, drops the",
     "segment headers and gives the bytes to recvmsg(). If the tag does not match, the RPC fails with EBADMSG."),
]

# 1. the handshake in user space, over plain Homa; then each side installs its keys on its data socket
HS_END = S[1] - 0.4
GHOST = {}  # (side, TX or RX) → the empty key slot
for y_app, y_sock, side, peer, port in [(36, 134, "client", "server", "Homa, port P"), (678, 596, "server", "client", "Homa port 2000")]:
    Text(44, y_app + 32, "user space", "mono mut").show(0.2, HS_END)
    Text(44, y_sock + 30, "homa.ko", "mono mut").show(0.2, HS_END)
    Box(150, y_app, 220, 56, {"a": ("k-app", [lbl(f"{side} app"), sub("TLS: OpenSSL, Go, rustls")])}).go(0.2, 0.6, op=1).go(HS_END, HS_END + 0.4, op=0)
    hs_port = "Homa, any port" if side == "client" else "Homa port 4433, no keys"
    Box(150, y_sock, 220, 50, {"s": ("k-app", [lbl("handshake socket"), sub(hs_port)])}).go(0.3, 0.7, op=1).go(HS_END, HS_END + 0.4, op=0)
    Box(400, y_sock, 764, 50, {"s": ("k-app", [])}).go(0.4, 0.8, op=1).go(HS_END, HS_END + 0.4, op=0)
    Text(414, y_sock + 22, "data socket", "small b").show(0.4, HS_END)
    Text(414, y_sock + 40, port, "small mut").show(0.4, HS_END)
    for x, slot, arrow in [(556, "TX", "→"), (862, "RX", "←")]:
        name = f"{slot} {arrow} {peer}:{'2000' if side == 'client' else 'P'}"
        GHOST[side, slot] = Box(x, y_sock + 6, 296, 38, {"g": ("k-ghost", [one(name)])}).go(0.5, 0.9, op=1)


def hs_message(name, t, down):
    ys = [50, 144, 606, 690] if down else [690, 606, 144, 50]
    Box(150, ys[0], 220, 30, {"m": ("k-hs", [one(name)])}).go(t, t + 0.2, op=1).go(t + 0.2, t + 0.6, y=ys[1]) \
        .go(t + 0.6, t + 1.8, lin=True, y=ys[2]).go(t + 1.8, t + 2.2, y=ys[3]).go(t + 2.2, t + 2.4, op=0)


def keys(y_app, y_sock, side, peer, t):
    """The exporter gives both keys; TX gets this side's own key, RX the peer's."""
    pp = "2000" if side == "client" else "P"
    for x, who in [(420, "client"), (610, "server")]:
        slot, arrow = ("TX", "→") if who == side else ("RX", "←")
        b = Box(x, y_app + 9, 170, 38, {"k": ("k-key", [one(f"{who} key · iv")]),
                                         "i": ("k-key", [one(f"{slot} · {who} key {arrow} {peer}:{pp}")])})
        b.go(t, t + 0.4, op=1).layer(t + 0.8, "i").go(t + 0.7, t + 1.5, x=556 if slot == "TX" else 862, y=y_sock + 6, w=296)
        b.go(HS_END, HS_END + 0.4, op=0)
        GHOST[side, slot].go(t + 1.3, t + 1.6, op=0)
    Text(800, y_app + 34, "TLS exporter: 56 bytes", "small mut").show(t, HS_END)
    Text(420, (y_app + y_sock + 56) / 2 + (8 if side == "client" else 14),
         "setsockopt(data, SOL_TLS, TLS_TX / TLS_RX, {peer, key, salt, iv})", "small").show(t + 0.6, HS_END)


hs_message("ClientHello", 1.2, True)
hs_message("ServerHello … Finished", 3.8, False)
keys(36, 134, "client", "server", 6.3)
hs_message("Finished + data port P", 8.1, True)
keys(678, 596, "server", "client", 10.5)
Text(400, 548, "Homa RPCs to port 4433: plain Homa, no SMT keys yet", "small mut").show(1.0, HS_END)
for k, (t, who, arrow, what) in enumerate([
        (1.6, "RPC 1", "→", "ClientHello"),
        (4.2, "", "←", "ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished"),
        (6.6, "client", "", "exporter → keys → setsockopt(), for the server's address and port 2000"),
        (8.5, "RPC 2", "→", "Finished + data port P (with mutual TLS: Certificate, CertificateVerify before it)"),
        (10.9, "server", "", "exporter → keys → setsockopt(), for the client's address and port P")]):
    Text(420, 300 + k * 26, f'<tspan class="b">{who}</tspan><tspan x="490">{arrow}</tspan><tspan x="520">{esc(what)}</tspan>', "small").show(t, 12.1)
Box(300, 298, 600, 150, {"b": ("k-banner", [("Now starting to send app data", "big", -4),
                                            ("keys set on both sides: the client sends, the server receives", "bigsub", 32)])}, w0=760, rx=14) \
    .go(12.2, 12.8, x=220, w=760, op=1).go(HS_END, HS_END + 0.4, op=0)

# The record steps: their times count from the end of the handshake.
ORIGIN = S[1]
E = END - ORIGIN

# 2. the message
msg = Box(150 - 1000, 40, 1000, 42, {"m": ("k-data", [lbl(f"message · {REC * NREC} bytes"), sub(asc(TEXT[:40].encode())[:-1] + ' …"')])})
msg.go(0.2, 1.2, x=150, op=1).go(9.0, 9.5, op=0.45)
Text(150, 106, '<tspan class="b">"</tspan>' + esc(TEXT.strip()) + '<tspan class="b">"</tspan>', "small").show(1.0, 3.7)

# 3. records cut out of it
for r in (1, 2):
    Box(150 + r * 1000 / 3 - 1, 32, 2, 58, {"c": ("k-ghost", [])}, rx=0).go(4.1, 4.4, op=1).go(8.6, 8.9, op=0)
for r in range(NREC):
    b = Box(150 + r * 1000 / 3, 40, 1000 / 3, 42, {"r": ("k-data", [lbl(f"record {r}"), sub(f"offset {r * REC} · index {r}")])}, w0=320)
    t = 4.7 + r * 0.18
    b.go(t, t + 0.9, x=150 + r * 340, y=100, w=320, op=1)
    if r != REC_I:
        b.go(9.0, 9.5, op=0.45)
    b.go(27.0, 27.5, op=0.3)

# 4. record 1 in detail: its segments come down, the segment headers drop in, the TLS header and the nonce rise
ZX, ZY, ZH = 124, 175, 58
hl(150 + REC_I * 340, 100, 320, 42, 9.0, 34.0)
Text(640, 162, "▼ one record = one TSO/GSO packet", "small mut").show(9.6, 27.0)
Z = {}
Z["tls"] = Box(ZX, ZY + 40, 112, ZH, {"p": ("k-tls", [lbl("TLS header"), sub(hx(TLS_HDR, ""))]),
                                      "s": ("k-tls", [one("TLS hdr")])}).go(11.8, 12.4, y=ZY, op=1)
Z["nonce"] = Box(ZX + 112, ZY + 40, 128, ZH, {"p": ("k-tls", [lbl("explicit nonce"), sub(hx(SEQ.to_bytes(8, "big"), ""))]),
                                              "s": ("k-tls", [one("nonce")])}).go(12.0, 12.6, y=ZY, op=1)
zx = ZX + 240
for s, (h, d) in enumerate(segs):
    Z[f"sh{s}"] = Box(zx, ZY - 60, 74, ZH, {
        "p": ("k-seg", [lbl("seg hdr"), sub(hx(h, ""))]),
        "f1": ("k-ct", [lbl("seg hdr"), sub(hx(NOISE[s][:4], ""))]),
        "f2": ("k-ct", [lbl("seg hdr"), sub(hx(NOISE[s + 1][:4], ""))]),
        "c": ("k-ct", [lbl("seg hdr"), sub(hx(CT[s * 20:][:4], ""))]),
        "cs": ("k-ct", [one("hdr")]),
        "ps": ("k-seg", [one("hdr")])}).go(10.8 + s * 0.15, 11.3 + s * 0.15, y=ZY, op=1)
    zx += 74
    ct = CT[s * 20 + 4:][:SEG]
    Z[f"sd{s}"] = Box(150 + REC_I * 340 + s * 320 / 3, 100, 320 / 3, ZH, {
        "p": ("k-data", [lbl(f"segment {s}"), sub(asc(d))]),
        "f1": ("k-ct", [lbl(f"segment {s}"), sub(hx(NOISE[s][:6]) + " …")]),
        "f2": ("k-ct", [lbl(f"segment {s}"), sub(hx(NOISE[s + 1][:6]) + " …")]),
        "c": ("k-ct", [lbl(f"ciphertext {s}"), sub(hx(ct[:6]) + " …")]),
        "cs": ("k-ct", [lbl(f"ciphertext {s}"), sub(hx(ct[:3]) + " …")]),
        "g1": ("k-ct", [lbl(f"segment {s}"), sub(hx(NOISE[s][:3]) + " …")]),
        "g2": ("k-ct", [lbl(f"segment {s}"), sub(hx(NOISE[s + 1][:3]) + " …")]),
        "ps": ("k-data", [lbl(f"segment {s}"), sub(asc(d)[:10] + " …")]),
        "pf": ("k-data", [lbl(f"segment {s}"), sub(asc(d))])}, w0=150)
    Z[f"sd{s}"].go(9.2, 9.21, op=1).go(9.4 + s * 0.12, 10.4 + s * 0.12, x=zx, y=ZY, w=150)
    zx += 150
Z["tag"] = Box(zx, ZY, 124, ZH, {"g": ("k-ghost", [lbl("tag"), sub("(after sealing)")]),
                                 "c": ("k-tag", [lbl("tag"), sub(hx(TAG[:5]) + " …")]),
                                 "s": ("k-tag", [one("tag")])}).go(12.6, 13.0, op=1)
Text(ZX, 260, f'TLS length 0x{TLS_LEN:04x} = 8 (nonce) + {NSEG} × (4 + {SEG}) + 16 (tag) = {TLS_LEN}', "mono mut").show(12.8, 15.0)

# 5. the nonce: the bits of the RPC id fly into seq, then the response bit, the record index and the nonce bytes
PITCH, X0, Y_ID, Y_SEQ, Y_NON = 15, 175, 285, 338, 404
col = lambda bit: X0 + (63 - bit) * PITCH


def bit(x, y, v, kind):
    ink = "bit i" if not v else "bit dk" if kind in ("k-data", "k-tls") else "bit"
    return Box(x, y, 14, 22, {"b": (kind + ("" if v else " z"), [(str(v), ink, 4)])}, rx=3)


slots = "".join(f'<rect x="{col(b)}" y="{Y_SEQ + Y0}" width="14" height="22" rx="3" class="slot"/>' for b in range(64))
keyframes("slots", [(ORIGIN + 15.2, "opacity:0"), (ORIGIN + 15.6, "opacity:1"), (ORIGIN + 27.0, "opacity:1"), (ORIGIN + 27.4, "opacity:0")])
for k in range(48):
    b = bit(col(k), Y_ID - 26, (RPC >> k) & 1, "k-seg")
    t = 15.3 + k * 0.012
    b.go(t, t + 0.5, y=Y_ID, op=1).go(16.8, 17.4, x=col(k - 1))
    if k == 0:  # >> 1 drops bit 0, the client/server bit
        b.go(17.4, 17.9, y=Y_ID + 26, op=0)
    else:
        t = 17.6 + (47 - k) * 0.025
        b.go(t, t + 0.8, x=col(k + 16), y=Y_SEQ).go(27.0, 27.4, op=0)
for k in range(17):
    b = bit(col(k), Y_SEQ - 14, (SEQ >> k) & 1, "k-tls" if k == 16 else "k-data")
    t = 19.8 if k == 16 else 20.3 + (15 - k) * 0.06
    b.go(t, t + 0.35, y=Y_SEQ, op=1).go(27.0, 27.4, op=0)
for j, byte in enumerate(NONCE):
    kind = "k-tls" if j < 4 else "k-seg"
    b = Box(X0 + j * 46, Y_NON + 26, 40, 30, {"n": (kind, [(f"{byte:02x}", "byte" + (" dk" if j < 4 else ""), 5)])})
    t = 22.0 + j * 0.07
    b.go(t, t + 0.45, y=Y_NON, op=1).go(27.0, 27.4, op=0)
Text(col(47) - 4, Y_ID - 10, f'<tspan class="c-id">RPC id</tspan> = <tspan class="b">0x{RPC:x}</tspan> (low 48 bits)').show(15.3, 27.0)
Text(col(47) + 320, Y_ID - 10, "&gt;&gt; 1   drops the client/server bit", "mono mut").show(16.8, 17.5)
Text(col(47) + 320, Y_ID - 10, "&lt;&lt; 17", "mono mut").show(17.6, 19.6)
Text(X0, Y_SEQ + 46, f'<tspan class="c-id">RPC id &gt;&gt; 1 (bits 63–17)</tspan><tspan dx="16" class="c-r">response bit (16) = {RESP}</tspan>'
     f'<tspan dx="16" class="c-ix">record index (15–0) = {REC_I}</tspan><tspan dx="16">seq = <tspan class="b">0x{SEQ:016x}</tspan></tspan>').show(21.4, 27.0)
Text(X0, Y_NON + 52, "salt (client iv)", "small mut").show(22.6, 27.0)
Text(X0 + 4 * 46, Y_NON + 52, "seq", "small mut").show(22.9, 27.0)
Text(X0 + 12 * 46 + 14, Y_NON + 21, "nonce = salt ‖ seq   (TLS 1.2)").show(23.0, 27.0)
hl(ZX + 112, ZY, 128, ZH, 23.6, 26.8)
Text(ZX + 112, 166, "explicit nonce = seq", "small acc").show(23.6, 26.8)

# 6. sealing: a sweep passes at constant speed, each piece flickers into ciphertext as it passes, the tag lights up
SW0, SW1 = 28.1, 30.1  # the sweep's center goes from ZX - 35 to ZX + 1071
Box(ZX - 70, ZY - 6, 70, ZH + 12, {"w": ("sweep", [])}).go(27.9, SW0, op=1).go(SW0, SW1, lin=True, x=ZX + 1036).go(SW1, SW1 + 0.2, op=0)
for p, b in Z.items():
    if p[:2] in ("sh", "sd"):
        c = b.now("x") + b.now("w") / 2
        b.flicker(SW0 + (c - ZX + 35) / 1106 * (SW1 - SW0), "c")
Z["tag"].layer(SW1, "c")
hl(Z["tag"].now("x"), ZY, 124, ZH, SW1, 32.4, "hl tg")
Text(150, 292, f'AAD   = <tspan class="b">{hx(AAD)}</tspan>   (seq ‖ 17 03 03 ‖ plaintext length)').show(27.6, 34.0)
Text(150, 322, f'nonce = <tspan class="b">{hx(NONCE)}</tspan>   (salt ‖ seq)').show(27.8, 34.0)
Text(150, 352, f'key   = <tspan class="b">{KEY.hex()}</tspan>   (client TX key; here the fixed test key)').show(28.0, 34.0)
Box(150, 374, 296, 34, {"k": ("k-key", [one("TX · client key → server:2000")])}).go(27.6, 28.0, op=1).go(34.0, 34.4, op=0)

# 7. TSO/GSO: the pieces spread into three packets in place, and the IP and Homa headers slide in
PW = dict(ip=40, hm=92, tls=60, nonce=62, sh=46, sd=100, tag=62)
PK = [["tls", "nonce", "sh0", "sd0"], ["sh1", "sd1"], ["sh2", "sd2", "tag"]]
pkt, px = {}, 52  # piece → (packet, x)
for i, ids in enumerate(PK):
    for p in [f"ip{i}", f"hm{i}"] + ids:
        pkt[p] = (i, px)
        px += PW[p.rstrip("012")]
    px += 26
for p, b in Z.items():
    short = {"tls": "s", "nonce": "s", "tag": "s"}.get(p, "cs")
    b.layer(34.3, short).go(34.3, 35.3, x=pkt[p][1], w=PW[p.rstrip("012")])
for i in range(3):
    for k, (p, kind, name, val) in enumerate([(f"ip{i}", "k-ip", "IP", f"id {i + 1}"),
                                              (f"hm{i}", "k-homa", "Homa DATA", f"pad {REC_I * REC:06x}")]):
        t = 35.4 + i * 0.22 + k * 0.08
        Z[p] = Box(pkt[p][1] - 80, ZY, PW[p[:2]], ZH, {"h": (kind, [lbl(name), sub(val)])}).go(t, t + 0.6, x=pkt[p][1], op=1)
Text(52, 165, "packets", "mono mut").show(35.4, 40.0)

# 8. the wire: the packets go down through it and packet 1 arrives last; control packets go the other way
DEPART = {0: 40.5, 2: 41.0, 1: 41.8}
for p, b in Z.items():
    i, x = pkt[p]
    n, t = list(DEPART).index(i), DEPART[i]
    b.go(t, t + 1.6, x=x + 40 + n * 15, y=510).go(t + 1.6, t + 2.4, x=x, y=640)
for k, name in enumerate(["GRANT", "ACK", "GRANT"]):
    t = 40.9 + k * 0.7
    Box(1110, 572, 70, 26, {"c": ("k-ctl", [one(name)])}).go(t, t + 0.2, op=1).go(t + 0.2, t + 2.8, lin=True, x=40).go(t + 2.8, t + 3.0, op=0)
Text(1170, 622, "arrival order: 0, 2, 1", "small mut e").show(44.3, 46.3)

# 9. the server: check the tag, decrypt, drop the headers, give the bytes to recvmsg()
Box(44, 632, 1124, 74, {"f": ("k-ghost", [])}, rx=6).go(46.8, 47.2, op=1).go(51.5, 52.0, op=0)
Box(44, 588, 296, 34, {"k": ("k-key", [one("RX · client key ← client:P")])}).go(46.8, 47.2, op=1).go(51.5, 52.0, op=0)
Box(44, 634, 90, 70, {"w": ("sweep", [])}).go(47.4, 47.6, op=1).go(47.6, 48.8, lin=True, x=1078).go(48.8, 49.0, op=0)
Box(41, 629, 1130, 80, {"f": ("okhl", [])}, rx=8).go(48.9, 49.2, op=1).go(51.5, 52.0, op=0)
Box(1010, 582, 160, 30, {"v": ("k-ok", [("✓ tag verified", "lb", 4)])}, rx=15).go(49.0, 49.35, y=592, op=1).go(51.5, 52.0, op=0)
for s in range(NSEG):
    t = 49.6 + s * 0.25
    Z[f"sd{s}"].flicker(t, "ps", ("g1", "g2"))
    Z[f"sh{s}"].layer(t, "ps", 0.2)
for p, b in Z.items():
    if not p.startswith("sd"):
        b.go(51.5, 52.0, op=0)
for s in range(NSEG):
    Z[f"sd{s}"].layer(52.2, "pf").go(52.1, 53.1, x=150 + s * 220, w=220)
Text(150, 728, f"recvmsg() on the server gets {REC} bytes of record {REC_I}   ·   replay guard: RPC 0x{RPC:x} is new, accepted").show(53.3)

# row labels
for name, y, t0, t1 in [("sendmsg()", 66, 0.2, E), ("records", 126, 4.6, E), (f"record {REC_I}", 209, 9.3, 34.0),
                        ("RPC id", 301, 15.3, 27.0), ("seq", 354, 15.2, 27.0), ("nonce", 424, 22.0, 27.0)]:
    Text(44, y, name, "mono mut").show(t0, t1)

# captions and progress, in loop time
ORIGIN = 0.0
for i, (title, *lines) in enumerate(CAPTIONS):
    t0, t1 = S[i] + 0.05, S[i + 1] - 0.3
    Text(24, 28 - Y0, f"STEP {i + 1} OF {len(CAPTIONS)}", "step").show(t0, t1, 0.25)
    Text(24, 60 - Y0, esc(title), "title").show(t0, t1, 0.25)
    for k, line in enumerate(lines):
        Text(24, 88 + k * 22 - Y0, esc(line), "desc").show(t0, t1, 0.25)
    Box(W - 24 - (len(CAPTIONS) - i) * 22, 18 - Y0, 16, 6, {"d": ("dot", [])}, rx=3).go(S[i], S[i] + 0.3, op=1).go(S[i + 1] - 0.2, S[i + 1] + 0.1, op=0.35)

for o in boxes + texts:
    o.emit()

# ------------------------------------------------------------------ write
LIGHT = dict(bg="#ffffff", stage="#f6f7fb", panel="#ffffff", line="#d3d8e4", ink="#121827", muted="#5a6378", accent="#3f4cf2",
             ok="#18a866", data="#2bb08b", seg="#3a86f7", tls="#f0a330", ct="#6a48ee", tag="#ff6a48", homa="#e6c35c", ip="#8c95ab",
             ctl="#c3c9d6", key="#e0559f", banner="#3f4cf2", r="#c47a06", ix="#1a9470")
DARK = dict(bg="#0a0e19", stage="#111727", panel="#1a2238", line="#252f48", ink="#e6e9f2", muted="#8e98ae", accent="#7c86ff",
            ok="#2fcf83", data="#33c79c", seg="#4d95ff", tls="#f5b04a", ct="#7c5cff", tag="#ff7a5a", homa="#e9c86a", ip="#75809a",
            ctl="#8a94ad", key="#f472b6", banner="#4650e6", r="#f5b04a", ix="#33c79c")


def colors(c):
    return (f".bg{{fill:{c['bg']}}}.stage{{fill:{c['stage']};stroke:{c['line']}}}.slot{{fill:{c['line']}}}"
            f".k-data{{fill:{c['data']}}}.k-seg{{fill:{c['seg']}}}.k-tls{{fill:{c['tls']}}}.k-ct{{fill:{c['ct']}}}.k-tag{{fill:{c['tag']}}}"
            f".k-homa{{fill:{c['homa']}}}.k-ip{{fill:{c['ip']}}}.k-ctl{{fill:{c['ctl']}}}.k-key{{fill:{c['key']}}}.k-banner{{fill:{c['banner']}}}.dot{{fill:{c['accent']}}}"
            f".k-ok{{fill:{c['ok']}}}.k-app{{fill:{c['panel']};stroke:{c['muted']}}}.k-hs{{fill:{c['panel']};stroke:{c['accent']}}}"
            f".k-ghost{{stroke:{c['muted']}}}.hl{{stroke:{c['accent']}}}.tg{{stroke:{c['tag']}}}.okhl{{stroke:{c['ok']}}}"
            f".mono,.small,.title,.bit.i,.n{{fill:{c['ink']}}}.desc,.mut,.leg,.g,.zone{{fill:{c['muted']}}}.step,.acc{{fill:{c['accent']}}}"
            f".c-id{{fill:{c['seg']}}}.c-r{{fill:{c['r']}}}.c-ix{{fill:{c['ix']}}}.wire{{stroke:{c['accent']}}}")


SANS = 'ui-sans-serif,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif'
MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace'
wire_on = [(0, ".25"), (1.0, ".25"), (1.4, ".85"), (HS_END, ".85"), (HS_END + 0.4, ".25"), (S[7], ".25"), (S[7] + 0.4, ".85"), (END, ".85"), (END + 0.8, ".25")]
style = (
    f"text{{font-family:{SANS}}}.mono,.small,.lb,.hx,.bit,.byte,.step{{font-family:{MONO}}}"
    ".lb,.hx,.bit,.byte{text-anchor:middle;fill:#10131c}.lb,.bit,.byte{font-weight:700}.lb{font-size:13px}.hx,.bit{font-size:12px}.byte{font-size:14px}"
    ".bit,.byte{fill:#fff}.dk{fill:#10131c}.w{fill:#fff}.z{fill-opacity:.22}"
    ".k-ghost{fill:none;stroke-dasharray:4 3}.k-app,.k-hs{stroke-width:1.5}.hl,.okhl{fill:none;stroke-width:2.5}.okhl{stroke-width:3}.sweep{fill:url(#sw)}"
    ".big{font-size:38px;font-weight:700;text-anchor:middle}.bigsub{font-size:17px;text-anchor:middle}"
    ".mono{font-size:15px}.small{font-size:13px}.b{font-weight:700}.e{text-anchor:end}"
    ".step{font-size:13px;font-weight:700;letter-spacing:.1em}.title{font-size:24px;font-weight:700}.desc{font-size:16px}"
    ".zone{font-size:12px;font-weight:700;letter-spacing:.16em}.leg{font-size:13px}"
    ".wire{stroke-width:4;stroke-dasharray:18 12;animation:flow 1s linear infinite}@keyframes flow{to{stroke-dashoffset:-30}}"
    + colors(LIGHT) + "@media (prefers-color-scheme:dark){" + colors(DARK) + "}"
    f"#all *{{animation-duration:{T:g}s;animation-iteration-count:infinite;animation-timing-function:{EASE};animation-fill-mode:both}}"
    ".sc{transform-box:fill-box;transform-origin:50% 50%}"
    f"#all{{animation:all {T:g}s linear infinite}}@keyframes all{{0%{{opacity:0}}0.5%{{opacity:1}}{pct(END)}{{opacity:1}}{pct(END + 0.8)},100%{{opacity:0}}}}"
    f"#wireg{{animation:wireg {T:g}s linear infinite}}@keyframes wireg{{{''.join(f'{pct(t)}{{opacity:{o}}}' for t, o in wire_on)}}}"
    f"@media (prefers-reduced-motion:reduce){{#all *,#all,#wireg,.wire{{animation-play-state:paused!important;animation-delay:-{STILL:g}s!important}}}}"
)
legend, lx = [], 24
for cls, name in [("k-data", "message bytes"), ("k-seg", "segment header"), ("k-tls", "TLS header, nonce"), ("k-ct", "ciphertext"),
                  ("k-tag", "tag"), ("k-homa", "Homa DATA header"), ("k-ip", "IP header"), ("k-key", "key")]:
    legend.append(f'<rect x="{lx}" y="{H - 31}" width="14" height="14" rx="3" class="{cls}"/><text x="{lx + 20}" y="{H - 19}" class="leg">{name}</text>')
    lx += 20 + sum(8.6 if ch.isupper() else 3.8 if ch in " ,-" else 6.9 for ch in name) + 30
dots = "".join(f'<rect x="{W - 24 - (len(CAPTIONS) - i) * 22}" y="18" width="16" height="6" rx="3" class="slot"/>' for i in range(len(CAPTIONS)))
svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="ttl dsc">
<title id="ttl">SMT on the wire</title>
<desc id="dsc">An animation in 9 steps: the client and the server agree on keys with a TLS handshake in user space and install them on their Homa sockets; the client sends a message, which SMT cuts into records; each record gets a TLS header and Homa segment headers, the nonce comes from the RPC id and the record index, AES-GCM seals the record, TSO/GSO cuts it into packets, the packets cross the wire, and the server checks the tag, decrypts and gives the bytes to recvmsg().</desc>
<defs><linearGradient id="sw" x1="0" x2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset=".5" stop-color="#fff" stop-opacity=".85"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient></defs>
<style>{style}{"".join(css)}</style>
<rect class="bg" width="{W}" height="{H}" rx="12"/>
{dots}
<rect class="stage" x="12" y="{Y0}" width="{W - 24}" height="{SH}" rx="10"/>
<text class="zone" transform="translate(31 {Y0 + 200}) rotate(-90)">CLIENT</text>
<text class="zone" transform="translate(31 {Y0 + 596}) rotate(-90)">WIRE</text>
<text class="zone" transform="translate(31 {Y0 + 734}) rotate(-90)">SERVER</text>
<g id="wireg"><line class="wire" x1="40" y1="{Y0 + 562}" x2="1160" y2="{Y0 + 562}"/></g>
<g id="all">
<g id="slots">{slots}</g>
{chr(10).join(body)}
</g>
{"".join(legend)}
</svg>
"""
with open(OUT, "w") as f:
    f.write(svg)
print(f"{OUT}: {len(svg) / 1024:.0f} KB, {len(boxes)} boxes, {len(texts)} texts")
