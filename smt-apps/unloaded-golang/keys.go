// Keys: unloaded/'s fixed ones, or from a TLS 1.3 handshake over Homa.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// cryptoInfo is struct tls12_crypto_info_aes_gcm_128 or _256: key, then IV
// (salt and nonce), for TLS 1.2 or 1.3 records.
func cryptoInfo(key, iv []byte, tls13 bool) []byte {
	b := make([]byte, 24+len(key))
	if tls13 {
		binary.NativeEndian.PutUint16(b, 0x0304)
		copy(b[4:12], iv[4:]) // TLS 1.2: the explicit nonce, rec_seq 0
	} else {
		binary.NativeEndian.PutUint16(b, 0x0303)
	}
	binary.NativeEndian.PutUint16(b[2:], uint16(50+len(key)/16)) // TLS_CIPHER_AES_GCM_128 / _256
	copy(b[12:], key)
	copy(b[12+len(key):], iv[:4])
	return b
}

// fixedKeys sets unloaded/'s test keys (smt_uapi.c) on a kTLS or SMT socket,
// for every peer; nothing when net.homa.smt_fixed_key already gives some.
func fixedKeys(fd int) {
	ck := []byte{0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42, 0x30}
	civ := []byte{0x87, 0xC6, 0x35, 0xC8, 0x17, 0x87, 0xDE, 0x4A, 0x88, 0x1D, 0xD2, 0xD5}
	sk := []byte{0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A, 0x7F}
	siv := []byte{0xB9, 0xFA, 0x55, 0x83, 0xD5, 0x8F, 0x85, 0x18, 0xFF, 0xA6, 0x3E, 0x66}
	if proto == "smt" {
		v, _ := os.ReadFile("/proc/sys/net/homa/smt_fixed_key")
		if n, _ := strconv.Atoi(strings.TrimSpace(string(v))); n != 0 {
			return
		}
	} else if err := syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, tcpULP, "tls"); err != nil {
		fatal("kTLS: %v", err)
	}
	if os.Getenv("SMT_KEY_BITS") == "256" {
		ck, sk = append(ck, ck...), append(sk, sk...)
	}
	tx, rx := [][]byte{ck, civ}, [][]byte{sk, siv}
	if server {
		tx, rx = rx, tx
	}
	tls13 := os.Getenv("SMT_TLS") == "13"
	for i, k := range [][][]byte{tx, rx} {
		b := cryptoInfo(k[0], k[1], tls13)
		if proto == "smt" {
			b = append(make([]byte, 10), b...) // struct smt_info: any peer
		}
		if err := setsockopt(fd, solTLS, 1+i, b); err != nil {
			fatal("setting keys: %v", err)
		}
	}
}

// rpcConn carries a TLS byte stream in Homa RPCs, as crypto/tls wants a
// net.Conn: what TLS writes waits for its next read, which sends it (as a
// request on the client, as the reply to the last request on the server)
// and returns the next message.
type rpcConn struct {
	hs   *homaSock
	peer syscall.RawSockaddrInet4
	in   chan request // server: the client's requests
	id   uint64       // server: the request to reply to
	rd   []byte       // received, not read yet
	wr   bytes.Buffer // written, not sent yet
}

type request struct {
	id  uint64
	msg []byte
}

func (c *rpcConn) Read(p []byte) (int, error) {
	for len(c.rd) == 0 {
		var err error
		if c.in == nil {
			if err = c.hs.send(&c.peer, 0, c.wr.Bytes()); err == nil {
				var parts [][]byte
				parts, _, err = c.hs.recv(nil)
				c.rd = bytes.Join(parts, nil)
			}
			c.wr.Reset()
		} else {
			c.Close()
			select {
			case r := <-c.in:
				c.id, c.rd = r.id, r.msg
			case <-time.After(10 * time.Second):
				err = os.ErrDeadlineExceeded
			}
		}
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, c.rd)
	c.rd = c.rd[n:]
	return n, nil
}

func (c *rpcConn) Write(p []byte) (int, error) { return c.wr.Write(p) }

// Close sends the server's reply, if one is due.
func (c *rpcConn) Close() error {
	if c.id != 0 {
		if err := c.hs.send(&c.peer, c.id, c.wr.Bytes()); err != nil {
			log.Print("handshake reply: ", err)
		}
		c.id = 0
	}
	c.wr.Reset()
	return nil
}

func (c *rpcConn) LocalAddr() net.Addr              { return nil }
func (c *rpcConn) RemoteAddr() net.Addr             { return nil }
func (c *rpcConn) SetDeadline(time.Time) error      { return nil }
func (c *rpcConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rpcConn) SetWriteDeadline(time.Time) error { return nil }

// tlsConfig: TLS 1.3 with ca.pem; this end's certificate, the client's only
// with --mtls, when the server requires one.
func tlsConfig() *tls.Config {
	pem, err := os.ReadFile("ca.pem")
	ca := x509.NewCertPool()
	if err != nil || !ca.AppendCertsFromPEM(pem) {
		fatal("ca.pem (make cert): %v", err)
	}
	cfg := &tls.Config{RootCAs: ca, ClientCAs: ca, ClientAuth: tls.VerifyClientCertIfGiven,
		ServerName: "smt-server", MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if mtls {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if name := "server"; server || mtls {
		if !server {
			name = "client"
		}
		cert, err := tls.LoadX509KeyPair(name+".pem", name+"-key.pem")
		if err != nil {
			fatal("certificates (make cert): %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

// setKeys takes the keys from the exporter (the client's first) and installs
// them on fd for the peer at ip:port.
func setKeys(fd int, conn *tls.Conn, ip []byte, port int) error {
	cs := conn.ConnectionState()
	k, err := cs.ExportKeyingMaterial(label, nil, 56)
	own := 0
	if server {
		own = 1
	}
	for i := 0; i < 2 && err == nil; i++ { // TLS_TX with our own key, then TLS_RX
		key := k[(own^i)*28:]
		b := binary.BigEndian.AppendUint16(append([]byte{}, ip...), uint16(port))
		b = append(append(b, 0, 0, 0, 0), cryptoInfo(key[:16], key[16:28], true)...)
		err = setsockopt(fd, solTLS, 1+i, b)
	}
	return err
}

// handshakes serves handshakes for data socket fd, a goroutine each, kept
// for up to 10 s between their two RPCs.
func handshakes(fd int) {
	hs, cfg := homaOpen(hsPort), tlsConfig()
	var mu sync.Mutex
	clients := map[syscall.RawSockaddrInet4]*rpcConn{}
	for {
		var src syscall.RawSockaddrInet4
		parts, _, err := hs.recv(&src)
		if err != nil {
			log.Print(err)
			continue
		}
		mu.Lock()
		c := clients[src]
		if c == nil {
			c = &rpcConn{hs: hs, peer: src, in: make(chan request, 1)}
			clients[src] = c
			go func() {
				handshake(fd, tls.Server(c, cfg))
				mu.Lock()
				delete(clients, src)
				mu.Unlock()
			}()
		}
		mu.Unlock()
		select {
		case c.in <- request{hs.ra.ID, bytes.Join(parts, nil)}:
		default: // a client sends one request at a time
		}
	}
}

// handshake gives one client its keys; Close sends the last reply.
func handshake(fd int, conn *tls.Conn) {
	defer conn.Close()
	ip := net.IP(conn.NetConn().(*rpcConn).peer.Addr[:])
	p := make([]byte, 2)
	_, err := io.ReadFull(conn, p)
	port := int(binary.BigEndian.Uint16(p))
	if err == nil && port == 0 {
		err = errors.New("Homa port 0")
	}
	if err == nil {
		err = setKeys(fd, conn, ip, port)
	}
	if err == nil {
		_, err = conn.Write([]byte{1})
	}
	if err != nil {
		log.Printf("handshake with %v failed: %v", ip, err)
		return
	}
	infof("keys for %v:%d, client %sauthenticated", ip, port,
		map[bool]string{true: "", false: "not "}[len(conn.ConnectionState().PeerCertificates) > 0])
}

// clientHandshake gets the keys for the server's data port.
func clientHandshake(data *homaSock) {
	peer := addr
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&peer.Port))[:], hsPort)
	conn := tls.Client(&rpcConn{hs: homaOpen(0), peer: peer}, tlsConfig())
	me, err := syscall.Getsockname(data.fd)
	if err != nil {
		fatal("getsockname: %v", err)
	}
	p := binary.BigEndian.AppendUint16(nil, uint16(me.(*syscall.SockaddrInet4).Port))
	if err = conn.Handshake(); err == nil {
		_, err = conn.Write(p)
	}
	if err == nil {
		err = setKeys(data.fd, conn, addr.Addr[:], port)
	}
	if err == nil {
		_, err = io.ReadFull(conn, p[:1])
	}
	if err != nil {
		fatal("handshake: %v", err)
	}
	syscall.Close(conn.NetConn().(*rpcConn).hs.fd)
}
