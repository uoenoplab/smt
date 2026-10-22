// smt_handshake_go: smt_handshake.c's protocol with Go's crypto/tls, standard
// library only. Either end interoperates with the C program.
//
// The client runs a TLS 1.3 handshake with the server over TCP, sends its Homa
// port and the TLS version of the SMT records (12 or 13), and both ends take
// their SMT keys from the TLS exporter: 56 bytes labelled
// "EXPORTER-SMT-NG keys", the client's AES-128 key and 12-byte IV followed by
// the server's, installed with setsockopt(SOL_TLS, TLS_TX / TLS_RX) for that
// peer only. The server then sends one byte, and the client starts its RPCs.
//
// usage: smt_handshake_go server [-p homa_port] [-t tls_port]
//
//	smt_handshake_go client -a server_ip [-p homa_port] [-t tls_port] [-3] [-l bytes] [-n rpcs]
//
// The server reads cert.pem and key.pem (make cert), the client trusts
// cert.pem for the name smt-server.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	label        = "EXPORTER-SMT-NG keys"
	keyLen       = 16
	ivLen        = 12
	ipprotoHoma  = 146
	soHomaRcvbuf = 10
	solTLS       = 282
	tlsTX        = 1
	tlsRX        = 2
	bpageSize    = 1 << 16
	maxBpages    = 16 // HOMA_MAX_BPAGES
	// Receive region: Homa wants a bpage per possible CPU plus two
	// maximum-size messages; untouched pages cost nothing.
	bufPages = 1000
)

// struct homa_sendmsg_args and struct homa_recvmsg_args (homa.h).
type sendArgs struct {
	ID, Cookie      uint64
	Flags, Reserved uint32
}

type recvArgs struct {
	ID, Cookie          uint64
	NumBpages, Reserved uint32
	Offsets             [maxBpages]uint32
}

var homaFD int
var rbuf []byte

func setsockopt(level, opt int, b []byte) {
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(homaFD), uintptr(level),
		uintptr(opt), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if e != 0 {
		log.Fatalf("setsockopt(%d, %d): %v", level, opt, e)
	}
}

// homaOpen opens the Homa socket, bound to port unless 0, with its receive
// buffer region.
func homaOpen(port int) {
	var err error
	if homaFD, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, ipprotoHoma); err != nil {
		log.Fatal("homa socket: ", err)
	}
	if port != 0 {
		if err = syscall.Bind(homaFD, &syscall.SockaddrInet4{Port: port}); err != nil {
			log.Fatal("homa bind: ", err)
		}
	}
	if rbuf, err = syscall.Mmap(-1, 0, bufPages*bpageSize, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS); err != nil {
		log.Fatal("mmap: ", err)
	}
	args := make([]byte, 16) // struct homa_rcvbuf_args
	binary.NativeEndian.PutUint64(args, uint64(uintptr(unsafe.Pointer(&rbuf[0]))))
	binary.NativeEndian.PutUint64(args[8:], uint64(len(rbuf)))
	setsockopt(ipprotoHoma, soHomaRcvbuf, args)
}

// setKeys installs tx and rx (each a key followed by its IV) for the peer at
// ip:port: struct smt_aes_gcm_128_info, a packed struct smt_info followed by
// struct tls12_crypto_info_aes_gcm_128.
func setKeys(ip net.IP, port int, tls13 bool, tx, rx []byte) {
	for _, d := range []struct {
		opt int
		k   []byte
	}{{tlsTX, tx}, {tlsRX, rx}} {
		k := d.k
		b := make([]byte, 50)
		copy(b[0:4], ip.To4())                           // peer_addr
		binary.BigEndian.PutUint16(b[4:6], uint16(port)) // peer_port; local_addr 0
		version := uint16(0x0303)
		if tls13 {
			version = 0x0304
		}
		binary.NativeEndian.PutUint16(b[10:12], version)
		binary.NativeEndian.PutUint16(b[12:14], 51) // TLS_CIPHER_AES_GCM_128
		copy(b[22:38], k[:keyLen])                  // key
		copy(b[38:42], k[keyLen:keyLen+4])          // salt
		// TLS 1.3 nonces use the whole IV; TLS 1.2 records carry an
		// explicit nonce, which must start out equal to rec_seq (0).
		if tls13 {
			copy(b[14:22], k[keyLen+4:keyLen+ivLen]) // iv
		}
		setsockopt(solTLS, d.opt, b)
	}
}

func msghdr(to *syscall.RawSockaddrInet4, iov []syscall.Iovec, ctl unsafe.Pointer, ctlLen int) *syscall.Msghdr {
	m := &syscall.Msghdr{Control: (*byte)(ctl), Controllen: uint64(ctlLen)}
	if to != nil {
		m.Name = (*byte)(unsafe.Pointer(to))
		m.Namelen = syscall.SizeofSockaddrInet4
	}
	if len(iov) > 0 {
		m.Iov = &iov[0]
		m.Iovlen = uint64(len(iov))
	}
	return m
}

// sys makes a sendmsg or recvmsg call, again when a signal interrupts it (Go
// preempts goroutines with signals). That is safe: recvmsg frees the bpages it
// was handed before it waits and writes num_bpages 0 back on its way out, and
// sendmsg is interrupted only while waiting for buffer space, before it
// creates the RPC.
func sys(name string, trap uintptr, m *syscall.Msghdr) (int, error) {
	for {
		n, _, e := syscall.Syscall(trap, uintptr(homaFD), uintptr(unsafe.Pointer(m)), 0)
		if e == 0 {
			return int(n), nil
		}
		if e != syscall.EINTR {
			return 0, fmt.Errorf("%s: %w", name, e)
		}
	}
}

// bpages returns the received message's bytes, bpage by bpage.
func bpages(ra *recvArgs, n int) []syscall.Iovec {
	v := make([]syscall.Iovec, ra.NumBpages)
	for i := range v {
		part := min(n-i*bpageSize, bpageSize)
		v[i].Base = &rbuf[ra.Offsets[i]]
		v[i].SetLen(part)
	}
	return v
}

func rawAddr(ip net.IP, port int) *syscall.RawSockaddrInet4 {
	a := &syscall.RawSockaddrInet4{Family: syscall.AF_INET}
	copy(a.Addr[:], ip.To4())
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&a.Port))[:], uint16(port))
	return a
}

func handshakes(tlsPort int) {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	// IPv4 only, as SMT: the peer's address goes into its key.
	l, err := tls.Listen("tcp4", fmt.Sprintf(":%d", tlsPort),
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		conn := c.(*tls.Conn)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := handshake(conn); err != nil {
			log.Print("handshake: ", err)
		}
		conn.Close()
	}
}

// handshake gives the client on conn its keys.
func handshake(conn *tls.Conn) error {
	hello := make([]byte, 3)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return err
	}
	peer := conn.RemoteAddr().(*net.TCPAddr)
	port := int(binary.BigEndian.Uint16(hello[:2]))
	if port == 0 {
		return fmt.Errorf("%s sent Homa port 0", peer.IP)
	}
	cs := conn.ConnectionState()
	keys, err := cs.ExportKeyingMaterial(label, nil, 2*(keyLen+ivLen))
	if err != nil {
		return err
	}
	minor := 2
	if hello[2] == 13 {
		minor = 3
	}
	setKeys(peer.IP, port, minor == 3, keys[keyLen+ivLen:], keys[:keyLen+ivLen])
	if _, err = conn.Write([]byte{1}); err != nil {
		return err
	}
	fmt.Printf("keys for %s:%d, TLS 1.%d records\n", peer.IP, port, minor)
	return nil
}

func serve(homaPort, tlsPort int) {
	homaOpen(homaPort)
	go handshakes(tlsPort)
	fmt.Printf("echoing on Homa port %d, handshakes on TCP port %d\n", homaPort, tlsPort)
	var ra recvArgs
	for {
		var src syscall.RawSockaddrInet4
		// ra still lists the last message's bpages: they go back.
		ra.ID = 0
		n, err := sys("recvmsg", syscall.SYS_RECVMSG, msghdr(&src, nil, unsafe.Pointer(&ra), int(unsafe.Sizeof(ra))))
		if err != nil {
			log.Print(err)
			continue
		}
		sa := sendArgs{ID: ra.ID}
		if _, err = sys("sendmsg", syscall.SYS_SENDMSG, msghdr(&src, bpages(&ra, n), unsafe.Pointer(&sa), 0)); err != nil {
			log.Print(err)
		}
	}
}

func client(server string, homaPort, tlsPort int, tls13 bool, size, n int) {
	ip := net.ParseIP(server).To4()
	if ip == nil {
		log.Fatal("server address")
	}
	homaOpen(0)
	me, err := syscall.Getsockname(homaFD)
	if err != nil {
		log.Fatal(err)
	}
	pem, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Fatal("cert.pem: no certificate")
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", server, tlsPort),
		&tls.Config{RootCAs: roots, ServerName: "smt-server", MinVersion: tls.VersionTLS13})
	if err != nil {
		log.Fatal("TLS handshake: ", err)
	}
	hello := []byte{0, 0, 12}
	binary.BigEndian.PutUint16(hello, uint16(me.(*syscall.SockaddrInet4).Port))
	if tls13 {
		hello[2] = 13
	}
	if _, err = conn.Write(hello); err != nil {
		log.Fatal("TLS write: ", err)
	}
	cs := conn.ConnectionState()
	keys, err := cs.ExportKeyingMaterial(label, nil, 2*(keyLen+ivLen))
	if err != nil {
		log.Fatal(err)
	}
	setKeys(ip, homaPort, tls13, keys[:keyLen+ivLen], keys[keyLen+ivLen:])
	if _, err = io.ReadFull(conn, make([]byte, 1)); err != nil {
		log.Fatal("no go-ahead from the server: ", err)
	}
	conn.Close()

	to := rawAddr(ip, homaPort)
	req := make([]byte, size)
	iov := []syscall.Iovec{{Base: &req[0]}}
	iov[0].SetLen(size)
	var ra recvArgs
	var total time.Duration
	for i := 0; i < n; i++ {
		for j := range req {
			req[j] = byte(i + j)
		}
		t0 := time.Now()
		var sa sendArgs
		if _, err = sys("sendmsg", syscall.SYS_SENDMSG, msghdr(to, iov, unsafe.Pointer(&sa), 0)); err != nil {
			log.Fatal(err)
		}
		ra.ID = 0
		got, err := sys("recvmsg", syscall.SYS_RECVMSG, msghdr(nil, nil, unsafe.Pointer(&ra), int(unsafe.Sizeof(ra))))
		if err != nil {
			log.Fatal(err)
		}
		total += time.Since(t0)
		if got != size {
			log.Fatalf("echo %d: %d bytes", i, got)
		}
		for b, v := range bpages(&ra, got) {
			part := unsafe.Slice(v.Base, v.Len)
			if !bytes.Equal(part, req[b*bpageSize:b*bpageSize+len(part)]) {
				log.Fatalf("echo %d differs", i)
			}
		}
	}
	minor := 2
	if tls13 {
		minor = 3
	}
	fmt.Printf("%d echoes of %d B checked over SMT (TLS 1.%d records), mean RTT %.1f us\n",
		n, size, minor, float64(total.Microseconds())/float64(n))
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "server" && os.Args[1] != "client") {
		fmt.Fprintf(os.Stderr, "usage: %s server|client [flags]\n", os.Args[0])
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	server := fs.String("a", "", "server IPv4 address (client)")
	homaPort := fs.Int("p", 2000, "server's Homa port")
	tlsPort := fs.Int("t", 4433, "server's TLS (TCP) port")
	tls13 := fs.Bool("3", false, "TLS 1.3 records (default 1.2)")
	size := fs.Int("l", 1500, "message bytes (client)")
	n := fs.Int("n", 1000, "RPCs (client)")
	fs.Parse(os.Args[2:])
	if fs.NArg() > 0 {
		fs.Usage()
		os.Exit(2)
	}
	if os.Args[1] == "server" {
		serve(*homaPort, *tlsPort)
	} else if *server == "" || *size <= 0 || *n <= 0 {
		fs.Usage()
		os.Exit(2)
	} else {
		client(*server, *homaPort, *tlsPort, *tls13, *size, *n)
	}
}
