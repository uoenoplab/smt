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
	binary.LittleEndian.PutUint64(args, uint64(uintptr(unsafe.Pointer(&rbuf[0]))))
	binary.LittleEndian.PutUint64(args[8:], uint64(len(rbuf)))
	setsockopt(ipprotoHoma, soHomaRcvbuf, args)
}

// setKeys installs tx and rx (each a key followed by its IV) for the peer at
// ip:port: struct smt_aes_gcm_128_info, a packed struct smt_info followed by
// struct tls12_crypto_info_aes_gcm_128.
func setKeys(ip net.IP, port int, tls13 bool, tx, rx []byte) {
	for i, k := range [][]byte{tx, rx} {
		b := make([]byte, 50)
		copy(b[0:4], ip.To4())                           // peer_addr
		binary.BigEndian.PutUint16(b[4:6], uint16(port)) // peer_port; local_addr 0
		version := uint16(0x0303)
		if tls13 {
			version = 0x0304
		}
		binary.LittleEndian.PutUint16(b[10:12], version)
		binary.LittleEndian.PutUint16(b[12:14], 51) // TLS_CIPHER_AES_GCM_128
		copy(b[22:38], k[:keyLen])                  // key
		copy(b[38:42], k[keyLen:keyLen+4])          // salt
		// TLS 1.3 nonces use the whole IV; TLS 1.2 records carry an
		// explicit nonce, which must start out equal to rec_seq (0).
		if tls13 {
			copy(b[14:22], k[keyLen+4:keyLen+ivLen]) // iv
		}
		setsockopt(solTLS, []int{tlsTX, tlsRX}[i], b)
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
// preempts goroutines with signals). That is safe for recvmsg: Homa frees
// the bpages it was handed and writes num_bpages 0 back before it waits.
func sys(trap uintptr, m *syscall.Msghdr) int {
	for {
		n, _, e := syscall.Syscall(trap, uintptr(homaFD), uintptr(unsafe.Pointer(m)), 0)
		if e == 0 {
			return int(n)
		}
		if e != syscall.EINTR {
			log.Fatalf("syscall %d: %v", trap, e)
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
	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", tlsPort),
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		hello := make([]byte, 3)
		conn := c.(*tls.Conn)
		if _, err = io.ReadFull(conn, hello); err != nil {
			log.Print("handshake: ", err)
			conn.Close()
			continue
		}
		cs := conn.ConnectionState()
		keys, err := cs.ExportKeyingMaterial(label, nil, 2*(keyLen+ivLen))
		if err != nil {
			log.Fatal(err)
		}
		peer := conn.RemoteAddr().(*net.TCPAddr)
		port := int(binary.BigEndian.Uint16(hello[:2]))
		setKeys(peer.IP, port, hello[2] == 13, keys[keyLen+ivLen:], keys[:keyLen+ivLen])
		conn.Write([]byte{1})
		fmt.Printf("keys for %s:%d, TLS 1.%d records\n", peer.IP, port, map[bool]int{true: 3, false: 2}[hello[2] == 13])
		conn.Close()
	}
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
		n := sys(syscall.SYS_RECVMSG, msghdr(&src, nil, unsafe.Pointer(&ra), int(unsafe.Sizeof(ra))))
		sa := sendArgs{ID: ra.ID}
		sys(syscall.SYS_SENDMSG, msghdr(&src, bpages(&ra, n), unsafe.Pointer(&sa), 0))
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
	roots.AppendCertsFromPEM(pem)
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
	conn.Write(hello)
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
	var ra recvArgs
	var total time.Duration
	for i := 0; i < n; i++ {
		for j := range req {
			req[j] = byte(i + j)
		}
		t0 := time.Now()
		iov := []syscall.Iovec{{Base: &req[0]}}
		iov[0].SetLen(size)
		var sa sendArgs
		sys(syscall.SYS_SENDMSG, msghdr(to, iov, unsafe.Pointer(&sa), 0))
		ra.ID = 0
		got := sys(syscall.SYS_RECVMSG, msghdr(nil, nil, unsafe.Pointer(&ra), int(unsafe.Sizeof(ra))))
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
	fmt.Printf("%d echoes of %d B checked over SMT (TLS 1.%d records), mean RTT %.1f us\n",
		n, size, map[bool]int{true: 3, false: 2}[tls13], float64(total.Microseconds())/float64(n))
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
	if os.Args[1] == "server" {
		serve(*homaPort, *tlsPort)
	} else if *server == "" || *size <= 0 || *n <= 0 {
		fs.Usage()
		os.Exit(2)
	} else {
		client(*server, *homaPort, *tlsPort, *tls13, *size, *n)
	}
}
