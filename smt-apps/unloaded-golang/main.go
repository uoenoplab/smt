// simple_server / simple_client in Go: unloaded/'s echo programs with the
// same options and output, one RPC in flight. With --handshake the SMT keys
// come from a TLS 1.3 handshake over Homa (handshake-c/'s protocol), with
// --mtls a mutual one; without, the fixed test keys of unloaded/. The binary
// acts as the server when its name ends in "server".
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	ipprotoHoma  = 146
	soHomaRcvbuf = 10
	solTLS       = 282
	tcpULP       = 31
	tcpQuickack  = 12
	bpageSize    = 1 << 16
	bufPages     = 4000 // as unloaded/: 256 MB, untouched pages cost nothing
	maxMsg       = 1000000
	hsPort       = 4433
	label        = "EXPORTER-SMT-NG keys"
)

// struct homa_sendmsg_args and struct homa_recvmsg_args (homa.h).
type sendArgs struct {
	ID, Cookie      uint64
	Flags, Reserved uint32
}

type recvArgs struct {
	ID, Cookie          uint64
	NumBpages, Reserved uint32
	Offsets             [16]uint32
}

// Options, as unloaded/'s.
var (
	server              bool
	proto               string
	addr                syscall.RawSockaddrInet4
	port                int
	reqSize, respSize   int
	numRtts             int
	check, hs, mtls     bool
	verbose             int
	stop                atomic.Bool
	shutdownFd          atomic.Int64 // the client's socket, shut down by Ctrl-C
	debugf, infof, hexf = logger(1), logger(0), func(string, []byte) {}
)

func logger(level int) func(string, ...any) {
	return func(f string, a ...any) {
		if verbose >= level {
			log.Printf(f, a...)
		}
	}
}

func fatal(f string, a ...any) {
	log.Printf("FATAL "+f, a...)
	os.Exit(1)
}

func usage() {
	p := filepath.Base(os.Args[0])
	fmt.Printf("Usage: %s [OPTIONS]\n  --proto <homa|smt|tcp|tcp_ktls>\n", p)
	if server {
		fmt.Printf("  -p, --listen-port <port>\n")
	} else {
		fmt.Printf("  -a, --server-address <address>\n  -p, --server-port <port>\n")
	}
	fmt.Printf("  -l, --payload-size <size> | <request-size>,<response-size>\n")
	if !server {
		fmt.Printf("  -n, --num-rtts <count>    stop after <count> round trips (default: Ctrl-C)\n" +
			"  -c, --check               Homa/SMT: check every echoed byte\n")
	}
	fmt.Printf("  --handshake               SMT: keys from a TLS 1.3 handshake on Homa port %d\n"+
		"  --mtls                    with --handshake: the client presents client.pem, the server requires one\n"+
		"  -v, --verbose (repeat)    -q, --quiet    -h, --help\n"+
		"Environment: HOMA_ECHO_PAYLOAD=fixed|mod|random, HOMA_ECHO_PIN_CORE_DISABLE,\n"+
		"  SMT_TLS=13, SMT_KEY_BITS=256 (fixed keys)\n", hsPort)
	os.Exit(1)
}

func parseArgs() {
	server = strings.HasSuffix(filepath.Base(os.Args[0]), "server")
	args := os.Args[1:]
	val := func(i *int) string {
		if *i+1 >= len(args) {
			usage()
		}
		*i++
		return args[*i]
	}
	num := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil {
			usage()
		}
		return n
	}
	for i := 0; i < len(args); i++ {
		a, v, hasV := strings.Cut(args[i], "=")
		if hasV {
			args = append(args[:i+1], append([]string{v}, args[i+1:]...)...)
			args[i] = a
		}
		switch a {
		case "--proto", "-r":
			proto = val(&i)
		case "-a", "--server-address":
			ips, err := net.LookupIP(val(&i))
			if err != nil || len(ips) == 0 || ips[0].To4() == nil {
				fatal("server address: %v", err)
			}
			copy(addr.Addr[:], ips[0].To4())
		case "-p", "--server-port", "--listen-port":
			port = num(val(&i))
		case "-l", "--payload-size":
			r, s, pair := strings.Cut(val(&i), ",")
			reqSize, respSize = num(r), num(r)
			if pair {
				respSize = num(s)
			}
		case "-n", "--num-rtts":
			numRtts = num(val(&i))
		case "-c", "--check":
			check = true
		case "--handshake":
			hs = true
		case "--mtls":
			mtls = true
		case "-q", "--quiet":
			verbose = -1
		case "-v", "-vv", "-vvv":
			verbose += len(a) - 1
		case "--verbose":
			verbose++
		default:
			usage()
		}
	}
	switch {
	case len(os.Args) < 2:
		usage()
	case proto != "homa" && proto != "smt" && proto != "tcp" && proto != "tcp_ktls":
		fatal("--proto must be homa, smt, tcp or tcp_ktls")
	case reqSize <= 0 || respSize <= 0 || reqSize > maxMsg || respSize > maxMsg:
		fatal("payload sizes must be between 1 and %d", maxMsg)
	case !server && addr.Addr == [4]byte{}:
		fatal("server IP address must be provided for client mode")
	case port <= 0 || port > 65535:
		fatal("port must be between 1 and 65535")
	case (hs || mtls) && proto != "smt", mtls && !hs:
		fatal("--handshake is for --proto smt, and --mtls goes with --handshake")
	}
	addr.Family = syscall.AF_INET
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:], uint16(port))
	if verbose >= 3 {
		hexf = func(t string, b []byte) { log.Printf("%s\n%s", t, hex.Dump(b)) }
	}
	keys := "fixed"
	if hs {
		keys = "handshake (TLS 1.3 records, AES-GCM-128)"
		if mtls {
			keys = "mutual TLS handshake (TLS 1.3 records, AES-GCM-128)"
		}
	}
	role, where := "CLIENT", fmt.Sprintf("\"server\": \"%v:%d\"", net.IP(addr.Addr[:]), port)
	if server {
		role, where = "SERVER", fmt.Sprintf("\"listen\": 0.0.0.0:%d", port)
	}
	fmt.Printf("--- %s CONFIG ---\n{\n  \"protocol\": \"%s\",\n  %s,\n  \"payload_size\": \"%d,%d\",\n",
		role, proto, where, reqSize, respSize)
	if !server {
		if numRtts > 0 {
			fmt.Printf("  \"num_rtts\": %d,\n", numRtts)
		} else {
			fmt.Printf("  \"num_rtts\": \"Stop with Ctrl-C\",\n")
		}
	}
	if proto == "smt" {
		fmt.Printf("  \"keys\": \"%s\",\n", keys)
	}
	level := map[int]string{-1: "quiet", 0: "info", 1: "debug", 2: "trace"}[min(verbose, 3)]
	if verbose >= 3 {
		level = "trace with hexdump"
	}
	fmt.Printf("  \"verbose_level\": \"%s\"\n}\n--- %s CONFIG ---\n\n", level, role)
}

// payload fills b as HOMA_ECHO_PAYLOAD says.
func payload(b []byte) {
	switch os.Getenv("HOMA_ECHO_PAYLOAD") {
	case "", "fixed":
		for i := range b {
			b[i] = '?'
		}
	case "mod":
		for i := range b {
			b[i] = byte(i)
		}
	case "random":
		f, err := os.Open("/dev/urandom")
		if err == nil {
			_, err = io.ReadFull(f, b)
		}
		if err != nil {
			fatal("/dev/urandom: %v", err)
		}
	default:
		fatal("HOMA_ECHO_PAYLOAD must be fixed, mod or random")
	}
}

func setsockopt(fd, level, opt int, b []byte) error {
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// serve echoes every request, with resp_size bytes: the request's, cut or
// followed by payload.
func serve() {
	extra := make([]byte, max(0, respSize-reqSize))
	payload(extra)
	if proto == "tcp" || proto == "tcp_ktls" {
		lfd, buf := tcpSocket(), make([]byte, max(reqSize, respSize))
		copy(buf[reqSize:], extra)
		for {
			fd, _, err := syscall.Accept(lfd)
			if err != nil {
				fatal("accept: %v", err)
			}
			tcpOpts(fd)
			if proto == "tcp_ktls" {
				fixedKeys(fd)
			}
			for full(syscall.Read, fd, buf[:reqSize]) == nil && full(syscall.Write, fd, buf[:respSize]) == nil {
			}
			syscall.Close(fd)
		}
	}
	data := homaOpen(port)
	if hs {
		go handshakes(data.fd)
	} else if proto == "smt" {
		fixedKeys(data.fd)
	}
	for {
		var src syscall.RawSockaddrInet4
		parts, n, err := data.recv(&src)
		if err == nil && n != reqSize {
			err = fmt.Errorf("received incorrect request size %d", n)
		}
		if err != nil {
			fatal("recvmsg: %v", err)
		}
		if left := respSize; left < n {
			for i := range parts {
				parts[i] = parts[i][:min(len(parts[i]), max(0, left))]
				left -= len(parts[i])
			}
		}
		if verbose >= 1 {
			debugf("server recv %d bytes, rpc %d", n, data.ra.ID)
			hexf("server recv", bytes.Join(parts, nil))
		}
		if err = data.send(&src, data.ra.ID, append(parts, extra)...); err != nil {
			fatal("sendmsg: %v", err)
		}
	}
}

func client() {
	req, rtts := make([]byte, reqSize), []float64{}
	payload(req)
	var seq uint64
	var rpc func() ([][]byte, error) // the response, part by part
	start := time.Now()
	if proto == "tcp" || proto == "tcp_ktls" {
		fd, resp := tcpSocket(), make([]byte, respSize)
		if proto == "tcp_ktls" {
			fixedKeys(fd)
		}
		shutdownFd.Store(int64(fd))
		rpc = func() ([][]byte, error) {
			err := full(syscall.Write, fd, req)
			if err == nil {
				err = full(syscall.Read, fd, resp)
			}
			return [][]byte{resp}, err
		}
	} else {
		data := homaOpen(0)
		if hs {
			clientHandshake(data)
		} else if proto == "smt" {
			fixedKeys(data.fd)
		}
		shutdownFd.Store(int64(data.fd))
		rpc = func() ([][]byte, error) {
			if err := data.send(&addr, 0, req); err != nil {
				return nil, err
			}
			parts, _, err := data.recv(nil)
			return parts, err
		}
	}
	if numRtts > 0 {
		infof("Start sending RPC, stopping after %d rtts...", numRtts)
	} else {
		infof("Start sending RPC, Press Ctrl+C to stop...")
	}
	for total := 0; !stop.Load() && (numRtts == 0 || total < numRtts); total++ {
		if check { // stamp the RPC's number into every 1 KB of the request
			seq++
			for i := 0; i+8 <= reqSize; i += 1024 {
				binary.NativeEndian.PutUint64(req[i:], seq)
			}
		}
		t0 := time.Now()
		parts, err := rpc()
		rtt := float64(time.Since(t0).Nanoseconds()) / 1e3
		if err != nil && stop.Load() {
			break // Ctrl-C while waiting
		}
		n := 0
		for _, p := range parts {
			if check && n < reqSize && !bytes.Equal(p[:min(len(p), reqSize-n)], req[n:][:min(len(p), reqSize-n)]) {
				err = fmt.Errorf("echo mismatch in rpc %d", seq)
			}
			n += len(p)
		}
		if err == nil && n != respSize {
			err = fmt.Errorf("received incorrect response size %d", n)
		}
		if err != nil {
			fatal("%v", err)
		}
		rtts = append(rtts, rtt)
		if verbose >= 1 {
			debugf("client rpc %d, rtt %.2f us", total, rtt)
			hexf("client recv", bytes.Join(parts, nil))
		}
	}
	result(time.Since(start).Seconds(), rtts)
}

// result prints unloaded/'s RESULT block; the first 2 RTTs are warm-up.
func result(secs float64, rtts []float64) {
	kops := float64(len(rtts)) / secs / 1000
	r := rtts[min(2, max(0, len(rtts)-1)):] // keep one at least
	if len(r) == 0 {
		r = []float64{0}
	}
	sort.Float64s(r)
	var sum, sq float64
	for _, v := range r {
		sum += v
	}
	avg := sum / float64(len(r))
	for _, v := range r {
		sq += (v - avg) * (v - avg)
	}
	pct := func(p float64) float64 { return r[max(0, int(float64(len(r))*p/100)-1)] }
	fmt.Printf("\n--- RESULT ---\n{\n  \"bench_time\": %f,\n  \"total_rpcs\": %d,\n  \"kops_per_second\": %.2f,\n"+
		"  \"tx_throughput_mbps\": %.2f,\n  \"rx_throughput_mbps\": %.2f,\n  \"average_rtt_us\": %.2f,\n"+
		"  \"average_stddev_rtt_us\": %.2f,\n  \"p50_median_rtt_us\": %.2f,\n  \"p95_rtt_us\": %.2f,\n"+
		"  \"p99_rtt_us\": %.2f\n}\n--- RESULT ---\n", secs, len(rtts), kops,
		kops*1000*float64(reqSize)*8/(1<<20), kops*1000*float64(respSize)*8/(1<<20), avg,
		math.Sqrt(sq/float64(max(1, len(r)-1))), pct(50), pct(95), pct(99))
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	parseArgs()
	if os.Getenv("HOMA_ECHO_PIN_CORE_DISABLE") == "" { // core 1, as unloaded/
		runtime.LockOSThread()
		mask := uint64(1 << 1)
		if _, _, e := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0, 8, uintptr(unsafe.Pointer(&mask))); e != 0 {
			fatal("pinning to core 1: %v", e)
		}
	}
	if server {
		serve()
	}
	// Ctrl-C: stop after this RPC, or now if it is stuck.
	shutdownFd.Store(-1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		stop.Store(true)
		signal.Stop(sig)
		syscall.Shutdown(int(shutdownFd.Load()), syscall.SHUT_RDWR)
	}()
	client()
}
