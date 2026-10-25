// Homa and TCP sockets.

package main

import (
	"encoding/binary"
	"io"
	"syscall"
	"unsafe"
)

// homaSock is a Homa socket and the bpages of its last message, which the
// next recv returns. One goroutine receives on it.
type homaSock struct {
	fd  int
	buf []byte
	ra  recvArgs
}

func homaOpen(port int) *homaSock {
	s := &homaSock{}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, ipprotoHoma)
	if s.fd = fd; err == nil && port != 0 {
		err = syscall.Bind(fd, &syscall.SockaddrInet4{Port: port})
	}
	if err == nil {
		s.buf, err = syscall.Mmap(-1, 0, bufPages*bpageSize,
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	}
	if err == nil { // struct homa_rcvbuf_args
		b := binary.NativeEndian.AppendUint64(nil, uint64(uintptr(unsafe.Pointer(&s.buf[0]))))
		err = setsockopt(fd, ipprotoHoma, soHomaRcvbuf, binary.NativeEndian.AppendUint64(b, uint64(len(s.buf))))
	}
	if err != nil {
		fatal("Homa socket: %v", err)
	}
	return s
}

// msg makes a sendmsg or recvmsg call, again when a signal interrupts it (Go
// preempts goroutines with signals). That is safe: recvmsg gives back its
// bpages before it waits, and sendmsg is interrupted only before it creates
// the RPC.
func (s *homaSock) msg(trap uintptr, peer *syscall.RawSockaddrInet4, iov []syscall.Iovec, args unsafe.Pointer, argsLen int) (int, error) {
	m := syscall.Msghdr{Control: (*byte)(args), Controllen: uint64(argsLen)}
	if peer != nil {
		m.Name, m.Namelen = (*byte)(unsafe.Pointer(peer)), syscall.SizeofSockaddrInet4
	}
	if len(iov) > 0 {
		m.Iov, m.Iovlen = &iov[0], uint64(len(iov))
	}
	for {
		n, _, e := syscall.Syscall(trap, uintptr(s.fd), uintptr(unsafe.Pointer(&m)), 0)
		if e == 0 {
			return int(n), nil
		} else if e != syscall.EINTR {
			return 0, e
		}
	}
}

// recv waits for the next message (any request on a server socket) and
// returns its bytes, bpage by bpage, valid until the next recv.
func (s *homaSock) recv(src *syscall.RawSockaddrInet4) ([][]byte, int, error) {
	s.ra.ID = 0
	n, err := s.msg(syscall.SYS_RECVMSG, src, nil, unsafe.Pointer(&s.ra), int(unsafe.Sizeof(s.ra)))
	if err != nil {
		return nil, 0, err
	}
	parts := make([][]byte, s.ra.NumBpages)
	for i := range parts {
		parts[i] = s.buf[s.ra.Offsets[i]:][:min(n-i*bpageSize, bpageSize)]
	}
	return parts, n, nil
}

// send sends a request when id is 0, else the reply to RPC id.
func (s *homaSock) send(to *syscall.RawSockaddrInet4, id uint64, parts ...[]byte) error {
	iov := make([]syscall.Iovec, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			iov = append(iov, syscall.Iovec{Base: &p[0]})
			iov[len(iov)-1].SetLen(len(p))
		}
	}
	sa := sendArgs{ID: id}
	_, err := s.msg(syscall.SYS_SENDMSG, to, iov, unsafe.Pointer(&sa), 0)
	return err
}

// tcpSocket returns a TCP socket, connected to the server or accepting on
// the listen port.
func tcpSocket() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil && server {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if err = syscall.Bind(fd, &syscall.SockaddrInet4{Port: port}); err == nil {
			err = syscall.Listen(fd, 1)
		}
	} else if err == nil {
		tcpOpts(fd)
		err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: port, Addr: addr.Addr})
	}
	if err != nil {
		fatal("TCP socket: %v", err)
	}
	return fd
}

// tcpOpts: no Nagle, quick ACKs, as unloaded/.
func tcpOpts(fd int) {
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, tcpQuickack, 1)
}

// full reads or writes all of b on a TCP socket.
func full(rw func(int, []byte) (int, error), fd int, b []byte) error {
	for len(b) > 0 {
		n, err := rw(fd, b)
		if err == syscall.EINTR {
			continue
		} else if err == nil && n == 0 {
			err = io.EOF
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
