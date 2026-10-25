//! Homa and TCP sockets.

use crate::{die, Opts, STOP};
use std::cell::UnsafeCell;
use std::io::{self, ErrorKind};
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ptr;
use std::sync::atomic::Ordering;

const IPPROTO_HOMA: i32 = 146;
const SO_HOMA_RCVBUF: i32 = 10;
const TCP_QUICKACK: i32 = 12;
const BPAGE_SIZE: usize = 1 << 16;
const BUF_PAGES: usize = 4000; // as unloaded/: 256 MB, untouched pages cost nothing

/// struct homa_sendmsg_args and struct homa_recvmsg_args (homa.h).
#[repr(C)]
#[derive(Default)]
struct SendArgs {
    id: u64,
    cookie: u64,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Default)]
struct RecvArgs {
    id: u64,
    cookie: u64,
    num_bpages: u32,
    reserved: u32,
    offsets: [u32; 16],
}

pub fn sockaddr(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    let mut a: libc::sockaddr_in = unsafe { zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    a
}

pub fn setsockopt(fd: i32, level: i32, opt: i32, v: &[u8]) -> io::Result<()> {
    let p = v.as_ptr() as *const libc::c_void;
    match unsafe { libc::setsockopt(fd, level, opt, p, v.len() as u32) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn check(r: i32, what: &str) -> i32 {
    if r < 0 {
        die(what, io::Error::last_os_error());
    }
    r
}

/// A Homa socket and the bpages of its last message, which the next recv
/// returns. One thread receives on it.
pub struct HomaSock {
    pub fd: i32,
    buf: *mut u8,
    ra: UnsafeCell<RecvArgs>,
}

impl HomaSock {
    pub fn open(port: u16) -> HomaSock {
        let len = BUF_PAGES * BPAGE_SIZE;
        let a = sockaddr(Ipv4Addr::UNSPECIFIED, port);
        let fd = check(
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, IPPROTO_HOMA) },
            "Homa socket",
        );
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if buf == libc::MAP_FAILED {
            die("mmap", io::Error::last_os_error());
        }
        if port != 0 {
            let sa = &a as *const _ as *const libc::sockaddr;
            check(
                unsafe { libc::bind(fd, sa, size_of::<libc::sockaddr_in>() as u32) },
                "Homa bind",
            );
        }
        let args = [(buf as u64).to_ne_bytes(), (len as u64).to_ne_bytes()].concat(); // struct homa_rcvbuf_args
        setsockopt(fd, IPPROTO_HOMA, SO_HOMA_RCVBUF, &args)
            .unwrap_or_else(|e| die("Homa socket", e));
        HomaSock {
            fd,
            buf: buf as *mut u8,
            ra: UnsafeCell::default(),
        }
    }

    /// sendmsg or recvmsg, again when a signal interrupts it, unless it was
    /// Ctrl-C.
    fn msg(
        &self,
        recv: bool,
        peer: *const libc::sockaddr_in,
        iov: &mut [libc::iovec],
        args: *mut libc::c_void,
    ) -> io::Result<usize> {
        let mut m: libc::msghdr = unsafe { zeroed() };
        m.msg_name = peer as *mut _;
        m.msg_namelen = size_of::<libc::sockaddr_in>() as u32;
        m.msg_iov = iov.as_mut_ptr();
        m.msg_iovlen = iov.len();
        m.msg_control = args;
        m.msg_controllen = if recv { size_of::<RecvArgs>() } else { 0 };
        loop {
            let n = unsafe {
                if recv {
                    libc::recvmsg(self.fd, &mut m, 0)
                } else {
                    libc::sendmsg(self.fd, &m, 0)
                }
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != ErrorKind::Interrupted || STOP.load(Ordering::Relaxed) {
                return Err(e);
            }
        }
    }

    /// Waits for the next message (any request on a server socket) and
    /// returns its bytes, bpage by bpage, valid until the next recv, and the
    /// RPC's id.
    pub fn recv(&self, src: &mut libc::sockaddr_in) -> io::Result<(Vec<&[u8]>, u64)> {
        let ra = self.ra.get();
        unsafe { (*ra).id = 0 };
        let n = self.msg(true, src, &mut [], ra as *mut libc::c_void)?;
        let ra = unsafe { &*ra };
        let parts = (0..ra.num_bpages as usize)
            .map(|i| unsafe {
                let len = (n - i * BPAGE_SIZE).min(BPAGE_SIZE);
                std::slice::from_raw_parts(self.buf.add(ra.offsets[i] as usize), len)
            })
            .collect();
        Ok((parts, ra.id))
    }

    /// Sends a request when id is 0, else the reply to RPC id.
    pub fn send(&self, to: &libc::sockaddr_in, id: u64, parts: &[&[u8]]) -> io::Result<()> {
        let mut iov: Vec<libc::iovec> = parts
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| libc::iovec {
                iov_base: p.as_ptr() as *mut _,
                iov_len: p.len(),
            })
            .collect();
        let mut sa = SendArgs {
            id,
            ..Default::default()
        };
        self.msg(
            false,
            to,
            &mut iov,
            &mut sa as *mut SendArgs as *mut libc::c_void,
        )
        .map(|_| ())
    }
}

/// A TCP socket, connected to the server or accepting on the listen port.
pub fn tcp_socket(o: &Opts) -> i32 {
    let fd = check(
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
        "TCP socket",
    );
    let a = sockaddr(
        if o.server {
            Ipv4Addr::UNSPECIFIED
        } else {
            o.addr
        },
        o.port,
    );
    let (sa, len) = (
        &a as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as u32,
    );
    let one = 1i32.to_ne_bytes();
    if o.server {
        setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one).ok();
        check(unsafe { libc::bind(fd, sa, len) }, "TCP bind");
        check(unsafe { libc::listen(fd, 1) }, "TCP listen");
    } else {
        tcp_opts(fd);
        check(unsafe { libc::connect(fd, sa, len) }, "TCP connect");
    }
    fd
}

/// No Nagle, quick ACKs, as unloaded/.
fn tcp_opts(fd: i32) {
    let one = 1i32.to_ne_bytes();
    setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, &one).ok();
    setsockopt(fd, libc::IPPROTO_TCP, TCP_QUICKACK, &one).ok();
}

pub fn accept(fd: i32) -> i32 {
    let fd = check(
        unsafe { libc::accept(fd, ptr::null_mut(), ptr::null_mut()) },
        "accept",
    );
    tcp_opts(fd);
    fd
}

/// Reads (write false) or writes all of b on a TCP socket.
pub fn full(fd: i32, write: bool, mut b: &mut [u8]) -> io::Result<()> {
    while !b.is_empty() {
        let p = b.as_mut_ptr() as *mut libc::c_void;
        let n = unsafe {
            if write {
                libc::write(fd, p, b.len())
            } else {
                libc::read(fd, p, b.len())
            }
        };
        if n < 0
            && io::Error::last_os_error().kind() == ErrorKind::Interrupted
            && !STOP.load(Ordering::Relaxed)
        {
            continue;
        }
        if n <= 0 {
            return Err(if n == 0 {
                ErrorKind::UnexpectedEof.into()
            } else {
                io::Error::last_os_error()
            });
        }
        b = &mut b[n as usize..];
    }
    Ok(())
}
