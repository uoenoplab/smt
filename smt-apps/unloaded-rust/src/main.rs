//! simple_server / simple_client in Rust: unloaded/'s echo programs with the
//! same options and output, one RPC in flight. With --handshake the SMT keys
//! come from a TLS 1.3 handshake over Homa (handshake-c/'s protocol), with
//! --mtls a mutual one; without, the fixed test keys of unloaded/. The binary
//! acts as the server when its name ends in "server".

mod keys;
mod socket;

use socket::{full, sockaddr, tcp_socket, HomaSock};
use std::fmt::Display;
use std::io::Read;
use std::mem::zeroed;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use std::{env, process, thread};

const MAX_MSG: usize = 1000000;
pub static STOP: AtomicBool = AtomicBool::new(false);

pub fn die(what: &str, e: impl Display) -> ! {
    eprintln!("FATAL {what}: {e}");
    process::exit(1)
}

/// Options, as unloaded/'s.
pub struct Opts {
    pub server: bool,
    pub proto: String,
    pub addr: Ipv4Addr,
    pub port: u16,
    req: usize,
    resp: usize,
    rtts: usize,
    check: bool,
    hs: bool,
    pub mtls: bool,
    verbose: i32,
}

impl Opts {
    pub fn info(&self, s: &str) {
        if self.verbose >= 0 {
            eprintln!("{s}");
        }
    }

    fn debug(&self, s: &str) {
        if self.verbose >= 1 {
            eprintln!("{s}");
        }
    }

    fn hexdump(&self, title: &str, parts: &[&[u8]]) {
        if self.verbose >= 3 {
            eprintln!("{title}");
            for (i, line) in parts.concat().chunks(16).enumerate() {
                let hex: Vec<String> = line.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("{:08x}  {}", i * 16, hex.join(" "));
            }
        }
    }
}

fn usage(server: bool) -> ! {
    let p = env::args().next().unwrap_or_default();
    println!("Usage: {p} [OPTIONS]\n  --proto <homa|smt|tcp|tcp_ktls>");
    if server {
        println!("  -p, --listen-port <port>");
    } else {
        println!("  -a, --server-address <address>\n  -p, --server-port <port>");
    }
    println!("  -l, --payload-size <size> | <request-size>,<response-size>");
    if !server {
        println!("  -n, --num-rtts <count>    stop after <count> round trips (default: Ctrl-C)");
        println!("  -c, --check               Homa/SMT: check every echoed byte");
    }
    println!(
        "  --handshake               SMT: keys from a TLS 1.3 handshake on Homa port {}",
        keys::HS_PORT
    );
    println!("  --mtls                    with --handshake: the client presents client.pem, the server requires one");
    println!("  -v, --verbose (repeat)    -q, --quiet    -h, --help");
    println!("Environment: HOMA_ECHO_PAYLOAD=fixed|mod|random, HOMA_ECHO_PIN_CORE_DISABLE,");
    println!("  SMT_TLS=13, SMT_KEY_BITS=256 (fixed keys)");
    process::exit(1)
}

fn parse_args() -> Opts {
    let argv: Vec<String> = env::args().collect();
    let mut o = Opts {
        server: argv[0].ends_with("server"),
        proto: String::new(),
        addr: Ipv4Addr::UNSPECIFIED,
        port: 0,
        req: 0,
        resp: 0,
        rtts: 0,
        check: false,
        hs: false,
        mtls: false,
        verbose: 0,
    };
    let args: Vec<String> = argv[1..]
        .iter()
        .flat_map(|a| match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => vec![k.to_string(), v.to_string()],
            _ => vec![a.clone()],
        })
        .collect();
    let mut it = args.iter();
    let server = o.server;
    let num = |v: Option<&String>| -> usize {
        v.and_then(|v| v.parse().ok())
            .unwrap_or_else(|| usage(server))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--proto" | "-r" => o.proto = it.next().cloned().unwrap_or_else(|| usage(server)),
            "-a" | "--server-address" => {
                let name = it.next().unwrap_or_else(|| usage(server));
                let ip = (name.as_str(), 0).to_socket_addrs().ok().and_then(|mut i| {
                    i.find_map(|a| match a.ip() {
                        std::net::IpAddr::V4(v4) => Some(v4),
                        _ => None,
                    })
                });
                o.addr = ip.unwrap_or_else(|| die("server address", name));
            }
            "-p" | "--server-port" | "--listen-port" => {
                o.port = num(it.next()).try_into().unwrap_or(0)
            }
            "-l" | "--payload-size" => {
                let v = it.next().unwrap_or_else(|| usage(server));
                let (r, s) = v.split_once(',').unwrap_or((v, v));
                (o.req, o.resp) = (num(Some(&r.to_string())), num(Some(&s.to_string())));
            }
            "-n" | "--num-rtts" => o.rtts = num(it.next()),
            "-c" | "--check" => o.check = true,
            "--handshake" => o.hs = true,
            "--mtls" => o.mtls = true,
            "-q" | "--quiet" => o.verbose = -1,
            "-v" | "-vv" | "-vvv" => o.verbose += a.len() as i32 - 1,
            "--verbose" => o.verbose += 1,
            _ => usage(server),
        }
    }
    let err = if argv.len() < 2 {
        usage(server)
    } else if !["homa", "smt", "tcp", "tcp_ktls"].contains(&o.proto.as_str()) {
        "--proto must be homa, smt, tcp or tcp_ktls"
    } else if o.req == 0 || o.resp == 0 || o.req > MAX_MSG || o.resp > MAX_MSG {
        "payload sizes must be between 1 and 1000000"
    } else if !o.server && o.addr.is_unspecified() {
        "server IP address must be provided for client mode"
    } else if o.port == 0 {
        "port must be between 1 and 65535"
    } else if (o.hs || o.mtls) && o.proto != "smt" || o.mtls && !o.hs {
        "--handshake is for --proto smt, and --mtls goes with --handshake"
    } else {
        ""
    };
    if !err.is_empty() {
        die("options", err);
    }
    let (role, wher) = if o.server {
        ("SERVER", format!("\"listen\": 0.0.0.0:{}", o.port))
    } else {
        ("CLIENT", format!("\"server\": \"{}:{}\"", o.addr, o.port))
    };
    println!("--- {role} CONFIG ---\n{{\n  \"protocol\": \"{}\",\n  {wher},\n  \"payload_size\": \"{},{}\",", o.proto, o.req, o.resp);
    if !o.server {
        match o.rtts {
            0 => println!("  \"num_rtts\": \"Stop with Ctrl-C\","),
            n => println!("  \"num_rtts\": {n},"),
        }
    }
    if o.proto == "smt" {
        let keys = match (o.hs, o.mtls) {
            (false, _) => "fixed",
            (true, false) => "handshake (TLS 1.3 records, AES-GCM-128)",
            (true, true) => "mutual TLS handshake (TLS 1.3 records, AES-GCM-128)",
        };
        println!("  \"keys\": \"{keys}\",");
    }
    let level = ["quiet", "info", "debug", "trace", "trace with hexdump"]
        [(o.verbose + 1).clamp(0, 4) as usize];
    println!("  \"verbose_level\": \"{level}\"\n}}\n--- {role} CONFIG ---\n");
    o
}

/// Fills b as HOMA_ECHO_PAYLOAD says.
fn payload(b: &mut [u8]) {
    match env::var("HOMA_ECHO_PAYLOAD").as_deref().unwrap_or("fixed") {
        "fixed" => b.fill(b'?'),
        "mod" => b.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8),
        "random" => std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(b))
            .unwrap_or_else(|e| die("/dev/urandom", e)),
        _ => die("HOMA_ECHO_PAYLOAD", "must be fixed, mod or random"),
    }
}

/// Echoes every request, with resp bytes: the request's, cut or followed by
/// payload.
fn serve(o: &'static Opts) -> ! {
    let mut extra = vec![0u8; o.resp.saturating_sub(o.req)];
    payload(&mut extra);
    if o.proto.starts_with("tcp") {
        let lfd = tcp_socket(o);
        let mut buf = vec![0u8; o.req.max(o.resp)];
        buf[o.req..].copy_from_slice(&extra);
        loop {
            let fd = socket::accept(lfd);
            if o.proto == "tcp_ktls" {
                keys::fixed_keys(o, fd);
            }
            while full(fd, false, &mut buf[..o.req]).is_ok()
                && full(fd, true, &mut buf[..o.resp]).is_ok()
            {}
            unsafe { libc::close(fd) };
        }
    }
    let data = HomaSock::open(o.port);
    let fd = data.fd;
    if o.hs {
        thread::spawn(move || keys::handshakes(o, fd));
    } else if o.proto == "smt" {
        keys::fixed_keys(o, fd);
    }
    loop {
        let mut src: libc::sockaddr_in = unsafe { zeroed() };
        let (mut parts, id) = data.recv(&mut src).unwrap_or_else(|e| die("recvmsg", e));
        let n: usize = parts.iter().map(|p| p.len()).sum();
        if n != o.req {
            die("recvmsg", format!("received incorrect request size {n}"));
        }
        let mut left = o.resp;
        for p in parts.iter_mut() {
            *p = &p[..p.len().min(left)];
            left -= p.len();
        }
        if o.verbose >= 1 {
            o.debug(&format!("server recv {n} bytes, rpc {id}"));
            o.hexdump("server recv", &parts);
        }
        parts.push(&extra);
        data.send(&src, id, &parts)
            .unwrap_or_else(|e| die("sendmsg", e));
    }
}

fn client(o: &Opts) {
    let mut req = vec![0u8; o.req];
    payload(&mut req);
    let mut resp = vec![0u8; o.resp];
    let (mut seq, mut rtts) = (0u64, Vec::new());
    let start = Instant::now();
    let tcp = o.proto.starts_with("tcp");
    let fd = if tcp { tcp_socket(o) } else { -1 };
    let data = if tcp { None } else { Some(HomaSock::open(0)) };
    match &data {
        None if o.proto == "tcp_ktls" => keys::fixed_keys(o, fd),
        Some(d) if o.hs => keys::client_handshake(o, d),
        Some(d) if o.proto == "smt" => keys::fixed_keys(o, d.fd),
        _ => {}
    }
    let to = sockaddr(o.addr, o.port);
    if o.rtts > 0 {
        o.info(&format!(
            "Start sending RPC, stopping after {} rtts...",
            o.rtts
        ));
    } else {
        o.info("Start sending RPC, Press Ctrl+C to stop...");
    }
    while !STOP.load(Ordering::Relaxed) && (o.rtts == 0 || rtts.len() < o.rtts) {
        if o.check {
            // stamp the RPC's number into every 1 KB of the request
            seq += 1;
            for i in (0..o.req.saturating_sub(7)).step_by(1024) {
                req[i..i + 8].copy_from_slice(&seq.to_ne_bytes());
            }
        }
        let t0 = Instant::now();
        let r = match data.as_ref() {
            None => full(fd, true, &mut req)
                .and_then(|()| full(fd, false, &mut resp))
                .map(|()| vec![&resp[..]]),
            Some(d) => d
                .send(&to, 0, &[&req])
                .and_then(|()| d.recv(&mut sockaddr(o.addr, 0)))
                .map(|(parts, _)| parts),
        };
        let rtt = t0.elapsed().as_nanos() as f64 / 1e3;
        if r.is_err() && STOP.load(Ordering::Relaxed) {
            break; // Ctrl-C while waiting
        }
        let parts = r.unwrap_or_else(|e| die("rpc", e));
        let mut n = 0;
        for p in &parts {
            let k = p.len().min(o.req.saturating_sub(n));
            if o.check && k > 0 && p[..k] != req[n..n + k] {
                die("rpc", format!("echo mismatch in rpc {seq}"));
            }
            n += p.len();
        }
        if n != o.resp {
            die("rpc", format!("received incorrect response size {n}"));
        }
        rtts.push(rtt);
        if o.verbose >= 1 {
            o.debug(&format!("client rpc {}, rtt {rtt:.2} us", rtts.len() - 1));
            o.hexdump("client recv", &parts);
        }
    }
    result(o, start.elapsed().as_secs_f64(), rtts);
}

/// Prints unloaded/'s RESULT block; the first 2 RTTs are warm-up.
fn result(o: &Opts, secs: f64, rtts: Vec<f64>) {
    let n = rtts.len();
    let kops = n as f64 / secs / 1000.0;
    let mut r = rtts[2.min(n.saturating_sub(1))..].to_vec(); // keep one at least
    if r.is_empty() {
        r.push(0.0);
    }
    r.sort_by(f64::total_cmp);
    let avg = r.iter().sum::<f64>() / r.len() as f64;
    let sd =
        (r.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / (r.len().max(2) - 1) as f64).sqrt();
    let pct = |p: f64| r[((r.len() as f64 * p / 100.0) as usize).max(1) - 1];
    let mbps = |size: usize| kops * 1000.0 * size as f64 * 8.0 / (1 << 20) as f64;
    println!(
        "\n--- RESULT ---\n{{\n  \"bench_time\": {secs:.6},\n  \"total_rpcs\": {n},\n  \"kops_per_second\": {kops:.2},\n  \
         \"tx_throughput_mbps\": {:.2},\n  \"rx_throughput_mbps\": {:.2},\n  \"average_rtt_us\": {avg:.2},\n  \
         \"average_stddev_rtt_us\": {sd:.2},\n  \"p50_median_rtt_us\": {:.2},\n  \"p95_rtt_us\": {:.2},\n  \
         \"p99_rtt_us\": {:.2}\n}}\n--- RESULT ---",
        mbps(o.req),
        mbps(o.resp),
        pct(50.0),
        pct(95.0),
        pct(99.0)
    );
}

extern "C" fn on_sigint(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}

fn main() {
    let o: &'static Opts = Box::leak(Box::new(parse_args()));
    if env::var_os("HOMA_ECHO_PIN_CORE_DISABLE").is_none() {
        // core 1, as unloaded/
        let mut set: libc::cpu_set_t = unsafe { zeroed() };
        unsafe { libc::CPU_SET(1, &mut set) };
        if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) } != 0
        {
            die("pinning to core 1", std::io::Error::last_os_error());
        }
    }
    if o.server {
        serve(o);
    }
    // Ctrl-C: stop after this RPC, or now if it is stuck (no SA_RESTART).
    unsafe {
        let mut sa: libc::sigaction = zeroed();
        sa.sa_sigaction = on_sigint as extern "C" fn(i32) as libc::sighandler_t;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
    client(o);
}
