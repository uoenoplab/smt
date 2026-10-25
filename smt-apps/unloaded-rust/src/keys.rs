//! Keys: unloaded/'s fixed ones, or from a TLS 1.3 handshake over Homa.

use crate::socket::{setsockopt, sockaddr, HomaSock};
use crate::{die, Opts};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig, ServerConnection,
};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const SOL_TLS: i32 = 282;
const TCP_ULP: i32 = 31;
pub const HS_PORT: u16 = 4433;
const LABEL: &[u8] = b"EXPORTER-SMT-NG keys";

/// struct tls12_crypto_info_aes_gcm_128 or _256: key, then IV (salt and
/// nonce), for TLS 1.2 or 1.3 records.
fn crypto_info(key: &[u8], iv: &[u8], tls13: bool) -> Vec<u8> {
    let mut b = vec![0u8; 24 + key.len()];
    b[..2].copy_from_slice(&(if tls13 { 0x0304u16 } else { 0x0303 }).to_ne_bytes());
    b[2..4].copy_from_slice(&(50 + key.len() as u16 / 16).to_ne_bytes()); // TLS_CIPHER_AES_GCM_128 / _256
    if tls13 {
        b[4..12].copy_from_slice(&iv[4..]); // TLS 1.2: the explicit nonce, rec_seq 0
    }
    b[12..12 + key.len()].copy_from_slice(key);
    b[12 + key.len()..16 + key.len()].copy_from_slice(&iv[..4]);
    b
}

/// Sets unloaded/'s test keys (smt_uapi.c) on a kTLS or SMT socket, for every
/// peer; nothing when net.homa.smt_fixed_key already gives some.
pub fn fixed_keys(o: &Opts, fd: i32) {
    let mut ck = vec![
        0x8D, 0xD2, 0x30, 0xA7, 0x7A, 0x05, 0xEB, 0x71, 0x15, 0x91, 0x29, 0xBC, 0xBC, 0xF6, 0x42,
        0x30,
    ];
    let civ = [
        0x87, 0xC6, 0x35, 0xC8, 0x17, 0x87, 0xDE, 0x4A, 0x88, 0x1D, 0xD2, 0xD5,
    ];
    let mut sk = vec![
        0x6C, 0xCF, 0x62, 0xFF, 0x4B, 0xE6, 0x14, 0x85, 0xD8, 0xBA, 0x29, 0xFE, 0x2E, 0x84, 0x7A,
        0x7F,
    ];
    let siv = [
        0xB9, 0xFA, 0x55, 0x83, 0xD5, 0x8F, 0x85, 0x18, 0xFF, 0xA6, 0x3E, 0x66,
    ];
    let smt = o.proto == "smt";
    if smt {
        let v = std::fs::read_to_string("/proc/sys/net/homa/smt_fixed_key").unwrap_or_default();
        if v.trim().parse::<i32>().unwrap_or(0) > 0 {
            return;
        }
    } else {
        setsockopt(fd, libc::IPPROTO_TCP, TCP_ULP, b"tls\0").unwrap_or_else(|e| die("kTLS", e));
    }
    if std::env::var("SMT_KEY_BITS").as_deref() == Ok("256") {
        ck.extend_from_within(..);
        sk.extend_from_within(..);
    }
    let (mut tx, mut rx) = ((&ck, &civ), (&sk, &siv));
    if o.server {
        (tx, rx) = (rx, tx);
    }
    let tls13 = std::env::var("SMT_TLS").as_deref() == Ok("13");
    for (i, (key, iv)) in [tx, rx].into_iter().enumerate() {
        let mut b = if smt { vec![0u8; 10] } else { vec![] }; // struct smt_info: any peer
        b.extend(crypto_info(key, iv, tls13));
        setsockopt(fd, SOL_TLS, 1 + i as i32, &b).unwrap_or_else(|e| die("setting keys", e));
    }
}

/// Takes the keys from the exporter (the client's first) and installs them on
/// fd for the peer at ip:port.
fn set_keys<D>(
    server: bool,
    fd: i32,
    conn: &ConnectionCommon<D>,
    ip: Ipv4Addr,
    port: u16,
) -> Result<(), String> {
    let k = conn
        .export_keying_material([0u8; 56], LABEL, None)
        .map_err(|e| e.to_string())?;
    for i in 0..2 {
        // TLS_TX with our own key, then TLS_RX
        let key = &k[(server as usize ^ i) * 28..][..28];
        let mut b = [&ip.octets()[..], &port.to_be_bytes(), &[0; 4]].concat();
        b.extend(crypto_info(&key[..16], &key[16..], true));
        setsockopt(fd, SOL_TLS, 1 + i as i32, &b).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// This end's certificate and key, and ca.pem.
fn certs(name: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let pem = format!("{name}.pem");
    let certs = CertificateDer::pem_file_iter(&pem).and_then(|i| i.collect::<Result<_, _>>());
    let key = PrivateKeyDer::from_pem_file(format!("{name}-key.pem"));
    (
        certs.unwrap_or_else(|e| die(&pem, e)),
        key.unwrap_or_else(|e| die(&pem, e)),
    )
}

fn ca() -> Arc<RootCertStore> {
    let mut ca = RootCertStore::empty();
    let certs =
        CertificateDer::pem_file_iter("ca.pem").and_then(|i| i.collect::<Result<Vec<_>, _>>());
    for c in certs.unwrap_or_else(|e| die("ca.pem (make cert)", e)) {
        ca.add(c).unwrap_or_else(|e| die("ca.pem", e));
    }
    Arc::new(ca)
}

/// Gives rustls a received message.
fn feed<D>(conn: &mut ConnectionCommon<D>, mut msg: &[u8]) -> Result<(), String> {
    while !msg.is_empty() {
        let n = conn.read_tls(&mut msg).map_err(|e| e.to_string())?;
        conn.process_new_packets().map_err(|e| e.to_string())?;
        if n == 0 {
            break; // closed
        }
    }
    Ok(())
}

/// What rustls has written.
fn drain<D>(conn: &mut ConnectionCommon<D>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}

/// Feeds a server handshake one request. Returns true once it is over, keys
/// installed or not.
fn handshake_step(
    o: &Opts,
    conn: &mut ServerConnection,
    msg: &[u8],
    fd: i32,
    ip: Ipv4Addr,
) -> bool {
    let mut p = [0u8; 2];
    if let Err(e) = feed(conn, msg) {
        eprintln!("handshake with {ip} failed: {e}"); // rustls has written its alert
        return true;
    }
    if conn.is_handshaking() {
        return false;
    }
    let r = match conn.reader().read_exact(&mut p) {
        Err(e) if e.kind() == ErrorKind::WouldBlock => return false,
        Err(e) => Err(e.to_string()),
        Ok(()) if p == [0, 0] => Err("Homa port 0".into()),
        Ok(()) => Ok(()),
    };
    let port = u16::from_be_bytes(p);
    match r.and_then(|()| set_keys(true, fd, conn, ip, port)) {
        Ok(()) => {
            conn.writer().write_all(&[1]).unwrap();
            let auth = if conn.peer_certificates().is_some() {
                ""
            } else {
                "not "
            };
            o.info(&format!("keys for {ip}:{port}, client {auth}authenticated"));
        }
        Err(e) => {
            eprintln!("handshake with {ip} failed: {e}");
            conn.send_close_notify(); // Homa can't send an empty reply
        }
    }
    true
}

/// Serves handshakes for data socket fd, each kept for up to 10 s between
/// its two RPCs. With --mtls the client must present a certificate.
pub fn handshakes(o: &Opts, fd: i32) {
    let auth = WebPkiClientVerifier::builder(ca());
    let auth = if o.mtls {
        auth.build()
    } else {
        auth.allow_unauthenticated().build()
    };
    let (certs, key) = certs("server");
    let cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(auth.unwrap_or_else(|e| die("ca.pem", e)))
        .with_single_cert(certs, key);
    let mut cfg = cfg.unwrap_or_else(|e| die("server.pem", e));
    cfg.send_tls13_tickets = 0;
    let cfg = Arc::new(cfg);
    let hs = HomaSock::open(HS_PORT);
    let mut pending: HashMap<(u32, u16), (ServerConnection, Instant)> = HashMap::new();
    loop {
        let mut src: libc::sockaddr_in = unsafe { zeroed() };
        let Ok((parts, id)) = hs.recv(&mut src) else {
            continue;
        };
        let msg = parts.concat();
        pending.retain(|_, (_, start)| start.elapsed() < Duration::from_secs(10));
        let peer = (src.sin_addr.s_addr, src.sin_port);
        let (conn, _) = pending
            .entry(peer)
            .or_insert_with(|| (ServerConnection::new(cfg.clone()).unwrap(), Instant::now()));
        let done = handshake_step(o, conn, &msg, fd, Ipv4Addr::from(peer.0.to_ne_bytes()));
        if let Err(e) = hs.send(&src, id, &[&drain(conn)]) {
            eprintln!("handshake sendmsg: {e}");
        }
        if done {
            pending.remove(&peer);
        }
    }
}

/// Gets the keys for the server's data port; with --mtls the client
/// presents client.pem.
pub fn client_handshake(o: &Opts, data: &HomaSock) {
    let cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(ca());
    let cfg = if o.mtls {
        let (certs, key) = certs("client");
        cfg.with_client_auth_cert(certs, key)
            .unwrap_or_else(|e| die("client.pem", e))
    } else {
        cfg.with_no_client_auth()
    };
    let mut conn = ClientConnection::new(Arc::new(cfg), "smt-server".try_into().unwrap()).unwrap();
    let hs = HomaSock::open(0);
    let mut srv = sockaddr(o.addr, HS_PORT);
    let mut me: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as u32;
    if unsafe { libc::getsockname(data.fd, &mut me as *mut _ as *mut libc::sockaddr, &mut len) }
        != 0
    {
        die("getsockname", std::io::Error::last_os_error());
    }
    // One handshake RPC: our records out, the server's back.
    let mut exchange = |conn: &mut ClientConnection| {
        let out = drain(conn);
        hs.send(&srv, 0, &[&out])
            .unwrap_or_else(|e| die("handshake", e));
        let msg = hs
            .recv(&mut srv)
            .unwrap_or_else(|e| die("handshake", e))
            .0
            .concat();
        feed(conn, &msg).unwrap_or_else(|e| die("TLS handshake", e));
    };
    exchange(&mut conn);
    if conn.is_handshaking() {
        die("TLS handshake", "more than one round");
    }
    conn.writer().write_all(&me.sin_port.to_ne_bytes()).unwrap();
    set_keys(false, data.fd, &conn, o.addr, o.port).unwrap_or_else(|e| die("keys", e));
    exchange(&mut conn);
    conn.reader()
        .read_exact(&mut [0u8])
        .unwrap_or_else(|e| die("no go-ahead from the server", e));
    unsafe { libc::close(hs.fd) };
}
