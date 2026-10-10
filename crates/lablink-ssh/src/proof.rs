//! The host-key possession proof ([`crate::Mode::KeyProof`]).
//!
//! `ssh-keyscan` shows public keys, which anyone can copy. The proof shows
//! that the host at an address holds the *private* key, and it never decides
//! that from text a server could influence. LabLink carries the connection
//! itself (`ProxyCommand=-`: ssh speaks the protocol over its stdin/stdout)
//! and watches only the bytes its own ssh client sends:
//!
//! - OpenSSH sends `SSH_MSG_NEWKEYS` only after the presented host key matched
//!   LabLink's known_hosts entry for the pin (`StrictHostKeyChecking=yes`)
//!   and the server's signature over the exchange hash, which covers ssh's
//!   fresh ephemeral key, verified with that key.
//! - A host that only replays a public key cannot produce that signature, so
//!   it cannot make ssh send `NEWKEYS`; the server's bytes are forwarded to
//!   ssh but never parsed.
//!
//! The connection is closed as soon as `NEWKEYS` is seen: no authentication
//! is attempted and no credential is ever offered. ssh's stderr is read only
//! to explain a proof that did not succeed.

use crate::command::{build_args, Mode, Target};
use crate::run::{classify_unproven, reader, KeyProof};
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// SSH_MSG_NEWKEYS (RFC 4253, section 7.3).
const MSG_NEWKEYS: u8 = 21;
/// Largest packet OpenSSH sends or accepts (`PACKET_MAX_SIZE`).
const MAX_PACKET: usize = 256 * 1024;
/// Longest identification line (RFC 4253, section 4.2).
const MAX_IDENT: usize = 255;

/// What the client side of the connection has shown so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seen {
    More,
    NewKeys,
    /// Not the start of an SSH-2 connection: never a proof.
    Malformed,
}

/// Follows the client's identification line and the unencrypted binary
/// packets of the first key exchange (`uint32 length`, `byte padding`,
/// payload, padding; no MAC before the first `NEWKEYS`).
#[derive(Debug, Default)]
pub(crate) struct ClientWatch {
    buf: Vec<u8>,
    ident_done: bool,
    done: Option<Seen>,
    /// Complete packets ssh has sent (KEXINIT, then its key-exchange init).
    pub(crate) packets: usize,
}

impl ClientWatch {
    pub(crate) fn feed(&mut self, data: &[u8]) -> Seen {
        if let Some(s) = self.done {
            return s;
        }
        self.buf.extend_from_slice(data);
        let s = self.scan();
        if s != Seen::More {
            self.done = Some(s);
            self.buf = Vec::new();
        }
        s
    }

    fn scan(&mut self) -> Seen {
        if !self.ident_done {
            let Some(end) = self.buf.iter().position(|&b| b == b'\n') else {
                return if self.buf.len() > MAX_IDENT {
                    Seen::Malformed
                } else {
                    Seen::More
                };
            };
            if end + 1 > MAX_IDENT || !self.buf.starts_with(b"SSH-2.0-") {
                return Seen::Malformed;
            }
            self.buf.drain(..=end);
            self.ident_done = true;
        }
        loop {
            if self.buf.len() < 6 {
                return Seen::More;
            }
            let len =
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            let pad = self.buf[4] as usize;
            // At least the padding-length byte, a message type and 4 bytes
            // of padding, a multiple of 8 with its length field.
            if !(6..=MAX_PACKET).contains(&len)
                || !(len + 4).is_multiple_of(8)
                || pad < 4
                || pad + 2 > len
            {
                return Seen::Malformed;
            }
            if self.buf[5] == MSG_NEWKEYS {
                return Seen::NewKeys;
            }
            if self.buf.len() < 4 + len {
                return Seen::More;
            }
            self.buf.drain(..4 + len);
            self.packets += 1;
        }
    }
}

/// The connection to the device that LabLink carries for ssh.
enum Transport {
    Tcp(TcpStream),
    /// The gateway hop (`ssh -W ip:port gateway`), run by LabLink instead of
    /// by ssh, on one end of a socket pair: shutting down LabLink's end ends
    /// both relay threads even if something the hop started keeps the other
    /// end open.
    Hop(Child, UnixStream),
}

impl Transport {
    fn open(t: &Target, deadline: Instant) -> Result<Self, String> {
        let left = deadline.saturating_duration_since(Instant::now());
        match &t.proxy_command {
            None => {
                let ip: IpAddr =
                    t.ip.parse()
                        .map_err(|_| format!("not an IP address: {}", t.ip))?;
                let wait = left
                    .min(Duration::from_secs(t.connect_timeout_s.max(1)))
                    .max(Duration::from_millis(1));
                TcpStream::connect_timeout(&SocketAddr::new(ip, t.port), wait)
                    .map(Transport::Tcp)
                    .map_err(|e| match e.kind() {
                        std::io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                            "connection timed out".to_string()
                        }
                        _ => e.to_string(),
                    })
            }
            Some(p) => {
                let ip: IpAddr =
                    t.ip.parse()
                        .map_err(|_| format!("not an IP address: {}", t.ip))?;
                let cmd = expand_proxy_tokens(p, &ip.to_string(), t.port)?;
                let fail = |e: std::io::Error| format!("cannot start the gateway hop: {e}");
                let (ours, theirs) = UnixStream::pair().map_err(fail)?;
                let theirs_in = OwnedFd::from(theirs.try_clone().map_err(fail)?);
                // The hop's `ssh` is looked up like LabLink's own.
                Command::new("/bin/sh")
                    .env("PATH", lablink_core::program::search_path())
                    .arg("-c")
                    .arg(format!("exec {cmd}"))
                    .stdin(Stdio::from(theirs_in))
                    .stdout(Stdio::from(OwnedFd::from(theirs)))
                    .stderr(Stdio::null())
                    .process_group(0)
                    .spawn()
                    .map(|c| Transport::Hop(c, ours))
                    .map_err(fail)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn split(&mut self) -> std::io::Result<(Box<dyn Write + Send>, Box<dyn Read + Send>)> {
        match self {
            Transport::Tcp(s) => Ok((Box::new(s.try_clone()?), Box::new(s.try_clone()?))),
            Transport::Hop(_, s) => Ok((Box::new(s.try_clone()?), Box::new(s.try_clone()?))),
        }
    }

    fn close(&mut self) {
        match self {
            Transport::Tcp(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Transport::Hop(c, s) => {
                let _ = s.shutdown(Shutdown::Both);
                kill_group(c.id());
                let _ = c.wait();
            }
        }
    }
}

/// Expand the `%h`, `%p` and `%%` tokens of a ProxyCommand built by
/// [`crate::proxy_command_through`] the way ssh would.
pub(crate) fn expand_proxy_tokens(cmd: &str, host: &str, port: u16) -> Result<String, String> {
    let mut out = String::with_capacity(cmd.len());
    let mut it = cmd.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(host),
            Some('p') => out.push_str(&port.to_string()),
            other => {
                return Err(format!(
                    "unsupported ProxyCommand token %{}",
                    other.unwrap_or(' ')
                ))
            }
        }
    }
    Ok(out)
}

fn kill_group(pid: u32) {
    // SAFETY: sending a signal has no memory-safety preconditions.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

/// Host-key signature algorithms for the key types pinned under `alias` in
/// LabLink's own known_hosts file, in file order; empty when it has none.
/// Passed first as `HostKeyAlgorithms`, so a list from a config file (which
/// stops OpenSSH preferring known key types) or a certificate algorithm can
/// never make the proof offer a type that is not pinned.
pub(crate) fn pinned_algorithms(known_hosts: &str, alias: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in known_hosts.lines() {
        let mut f = line.split_whitespace();
        let (Some(host), Some(kt), Some(_key)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if host.starts_with('#') || host.starts_with('@') || !host.eq_ignore_ascii_case(alias) {
            continue;
        }
        let algs: &[&str] = match kt {
            // SHA-1 signatures are off in current OpenSSH.
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256"],
            other => &[other][..],
        };
        for a in algs {
            if a.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-@.".contains(c))
                && !out.iter().any(|x| x == a)
            {
                out.push((*a).to_string());
            }
        }
    }
    out
}

/// Wait up to `limit` for a helper thread, never forever.
fn join_within<T>(h: std::thread::JoinHandle<T>, limit: Duration) -> Option<T> {
    let end = Instant::now() + limit;
    while !h.is_finished() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    if h.is_finished() {
        h.join().ok()
    } else {
        None
    }
}

/// Prove that the host at `t.ip` (directly, or through `t.proxy_command`)
/// holds one of the keys pinned for `t.host_key_alias`. Blocking; gives up
/// after `timeout`.
pub fn prove_host_key(t: &Target, timeout: Duration) -> KeyProof {
    let (Some(alias), Some(kh)) = (&t.host_key_alias, &t.known_hosts_file) else {
        return KeyProof::Inconclusive("no pinned host key".into());
    };
    let algorithms = std::fs::read_to_string(kh)
        .map(|s| pinned_algorithms(&s, alias))
        .unwrap_or_default();
    if algorithms.is_empty() {
        return KeyProof::Inconclusive(format!(
            "LabLink's known_hosts file has no key pinned for {alias}"
        ));
    }
    let deadline = Instant::now() + timeout;
    let mut transport = match Transport::open(t, deadline) {
        Ok(x) => x,
        Err(e) => return KeyProof::Inconclusive(e),
    };
    let (mut to_server, mut from_server) = match transport.split() {
        Ok(x) => x,
        Err(e) => {
            transport.close();
            return KeyProof::Inconclusive(e.to_string());
        }
    };
    let mut args = vec![
        "-o".to_string(),
        format!("HostKeyAlgorithms={}", algorithms.join(",")),
    ];
    args.extend(build_args(t, &Mode::KeyProof, &[]));
    let spawned = lablink_core::program::command(&t.binary).and_then(|mut c| {
        c.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
    });
    let mut ssh = match spawned {
        Ok(c) => c,
        Err(e) => {
            transport.close();
            return KeyProof::Inconclusive(format!("cannot run ssh: {e}"));
        }
    };
    let newkeys = Arc::new(AtomicBool::new(false));
    let malformed = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let up = {
        let mut client = ssh.stdout.take().expect("piped");
        let (newkeys, malformed, sent) = (newkeys.clone(), malformed.clone(), sent.clone());
        std::thread::spawn(move || {
            let mut watch = ClientWatch::default();
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = match client.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let seen = watch.feed(&buf[..n]);
                sent.store(watch.packets, Ordering::SeqCst);
                match seen {
                    Seen::NewKeys => return newkeys.store(true, Ordering::SeqCst),
                    Seen::Malformed => return malformed.store(true, Ordering::SeqCst),
                    Seen::More => {}
                }
                if to_server.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        })
    };
    let down = {
        let mut client = ssh.stdin.take().expect("piped");
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut from_server, &mut client);
        })
    };
    let err = reader(ssh.stderr.take());

    let mut timed_out = false;
    let mut reaped = false;
    while !newkeys.load(Ordering::SeqCst) && !malformed.load(Ordering::SeqCst) {
        if matches!(ssh.try_wait(), Ok(Some(_)) | Err(_)) {
            reaped = true;
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Never signal a process group whose leader was already reaped: its id
    // may belong to someone else by now.
    if !reaped {
        kill_group(ssh.id());
        let _ = ssh.wait();
    }
    transport.close();
    // ssh may have sent NEWKEYS just before it exited: let the watcher
    // finish reading what it wrote.
    let _ = join_within(up, Duration::from_secs(1));
    let _ = join_within(down, Duration::from_secs(1));
    let stderr = err
        .and_then(|h| join_within(h, Duration::from_secs(1)))
        .map(|(b, _)| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    if newkeys.load(Ordering::SeqCst) {
        return KeyProof::Proven;
    }
    if malformed.load(Ordering::SeqCst) {
        return KeyProof::Inconclusive("ssh did not start an SSH-2 key exchange".into());
    }
    match classify_unproven(&stderr, timed_out) {
        // A verdict about the key needs ssh to have sent its half of the
        // key exchange (KEXINIT, then its init) and judged the answer.
        KeyProof::Refused(_) if sent.load(Ordering::SeqCst) < 2 => {
            KeyProof::Inconclusive("the key exchange did not get as far as the host key".into())
        }
        p => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(msg: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![msg];
        payload.extend_from_slice(body);
        let mut pad = 8 - ((5 + payload.len()) % 8);
        if pad < 4 {
            pad += 8;
        }
        let mut p = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
        p.push(pad as u8);
        p.extend_from_slice(&payload);
        p.extend(std::iter::repeat_n(0u8, pad));
        p
    }

    fn client_stream(with_newkeys: bool) -> Vec<u8> {
        let mut s = b"SSH-2.0-OpenSSH_10.2\r\n".to_vec();
        // A KEXINIT and a KEX_ECDH_INIT whose bodies contain the byte 21
        // everywhere: only a packet's type byte counts.
        s.extend(packet(20, &[21u8; 300]));
        s.extend(packet(30, &[21u8; 1220]));
        if with_newkeys {
            s.extend(packet(MSG_NEWKEYS, &[]));
        }
        s
    }

    #[test]
    fn newkeys_found_only_as_a_packet_type_in_any_split() {
        let full = client_stream(true);
        for chunk in [1, 2, 3, 7, 64, 4096] {
            let mut w = ClientWatch::default();
            let mut seen = Seen::More;
            for c in full.chunks(chunk) {
                seen = w.feed(c);
                if seen != Seen::More {
                    break;
                }
            }
            assert_eq!(seen, Seen::NewKeys, "chunk {chunk}");
        }
        let mut w = ClientWatch::default();
        assert_eq!(w.feed(&client_stream(false)), Seen::More);
    }

    #[test]
    fn anything_but_an_ssh2_client_is_malformed() {
        for bad in [
            &b"SSH-1.5-old\r\n"[..],
            b"GET / HTTP/1.1\r\n",
            &[b'A'; 300][..],
        ] {
            assert_eq!(ClientWatch::default().feed(bad), Seen::Malformed);
        }
        let mut s = b"SSH-2.0-x\r\n".to_vec();
        s.extend_from_slice(&(10_000_000u32).to_be_bytes());
        s.extend_from_slice(&[4, 20]);
        assert_eq!(ClientWatch::default().feed(&s), Seen::Malformed);
        let mut s = b"SSH-2.0-x\r\n".to_vec();
        s.extend_from_slice(&12u32.to_be_bytes());
        s.extend_from_slice(&[11, MSG_NEWKEYS]); // padding longer than the packet
        assert_eq!(ClientWatch::default().feed(&s), Seen::Malformed);
        // Once decided, the answer never changes.
        let mut w = ClientWatch::default();
        assert_eq!(w.feed(b"x\n"), Seen::Malformed);
        assert_eq!(w.feed(&client_stream(true)), Seen::Malformed);
    }

    #[test]
    fn only_pinned_key_types_are_offered() {
        let kh = "# Managed by lablinkd\n\
                  lablink.s.dev ssh-ed25519 AAAA\n\
                  lablink.s.other ecdsa-sha2-nistp256 AAAA\n\
                  @revoked lablink.s.dev ssh-dss AAAA\n\
                  LABLINK.S.DEV ssh-rsa AAAA\n\
                  lablink.s.dev ssh-ed25519 BBBB\n\
                  lablink.s.dev bad,type AAAA\n";
        assert_eq!(
            pinned_algorithms(kh, "lablink.s.dev"),
            ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]
        );
        assert!(pinned_algorithms(kh, "lablink.s.none").is_empty());
        assert!(pinned_algorithms("", "lablink.s.dev").is_empty());
    }

    #[test]
    fn proxy_tokens_expand_like_ssh() {
        assert_eq!(
            expand_proxy_tokens(
                "ssh -o 'UserKnownHostsFile=/s/100%%/kh' -W %h:%p gw",
                "10.0.0.5",
                2222
            )
            .unwrap(),
            "ssh -o 'UserKnownHostsFile=/s/100%/kh' -W 10.0.0.5:2222 gw"
        );
        assert!(expand_proxy_tokens("nc %r", "h", 1).is_err());
        assert!(expand_proxy_tokens("nc %", "h", 1).is_err());
    }

    #[test]
    fn an_unpinned_target_is_never_proven() {
        let t = Target {
            binary: "ssh".into(),
            ip: "127.0.0.1".into(),
            port: 1,
            ssh_host: "x".into(),
            username: None,
            host_key_alias: None,
            known_hosts_file: None,
            connect_timeout_s: 1,
            options: Default::default(),
            proxy_command: None,
        };
        assert!(matches!(
            prove_host_key(&t, Duration::from_secs(1)),
            KeyProof::Inconclusive(_)
        ));
    }

    /// Exercise the complete subprocess/relay path, including its stderr
    /// classification. A host-key refusal before the client sent both KEX
    /// packets is not evidence that any host key was judged.
    #[test]
    fn stderr_verdict_requires_a_host_key_exchange_and_never_proves_possession() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        std::fs::write(&kh, "lablink.t.dev ssh-ed25519 AAAA\n").unwrap();
        for sent in 0..=2 {
            for stderr in ["incorrect signature", "Authenticated to 127.0.0.1"] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = std::io::copy(&mut stream, &mut std::io::sink());
                });
                let mut bytes = b"SSH-2.0-test\r\n".to_vec();
                for msg in [20, 30].into_iter().take(sent) {
                    bytes.extend(packet(msg, &[]));
                }
                let octal = bytes
                    .iter()
                    .map(|b| format!("\\{b:03o}"))
                    .collect::<String>();
                let binary = dir.path().join("fake-ssh");
                std::fs::write(
                    &binary,
                    format!("#!/bin/sh\nprintf '%b' '{octal}'\nprintf '%s\\n' '{stderr}' >&2\nexit 255\n"),
                ).unwrap();
                std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
                let t = Target {
                    binary: binary.display().to_string(),
                    ip: "127.0.0.1".into(),
                    port,
                    ssh_host: "dev".into(),
                    username: None,
                    host_key_alias: Some("lablink.t.dev".into()),
                    known_hosts_file: Some(kh.clone()),
                    connect_timeout_s: 1,
                    options: Default::default(),
                    proxy_command: None,
                };
                let proof = prove_host_key(&t, Duration::from_secs(5));
                server.join().unwrap();
                if stderr == "incorrect signature" && sent == 2 {
                    assert!(matches!(proof, KeyProof::Refused(_)), "{sent}: {proof:?}");
                } else {
                    assert!(
                        matches!(proof, KeyProof::Inconclusive(_)),
                        "{sent}, {stderr}: {proof:?}"
                    );
                }
            }
        }
    }
}
