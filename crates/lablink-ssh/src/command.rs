//! Argument construction for the OpenSSH client.

use lablink_core::model::{IdentityState, ResolveResult};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Everything needed to address one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub binary: String,
    pub ip: String,
    pub port: u16,
    /// Host argument given to ssh, so matching `Host` blocks in ~/.ssh/config apply.
    pub ssh_host: String,
    pub username: Option<String>,
    /// Present only for verified identities.
    pub host_key_alias: Option<String>,
    pub known_hosts_file: Option<PathBuf>,
    pub connect_timeout_s: u64,
    pub options: BTreeMap<String, String>,
    /// OpenSSH ProxyCommand for devices reached through a gateway.
    pub proxy_command: Option<String>,
}

impl Target {
    /// Build a target from the daemon's resolve result. Refuses mismatched identities.
    pub fn from_resolve(r: &ResolveResult) -> Result<Self, String> {
        if r.identity == IdentityState::Mismatch {
            return Err(format!(
                "refusing to connect to '{}': its SSH host key does not match the pinned identity",
                r.name
            ));
        }
        Ok(Self {
            binary: r.ssh_binary.clone(),
            ip: r.ip.clone(),
            port: r.port,
            ssh_host: r.ssh_host.clone(),
            username: r.username.clone(),
            host_key_alias: r.host_key_alias.clone(),
            known_hosts_file: r.known_hosts_file.as_ref().map(PathBuf::from),
            connect_timeout_s: r.connect_timeout_s,
            options: r.ssh_options.clone(),
            proxy_command: r.proxy_command.clone(),
        })
    }
}

/// How ssh is being used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Interactive login (`lablink ssh`). Prompts are allowed.
    Interactive,
    /// One remote command (`lablink exec`). `batch` forbids all prompts.
    Exec { command: String, batch: bool },
    /// Daemon login check: batch, never creates a ControlMaster, prints `hostname`.
    AuthProbe,
    /// Proof that the host holds the pinned host key, with no credentials:
    /// a fresh connection (never a ControlMaster, which would skip the key
    /// exchange) with every authentication method off, carried over ssh's
    /// stdin/stdout (`ProxyCommand=-`) by [`crate::prove_host_key`], which
    /// decides from the bytes ssh itself sends, never from printed text.
    KeyProof,
}

/// Options for ssh sessions LabLink starts on its own (login checks, service
/// checks, doctor, GUI actions): whatever the user's `~/.ssh/config` says,
/// such a session never forwards the agent, X11 or ports to the device and
/// never runs a `LocalCommand`. Command-line options beat the config file.
pub const AUTOMATED_SESSION_OPTIONS: [&str; 4] = [
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
];

/// [`AUTOMATED_SESSION_OPTIONS`] as `-o` arguments, for `extra`.
pub fn automated_session_args() -> Vec<String> {
    AUTOMATED_SESSION_OPTIONS
        .iter()
        .flat_map(|o| ["-o".to_string(), (*o).to_string()])
        .collect()
}

/// Does this ssh accept the option `setting` (for example
/// `KnownHostsCommand=none`, OpenSSH 8.5+, or `GSSAPIKeyExchange=no`, only
/// in distribution builds with the GSSAPI key-exchange patch)? Asked once
/// per binary and option with `ssh -G`, which parses options without
/// connecting. A client that rejects an option cannot read it from its
/// config files either.
fn supports_option(binary: &str, setting: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<(String, String), bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (binary.to_string(), setting.to_string());
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return *v;
    }
    // -F /dev/null: no config file is read, so a `Match` block that only
    // breaks this probe cannot make LabLink leave the option out.
    let args: Vec<String> = option_probe_args(setting).map(String::from).into();
    let out = crate::run::run_captured(
        binary,
        &args,
        std::time::Duration::from_secs(5),
        crate::run::OutputMode::Capture,
        true,
    );
    match out.ok().as_ref().and_then(probe_verdict) {
        Some(v) => {
            cache.lock().unwrap().insert(key, v);
            v
        }
        // Any other failure (timeout, no fork): pass the option and ask
        // again next time. An ssh that really lacks it then fails closed.
        None => true,
    }
}

/// What an option probe proved: supported (exit 0), unsupported (OpenSSH's
/// own "Bad configuration option"), or nothing.
fn probe_verdict(o: &crate::run::ExecOutput) -> Option<bool> {
    if o.exit_code == Some(0) && !o.timed_out {
        return Some(true);
    }
    String::from_utf8_lossy(&o.stderr)
        .contains("Bad configuration option")
        .then_some(false)
}

fn option_probe_args(setting: &str) -> [&str; 6] {
    [
        "-F",
        "/dev/null",
        "-G",
        "-o",
        setting,
        "lablink-option-check",
    ]
}

fn supports_known_hosts_command(binary: &str) -> bool {
    supports_option(binary, "KnownHostsCommand=none")
}

fn opt(args: &mut Vec<String>, k: &str, v: impl AsRef<str>) {
    args.push("-o".into());
    args.push(format!("{k}={}", v.as_ref()));
}

/// Build the argument vector (excluding the binary). `extra` are additional
/// user-supplied ssh options; they come after LabLink's options and therefore
/// cannot override them.
pub fn build_args(t: &Target, mode: &Mode, extra: &[String]) -> Vec<String> {
    let mut a = Vec::new();
    if *mode == Mode::KeyProof {
        // No config file: the proof needs nothing from one (everything is on
        // this command line), and a config could otherwise vouch for a key
        // or print text into stderr (`Match exec`).
        a.push("-F".into());
        a.push("/dev/null".into());
        // The caller carries the connection (direct or through the gateway).
        opt(&mut a, "ProxyCommand", "-");
    } else if let Some(p) = &t.proxy_command {
        opt(&mut a, "ProxyCommand", p);
    }
    // Addressing: always the daemon-resolved address, never DNS at connect time.
    opt(&mut a, "HostName", &t.ip);
    opt(&mut a, "Port", t.port.to_string());
    // Host-key policy for verified devices.
    if let (Some(alias), Some(kh)) = (&t.host_key_alias, &t.known_hosts_file) {
        opt(&mut a, "HostKeyAlias", alias);
        opt(&mut a, "UserKnownHostsFile", kh.display().to_string());
        opt(&mut a, "GlobalKnownHostsFile", "/dev/null");
        opt(&mut a, "StrictHostKeyChecking", "yes");
        opt(&mut a, "UpdateHostKeys", "no");
        opt(&mut a, "CheckHostIP", "no");
        // A KnownHostsCommand in ~/.ssh/config or /etc/ssh/ssh_config would
        // add accepted keys next to the pinned file.
        if supports_known_hosts_command(&t.binary) {
            opt(&mut a, "KnownHostsCommand", "none");
        }
        // With VerifyHostKeyDNS=yes in a config file, a DNS answer
        // marked secure would be accepted in place of the pin.
        opt(&mut a, "VerifyHostKeyDNS", "no");
        // Distribution builds can trust a Kerberos exchange instead of the
        // host key (the proof sets this below, with its other options).
        if *mode != Mode::KeyProof && supports_option(&t.binary, "GSSAPIKeyExchange=no") {
            opt(&mut a, "GSSAPIKeyExchange", "no");
        }
    }
    // A master connection is reused by user, address and port alone: one
    // the user's config opened to another machine at this address would
    // carry the session past the pin. The daemon names a master path of
    // LabLink's own (see [`control_path`]) or `none`; a resolve result
    // without one (an older daemon) gets `none`.
    if *mode != Mode::KeyProof && !t.options.contains_key("ControlPath") {
        opt(&mut a, "ControlPath", "none");
    }
    match mode {
        Mode::Interactive => {}
        Mode::Exec { batch, .. } => {
            if *batch {
                opt(&mut a, "BatchMode", "yes");
            }
            opt(&mut a, "ConnectTimeout", t.connect_timeout_s.to_string());
            a.push("-T".into());
            a.push("-n".into());
        }
        Mode::KeyProof => {
            opt(&mut a, "BatchMode", "yes");
            opt(&mut a, "ConnectTimeout", t.connect_timeout_s.to_string());
            opt(&mut a, "ControlMaster", "no");
            opt(&mut a, "ControlPath", "none");
            for k in [
                "PubkeyAuthentication",
                "PasswordAuthentication",
                "KbdInteractiveAuthentication",
                "GSSAPIAuthentication",
                "HostbasedAuthentication",
            ] {
                opt(&mut a, k, "no");
            }
            opt(&mut a, "IdentityAgent", "none");
            // A config's ProxyUseFdpass would make ssh refuse ProxyCommand=-.
            opt(&mut a, "ProxyUseFdpass", "no");
            // Distribution builds can trust a Kerberos exchange instead of
            // the host key; the proof must only ever rest on the pin.
            if supports_option(&t.binary, "GSSAPIKeyExchange=no") {
                opt(&mut a, "GSSAPIKeyExchange", "no");
            }
            // stderr only explains a proof that failed (it never proves
            // anything). OpenSSH reports a bad host signature at INFO.
            opt(&mut a, "LogLevel", "INFO");
            for o in AUTOMATED_SESSION_OPTIONS {
                a.push("-o".into());
                a.push(o.into());
            }
            // No -n: stdin carries the connection.
            a.push("-T".into());
        }
        Mode::AuthProbe => {
            opt(&mut a, "BatchMode", "yes");
            opt(&mut a, "ConnectTimeout", t.connect_timeout_s.to_string());
            // Reuse an existing master if the user has one, never start one.
            opt(&mut a, "ControlMaster", "no");
            opt(&mut a, "LogLevel", "ERROR");
            for o in AUTOMATED_SESSION_OPTIONS {
                a.push("-o".into());
                a.push(o.into());
            }
            a.push("-T".into());
            a.push("-n".into());
        }
    }
    if let Some(u) = &t.username {
        a.push("-l".into());
        a.push(u.clone());
    }
    for (k, v) in &t.options {
        opt(&mut a, k, v);
    }
    a.extend(extra.iter().cloned());
    a.push("--".into());
    a.push(t.ssh_host.clone());
    match mode {
        Mode::Interactive => {}
        Mode::Exec { command, .. } => a.push(command.clone()),
        Mode::AuthProbe => a.push("hostname".into()),
        Mode::KeyProof => a.push("true".into()),
    }
    a
}

/// The master connection path for a pinned device: a socket in `dir` (a
/// private directory of LabLink's) named after the device's alias and pins,
/// then ssh's `%C` (local host, address, port, user). Only ssh started by
/// LabLink with this device's pinned options can open a master there, so a
/// reused master was itself checked against the same pins. `None` (use
/// `ControlPath=none`) when the path would be too long for a socket or
/// cannot be written as one ssh option word.
pub fn control_path(dir: &std::path::Path, alias: &str, pins: &[&str]) -> Option<String> {
    use sha2::{Digest, Sha256};
    let dir = dir.to_str()?;
    if !dir.starts_with('/')
        || !dir
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@%".contains(c))
    {
        return None;
    }
    let mut h = Sha256::new();
    h.update(alias.as_bytes());
    let mut pins = pins.to_vec();
    pins.sort_unstable();
    for p in pins {
        h.update([0]);
        h.update(p.as_bytes());
    }
    let name: String = h.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // sun_path is 108 bytes with the NUL; %C expands to 40 characters and
    // a starting master appends a 17-character temporary suffix.
    let expanded = dir.len() + 1 + name.len() + 1 + 40;
    if expanded + 17 >= 108 {
        return None;
    }
    Some(format!("{}/{name}-%C", dir.replace('%', "%%")))
}

/// Arguments for `ssh-copy-id` that install `pubkey` on the device through
/// exactly the same addressing and pinned host-key options as `lablink ssh`.
/// Refuses unverified targets: the password typed for ssh-copy-id must only
/// ever reach the machine whose identity was pinned.
pub fn copy_id_args(t: &Target, pubkey: &std::path::Path) -> Result<Vec<String>, String> {
    if t.host_key_alias.is_none() || t.known_hosts_file.is_none() {
        return Err("the device's host key is not pinned yet".into());
    }
    let ssh = build_args(t, &Mode::Interactive, &[]);
    let mut a = vec!["-i".to_string(), pubkey.display().to_string()];
    let mut i = 0;
    while i < ssh.len() {
        match ssh[i].as_str() {
            "-o" if i + 1 < ssh.len() => {
                a.push("-o".into());
                a.push(ssh[i + 1].clone());
                i += 2;
            }
            "--" => break,
            _ => i += 1,
        }
    }
    let host = match &t.username {
        Some(u) => format!("{u}@{}", t.ssh_host),
        None => t.ssh_host.clone(),
    };
    a.push(host);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_id_uses_the_pinned_options_and_refuses_unpinned() {
        let t = target(true);
        let a = copy_id_args(&t, std::path::Path::new("/h/.ssh/id_ed25519.pub")).unwrap();
        assert_eq!(&a[..2], ["-i", "/h/.ssh/id_ed25519.pub"]);
        for o in [
            "HostName=192.168.10.71",
            "HostKeyAlias=lablink.jetson-a",
            "UserKnownHostsFile=/s/known_hosts",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
        ] {
            let i = a
                .iter()
                .position(|x| x == o)
                .unwrap_or_else(|| panic!("{o}: {a:?}"));
            assert_eq!(a[i - 1], "-o");
        }
        assert_eq!(a.last().unwrap(), "ops@jetson-a");
        assert!(!a.iter().any(|x| x == "--" || x == "-l"));
        assert!(copy_id_args(&target(false), std::path::Path::new("/k.pub")).is_err());
    }

    fn target(verified: bool) -> Target {
        Target {
            binary: "ssh".into(),
            ip: "192.168.10.71".into(),
            port: 22,
            ssh_host: "jetson-a".into(),
            username: Some("ops".into()),
            host_key_alias: verified.then(|| "lablink.jetson-a".to_string()),
            known_hosts_file: verified.then(|| PathBuf::from("/s/known_hosts")),
            connect_timeout_s: 5,
            options: [("ServerAliveInterval".to_string(), "10".to_string())].into(),
            proxy_command: None,
        }
    }

    fn values<'a>(a: &'a [String], key: &str) -> Vec<&'a str> {
        a.iter()
            .filter_map(|x| x.strip_prefix(key)?.strip_prefix('='))
            .collect()
    }

    #[test]
    fn no_session_rides_a_master_the_daemon_did_not_name() {
        // No ControlPath from the daemon (an older one): never reuse.
        for verified in [true, false] {
            for mode in [
                Mode::Interactive,
                Mode::Exec {
                    command: "id".into(),
                    batch: true,
                },
                Mode::AuthProbe,
                Mode::KeyProof,
            ] {
                let a = build_args(&target(verified), &mode, &[]);
                assert_eq!(values(&a, "ControlPath"), ["none"], "{mode:?}: {a:?}");
            }
        }
        // The daemon's private path is the only one on the command line.
        let mut t = target(true);
        t.options
            .insert("ControlPath".into(), "/run/user/7/lablink/ab-%C".into());
        for mode in [
            Mode::Interactive,
            Mode::Exec {
                command: "id".into(),
                batch: true,
            },
            Mode::AuthProbe,
        ] {
            let a = build_args(&t, &mode, &[]);
            assert_eq!(
                values(&a, "ControlPath"),
                ["/run/user/7/lablink/ab-%C"],
                "{a:?}"
            );
        }
        assert_eq!(
            values(
                &copy_id_args(&t, std::path::Path::new("/k.pub")).unwrap(),
                "ControlPath"
            ),
            ["/run/user/7/lablink/ab-%C"]
        );
        // The proof is always a fresh connection, first value wins.
        let a = build_args(&t, &Mode::KeyProof, &[]);
        assert_eq!(values(&a, "ControlPath")[0], "none", "{a:?}");
    }

    #[test]
    fn master_path_is_per_device_and_pins_and_fits_a_socket() {
        let dir = std::path::Path::new("/run/user/1000/lablink");
        let p = control_path(dir, "lablink.home.dev1", &["SHA256:a", "SHA256:b"]).unwrap();
        assert!(
            p.starts_with("/run/user/1000/lablink/") && p.ends_with("-%C"),
            "{p}"
        );
        // Pin order does not matter; alias and pins do.
        assert_eq!(
            Some(&p),
            control_path(dir, "lablink.home.dev1", &["SHA256:b", "SHA256:a"]).as_ref()
        );
        assert_ne!(
            Some(&p),
            control_path(dir, "lablink.cares.dev1", &["SHA256:a", "SHA256:b"]).as_ref()
        );
        assert_ne!(
            Some(&p),
            control_path(dir, "lablink.home.dev1", &["SHA256:a"]).as_ref()
        );
        // %C is 40 characters; a starting master appends 17 more.
        let long = std::path::PathBuf::from(format!("/{}", "d".repeat(35)));
        assert!(control_path(&long, "a", &[]).is_some());
        let too_long = std::path::PathBuf::from(format!("/{}", "d".repeat(36)));
        assert_eq!(control_path(&too_long, "a", &[]), None);
        // One ssh option word, absolute, '%' literal.
        assert_eq!(control_path(std::path::Path::new("/a b"), "a", &[]), None);
        assert_eq!(control_path(std::path::Path::new("rel"), "a", &[]), None);
        assert!(control_path(std::path::Path::new("/a%b"), "a", &[])
            .unwrap()
            .starts_with("/a%%b/"));
    }

    #[test]
    fn pinned_sessions_refuse_a_kerberos_key_exchange() {
        // Only meaningful where this ssh has the option (Debian/Ubuntu).
        if !supports_option("ssh", "GSSAPIKeyExchange=no") {
            return;
        }
        for mode in [
            Mode::Interactive,
            Mode::Exec {
                command: "id".into(),
                batch: true,
            },
            Mode::AuthProbe,
        ] {
            let a = build_args(&target(true), &mode, &[]);
            assert_eq!(values(&a, "GSSAPIKeyExchange"), ["no"], "{mode:?}");
        }
    }

    fn pos(a: &[String], s: &str) -> usize {
        a.iter()
            .position(|x| x == s)
            .unwrap_or_else(|| panic!("{s} missing from {a:?}"))
    }

    #[test]
    fn verified_device_pins_host_key_first() {
        let a = build_args(
            &target(true),
            &Mode::Interactive,
            &["-o".into(), "StrictHostKeyChecking=no".into()],
        );
        let strict = pos(&a, "StrictHostKeyChecking=yes");
        let weak = pos(&a, "StrictHostKeyChecking=no");
        assert!(
            strict < weak,
            "LabLink's option must precede user extras: {a:?}"
        );
        assert!(a.contains(&"HostKeyAlias=lablink.jetson-a".to_string()));
        assert!(a.contains(&"HostName=192.168.10.71".to_string()));
        if supports_known_hosts_command("ssh") {
            assert!(a.contains(&"KnownHostsCommand=none".to_string()), "{a:?}");
        }
        assert_eq!(
            &a[a.len() - 2..],
            &["--".to_string(), "jetson-a".to_string()]
        );
    }

    #[test]
    fn unverified_device_leaves_openssh_policy_alone() {
        let a = build_args(&target(false), &Mode::Interactive, &[]);
        assert!(!a.iter().any(|x| x.starts_with("StrictHostKeyChecking")));
        assert!(!a.iter().any(|x| x.starts_with("HostKeyAlias")));
        assert!(!a.iter().any(|x| x.starts_with("UserKnownHostsFile")));
    }

    #[test]
    fn exec_is_batch_and_command_is_single_argument() {
        let a = build_args(
            &target(true),
            &Mode::Exec {
                command: "uname -a; echo 'x y'".into(),
                batch: true,
            },
            &[],
        );
        assert!(a.contains(&"BatchMode=yes".to_string()));
        assert!(a.contains(&"-T".to_string()) && a.contains(&"-n".to_string()));
        assert_eq!(a.last().unwrap(), "uname -a; echo 'x y'");
        assert_eq!(a[a.len() - 2], "jetson-a");
        assert_eq!(a[a.len() - 3], "--");
    }

    #[test]
    fn key_proof_sends_no_credentials_and_never_multiplexes() {
        let a = build_args(&target(true), &Mode::KeyProof, &[]);
        for o in [
            "StrictHostKeyChecking=yes",
            "HostKeyAlias=lablink.jetson-a",
            "BatchMode=yes",
            "ControlPath=none",
            "PubkeyAuthentication=no",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "GSSAPIAuthentication=no",
            "HostbasedAuthentication=no",
            "IdentityAgent=none",
            "ForwardAgent=no",
            "VerifyHostKeyDNS=no",
        ] {
            assert_eq!(a[pos(&a, o) - 1], "-o", "{o}");
        }
        assert_eq!(a.last().unwrap(), "true");
        // The connection is LabLink's, whatever the target's route.
        let mut via = target(true);
        via.proxy_command = Some("ssh -W %h:%p gw".into());
        let a = build_args(&via, &Mode::KeyProof, &[]);
        assert_eq!(&a[..4], ["-F", "/dev/null", "-o", "ProxyCommand=-"]);
        assert_eq!(
            a.iter().filter(|x| x.starts_with("ProxyCommand=")).count(),
            1
        );
        assert!(
            !a.contains(&"-n".to_string()),
            "stdin is the transport: {a:?}"
        );
        assert!(a.contains(&"ProxyUseFdpass=no".to_string()));
    }

    #[test]
    fn option_probes_ignore_every_config_file() {
        assert_eq!(&option_probe_args("X=y")[..2], ["-F", "/dev/null"]);
    }

    #[test]
    fn only_openssh_s_own_answer_leaves_an_option_out() {
        let o = |code: Option<i32>, err: &str, timed_out: bool| crate::run::ExecOutput {
            exit_code: code,
            signal: None,
            stdout: Vec::new(),
            stderr: err.as_bytes().to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out,
            duration: std::time::Duration::ZERO,
        };
        assert_eq!(probe_verdict(&o(Some(0), "", false)), Some(true));
        assert_eq!(
            probe_verdict(&o(
                Some(255),
                "command-line: line 0: Bad configuration option: knownhostscommand\n",
                false
            )),
            Some(false)
        );
        for (code, err, t) in [
            (Some(255), "ssh: Could not resolve hostname x\n", false),
            (None, "", true),
            (Some(1), "", false),
        ] {
            assert_eq!(probe_verdict(&o(code, err, t)), None, "{err:?}");
        }
        // A probe that fails for any other reason still passes the option.
        let dir = std::env::temp_dir().join(format!("lablink-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("ssh");
        std::fs::write(
            &fake,
            "#!/bin/sh\necho 'ssh: connect: Resource temporarily unavailable' >&2\nexit 255\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mut t = target(true);
        t.binary = fake.display().to_string();
        let a = build_args(&t, &Mode::Interactive, &[]);
        assert!(a.contains(&"KnownHostsCommand=none".to_string()), "{a:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auth_probe_never_creates_master() {
        let a = build_args(&target(true), &Mode::AuthProbe, &[]);
        assert!(a.contains(&"ControlMaster=no".to_string()));
        for o in AUTOMATED_SESSION_OPTIONS {
            let i = pos(&a, o);
            assert_eq!(a[i - 1], "-o");
            assert!(i < pos(&a, "--"), "{a:?}");
        }
        assert!(a.contains(&"BatchMode=yes".to_string()));
        assert_eq!(a.last().unwrap(), "hostname");
    }

    #[test]
    fn mismatch_refused() {
        let r = ResolveResult {
            schema_version: 1,
            name: "jetson-a".into(),
            id: "site-alpha/jetson-a".into(),
            site_name: "Site Alpha".into(),
            shared_name: false,
            site_away: false,
            ip: "192.0.2.4".into(),
            port: 22,
            ssh_host: "jetson-a".into(),
            username: None,
            identity: IdentityState::Mismatch,
            color: lablink_core::model::Color::Red,
            network: lablink_core::model::NetworkState::Online,
            host_key_alias: None,
            known_hosts_file: None,
            ssh_binary: "ssh".into(),
            connect_timeout_s: 5,
            ssh_options: Default::default(),
            proxy_command: None,
        };
        assert!(Target::from_resolve(&r).is_err());
    }
}

/// Quote one argument for a POSIX shell (OpenSSH runs ProxyCommand via `sh -c`).
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// A ProxyCommand that tunnels through `gateway` (`ssh <gateway args> -W %h:%p`),
/// with the gateway's own pinned host-key options. `batch` forbids prompts.
pub fn proxy_command_through(gateway: &Target, batch: bool) -> String {
    // The hop is a session LabLink starts on its own, whether or not the
    // user's terminal waits on it.
    let mut extra = automated_session_args();
    extra.extend(["-W".to_string(), "%h:%p".to_string()]);
    if batch {
        extra.splice(
            0..0,
            [
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                "-o".to_string(),
                "ControlMaster=no".to_string(),
                // The hop's stderr is merged into the background check's:
                // keep text the gateway side could send out of it.
                "-o".to_string(),
                "LogLevel=FATAL".to_string(),
            ],
        );
    }
    let args = build_args(gateway, &Mode::Interactive, &extra);
    // ssh %-expands ProxyCommand before the shell runs it: a literal '%'
    // (e.g. in the known_hosts path) must be doubled, except in %h:%p.
    std::iter::once(gateway.binary.as_str())
        .chain(args.iter().map(String::as_str))
        .map(|a| {
            if a == "%h:%p" {
                a.to_string()
            } else {
                shell_quote(&a.replace('%', "%%"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("HostName=10.0.0.1"), "HostName=10.0.0.1");
        assert_eq!(shell_quote("%h:%p"), "%h:%p");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn proxy_command_escapes_percent_outside_the_tokens() {
        let gw = Target {
            binary: "ssh".into(),
            ip: "10.0.0.1".into(),
            port: 22,
            ssh_host: "gw".into(),
            username: None,
            host_key_alias: Some("lablink.s.gw".into()),
            known_hosts_file: Some(PathBuf::from("/s/100%/known_hosts")),
            connect_timeout_s: 5,
            options: Default::default(),
            proxy_command: None,
        };
        let p = proxy_command_through(&gw, true);
        assert!(p.contains("UserKnownHostsFile=/s/100%%/known_hosts"), "{p}");
        assert!(p.contains(" -W %h:%p "), "{p}");
    }

    #[test]
    fn proxy_command_keeps_gateway_pin_and_goes_first() {
        let gw = Target {
            binary: "ssh".into(),
            ip: "192.168.10.70".into(),
            port: 22,
            ssh_host: "jetson-a".into(),
            username: Some("ops".into()),
            host_key_alias: Some("lablink.jetson-a".into()),
            known_hosts_file: Some(PathBuf::from("/s/known hosts")),
            connect_timeout_s: 5,
            options: Default::default(),
            proxy_command: None,
        };
        let p = proxy_command_through(&gw, true);
        assert!(p.starts_with("ssh -o HostName=192.168.10.70"), "{p}");
        assert!(p.contains("HostKeyAlias=lablink.jetson-a"));
        assert!(p.contains("StrictHostKeyChecking=yes"));
        assert!(p.contains("'UserKnownHostsFile=/s/known hosts'"));
        assert!(p.contains("BatchMode=yes"));
        assert!(p.ends_with("-W %h:%p -- jetson-a"), "{p}");
        // The hop never forwards, listens or runs a LocalCommand, prompted or not.
        for batch in [true, false] {
            let h = proxy_command_through(&gw, batch);
            for o in AUTOMATED_SESSION_OPTIONS {
                assert!(h.contains(&format!(" -o {o} ")), "{o}: {h}");
            }
            assert!(h.contains(" -o ControlPath=none "), "{h}");
        }
        let dev = Target {
            ip: "192.168.50.161".into(),
            ssh_host: "robot-a".into(),
            host_key_alias: None,
            known_hosts_file: None,
            username: None,
            proxy_command: Some(p.clone()),
            ..gw
        };
        let a = build_args(
            &dev,
            &Mode::Exec {
                command: "true".into(),
                batch: true,
            },
            &[],
        );
        assert_eq!(a[0], "-o");
        assert_eq!(a[1], format!("ProxyCommand={p}"));
        assert!(a.contains(&"HostName=192.168.50.161".to_string()));
    }
}

#[cfg(test)]
mod probe_parity_tests {
    use super::*;

    /// The daemon's login check and `lablink exec` must authenticate the same
    /// way: identical address, user, identity-related config and pinned
    /// host-key options. Only the probe-specific flags may differ.
    #[test]
    fn auth_probe_and_exec_share_identity_and_host_key_options() {
        let t = Target {
            binary: "ssh".into(),
            ip: "192.168.10.70".into(),
            port: 22,
            ssh_host: "jetson-a".into(),
            username: Some("ops".into()),
            host_key_alias: Some("lablink.jetson-a".into()),
            known_hosts_file: Some(PathBuf::from("/s/known_hosts")),
            connect_timeout_s: 5,
            options: [("ServerAliveInterval".to_string(), "10".to_string())].into(),
            proxy_command: None,
        };
        let exec = build_args(
            &t,
            &Mode::Exec {
                command: "hostname".into(),
                batch: true,
            },
            &[],
        );
        let probe = build_args(&t, &Mode::AuthProbe, &[]);
        // Probe-only flags; the forwarding switches do not affect
        // authentication.
        let probe_only: Vec<&str> = ["ControlMaster=no", "LogLevel=ERROR"]
            .into_iter()
            .chain(AUTOMATED_SESSION_OPTIONS)
            .collect();
        let strip = |a: &[String]| -> Vec<String> {
            let mut out = Vec::new();
            let mut i = 0;
            while i < a.len() {
                if a[i] == "-o" && probe_only.contains(&a[i + 1].as_str()) {
                    i += 2;
                    continue;
                }
                out.push(a[i].clone());
                i += 1;
            }
            out
        };
        let (e, p) = (strip(&exec), strip(&probe));
        // Same everything up to the remote command, which is the probe's `hostname`.
        assert_eq!(e, p, "exec: {exec:?}\nprobe: {probe:?}");
        for must in [
            "HostKeyAlias=lablink.jetson-a",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=/s/known_hosts",
            "BatchMode=yes",
        ] {
            assert!(
                probe.contains(&must.to_string()),
                "{must} missing from probe"
            );
        }
        // Neither path disables public-key auth or adds password handling.
        for a in [&exec, &probe] {
            assert!(!a.iter().any(|x| x.starts_with("PubkeyAuthentication")
                || x.starts_with("PasswordAuthentication")));
        }
    }
}
