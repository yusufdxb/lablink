//! Password-blind coordination between the GUI, its terminal helper and
//! system OpenSSH. Only typed progress enums cross the session boundary.
use lablink_core::client::Client;
use lablink_core::config::{valid_name, valid_ssh_identity_path, valid_username};
use lablink_core::model::{IdentityState, ResolveResult};
use lablink_core::protocol::{DeviceChanges, Request};
use lablink_ssh::{build_args, copy_id_args, Mode, Target};
use serde::{Deserialize, Serialize};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Always site-qualified; a bare name is never used here.
    pub device: String,
    pub username: String,
    pub fingerprints: Vec<String>,
    /// None means generating a fresh key, after explicit GUI consent.
    pub identity: Option<PathBuf>,
    pub generate_consent: bool,
}
impl Plan {
    pub fn validate(&self) -> Result<(), String> {
        let Some((site, name)) = self.device.split_once('/') else {
            return Err("Choose a device and its site first.".into());
        };
        if !valid_name(site) || !valid_name(name) || !valid_username(&self.username) {
            return Err("Check the SSH username and selected site.".into());
        }
        if self.fingerprints.is_empty()
            || self.fingerprints.len() > 16
            || self
                .fingerprints
                .iter()
                .any(|f| !lablink_core::config::valid_fingerprint(f))
        {
            return Err("Independently verify and confirm the SSH fingerprints first.".into());
        }
        if let Some(path) = &self.identity {
            validate_identity(path)?;
        } else if !self.generate_consent {
            return Err("Creating an SSH key needs your consent.".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Progress {
    Waiting,
    Configuring,
    Testing,
    Connected,
    Cancelled,
    AuthenticationFailed,
    TestFailed,
    IdentityFailed,
    KeyFailed,
    Unavailable,
}
impl Progress {
    pub fn finished(self) -> bool {
        !matches!(self, Self::Waiting | Self::Configuring | Self::Testing)
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::Waiting => "Opening the authentication terminal…",
            Self::Configuring => "Enter your SSH password or key passphrase in the terminal.",
            Self::Testing => "Testing a fresh connection using your SSH key…",
            Self::Connected => "Connected. Your SSH key works with the approved device identity.",
            Self::Cancelled => "Setup was cancelled or the terminal was closed. You can retry.",
            Self::AuthenticationFailed => "SSH could not install your key. Check the username and password, or ask the device administrator whether password login is allowed. Retry to continue.",
            Self::TestFailed => "The key was installed, but key login did not work. Check the terminal and the server's public-key login policy, then retry.",
            Self::IdentityFailed => "Security stop: the device identity or selected site changed. Verify the device independently before retrying. Existing pins were kept.",
            Self::KeyFailed => "The SSH key could not be used or created. Existing keys were kept. Choose a valid key and retry.",
            Self::Unavailable => "The device, daemon, or OpenSSH tools are unavailable. Check the connection and retry.",
        }
    }
}

/// A fresh mode-0700 directory, with no password field or arbitrary output.
/// Retained while the terminal runs, then removed with this owner.
pub struct Session {
    dir: tempfile::TempDir,
}
impl Session {
    pub fn new(plan: &Plan) -> Result<Self, String> {
        plan.validate()?;
        // A fixed absolute base avoids shell-sensitive TMPDIR names in
        // OpenSSH and the system ssh-copy-id script.
        let dir = tempfile::Builder::new()
            .prefix("lablink-onboard-")
            .tempdir_in("/tmp")
            .map_err(|_| "Cannot create a private onboarding session.".to_string())?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot protect the onboarding session.".to_string())?;
        private_write(
            &dir.path().join("request.json"),
            &serde_json::to_vec(plan).unwrap(),
        )
        .map_err(|_| "Cannot write the onboarding session.".to_string())?;
        write_progress(dir.path(), Progress::Waiting)
            .map_err(|_| "Cannot write progress.".to_string())?;
        Ok(Self { dir })
    }
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
    pub fn progress(&self) -> Option<Progress> {
        read_private(&self.path().join("progress.json"), 128)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }
    pub fn cancel(&self) {
        let _ = private_write(&self.path().join("cancel"), b"");
    }
}

fn private_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
fn read_private(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    // SAFETY: getuid has no preconditions.
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || m.len() > limit
    {
        return Err(std::io::Error::other("unsafe session file"));
    }
    let mut bytes = Vec::new();
    f.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("oversize session file"));
    }
    Ok(bytes)
}
fn write_progress(dir: &Path, progress: Progress) -> std::io::Result<()> {
    let mut f = tempfile::NamedTempFile::new_in(dir)?;
    f.write_all(&serde_json::to_vec(&progress)?)?;
    f.persist(dir.join("progress.json")).map_err(|e| e.error)?;
    Ok(())
}

pub fn validate_identity(path: &Path) -> Result<(), String> {
    if !path.to_str().is_some_and(valid_ssh_identity_path) {
        return Err(
            "SSH key paths must be absolute and contain only letters, digits, / . _ - .".into(),
        );
    }
    for (p, private) in [(path.to_path_buf(), true), (public_path(path), false)] {
        let m = std::fs::symlink_metadata(&p)
            .map_err(|_| "Choose an existing SSH key pair.".to_string())?;
        // SAFETY: getuid has no preconditions.
        if !m.is_file()
            || m.uid() != unsafe { libc::getuid() }
            || (private && m.mode() & 0o077 != 0)
            || m.mode() & 0o022 != 0
            || lablink_core::paths::writable_by_others(&p).is_some()
        {
            return Err("SSH keys must be owned by you; private keys need mode 0600 or 0400 and protected parent directories.".into());
        }
    }
    Ok(())
}
pub fn public_path(private: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", private.display()))
}
pub fn existing_identity() -> Option<PathBuf> {
    let dir = lablink_core::paths::home().join(".ssh");
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .into_iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file() && public_path(p).is_file())
}

/// Resolve immediately before use and freeze only the approved pins. A
/// subsequent daemon update cannot silently broaden this session's trust.
pub fn pinned_target(client: &Client, plan: &Plan, dir: &Path) -> Result<Target, String> {
    plan.validate()?;
    let r: ResolveResult = client
        .call_typed(&Request::Resolve {
            device: plan.device.clone(),
            batch: false,
        })
        .map_err(|e| e.to_string())?;
    if r.id != plan.device
        || r.site_away
        || r.username.as_deref() != Some(&plan.username)
        || r.identity == IdentityState::Mismatch
        || r.proxy_command.is_some()
    {
        return Err("Device identity, username or site changed.".into());
    }
    let mut t = Target::from_resolve(&r)?;
    let alias = t
        .host_key_alias
        .as_deref()
        .ok_or("No pinned host identity.")?;
    let path = t.known_hosts_file.as_ref().ok_or("No pinned host file.")?;
    if !valid_name(alias)
        || !path.to_str().is_some_and(valid_ssh_identity_path)
        || t.ip.parse::<std::net::IpAddr>().is_err()
        || !valid_name(&t.ssh_host)
    {
        return Err("Unsafe SSH target.".into());
    }
    let m = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if m.len() > 4 * 1024 * 1024 || lablink_core::paths::writable_by_others(path).is_some() {
        return Err("Unsafe host-key file.".into());
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines = text
        .lines()
        .filter(|l| l.split_whitespace().next() == Some(alias))
        .collect::<Vec<_>>()
        .join("\n");
    let keys = lablink_ssh::parse_known_hosts_lines(&lines);
    let mut actual = keys
        .iter()
        .map(|k| k.fingerprint.clone())
        .collect::<Vec<_>>();
    let mut approved = plan.fingerprints.clone();
    actual.sort();
    actual.dedup();
    approved.sort();
    approved.dedup();
    if actual != approved {
        return Err("Pinned keys differ from the independently approved fingerprints.".into());
    }
    let snapshot = dir.join("known_hosts");
    let entries = keys
        .into_iter()
        .map(|k| lablink_ssh::KnownHostsEntry {
            alias: alias.to_string(),
            key_type: k.key_type,
            public_key: k.public_key.unwrap(),
        })
        .collect::<Vec<_>>();
    lablink_ssh::write_known_hosts(&snapshot, &entries).map_err(|e| e.to_string())?;
    t.known_hosts_file = Some(snapshot);
    // GUI onboarding is a direct connection with explicit identity. User
    // config is excluded below; arbitrary configured options aren't needed.
    t.options.clear();
    Ok(t)
}

/// First command-line options win. Used for a fresh, public-key-only test
/// that allows OpenSSH to prompt for an encrypted private key's passphrase.
pub fn test_args(t: &Target, identity: &Path) -> Vec<String> {
    let mut args = vec!["-F".into(), "/dev/null".into()];
    for o in [
        "ControlPath=none",
        "ControlMaster=no",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "LogLevel=ERROR",
    ] {
        args.extend(["-o".into(), o.into()]);
    }
    args.extend(["-i".into(), identity.display().to_string()]);
    args.extend(build_args(
        t,
        &Mode::Exec {
            command: "true".into(),
            batch: false,
        },
        &[],
    ));
    args
}

/// Monitor process status only. No terminal stream is read or piped. All
/// three descriptors are inherited; OpenSSH owns password/passphrase input.
fn interactive(dir: &Path, mut cmd: Command) -> Result<bool, Progress> {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Never allow an askpass executable to substitute for the real terminal.
    cmd.env_remove("SSH_ASKPASS")
        .env("SSH_ASKPASS_REQUIRE", "never");
    let mut child = cmd.spawn().map_err(|_| Progress::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    loop {
        if dir.join("cancel").exists() || Instant::now() >= deadline {
            let _ = write_progress(dir, Progress::Cancelled);
            // The helper runs as the foreground job of its own terminal.
            // Terminate its entire group, including ssh-copy-id's ssh child.
            // SAFETY: queried process group belongs to this terminal, checked
            // by run_helper before any interactive child is started.
            unsafe {
                libc::kill(-libc::getpgrp(), libc::SIGTERM);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(Progress::Cancelled);
        }
        match child.try_wait() {
            Ok(Some(s)) => return Ok(s.success()),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Progress::Unavailable);
            }
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

pub fn run_helper(client: &Client, dir: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(dir).map_err(|_| "Missing onboarding session.")?;
    // SAFETY: getuid/getpgrp/tcgetpgrp have no unsafe pointer arguments.
    let own_terminal = unsafe {
        libc::getpgrp() == libc::tcgetpgrp(libc::STDIN_FILENO) && libc::getpgrp() == libc::getpid()
    };
    if !m.is_dir()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || !dir.to_str().is_some_and(valid_ssh_identity_path)
        || !std::io::stdin().is_terminal()
        || !own_terminal
    {
        return Err(
            "Onboarding needs a private session and its own real foreground terminal.".into(),
        );
    }
    // Prevent two terminal helpers installing keys for the same session.
    private_write(&dir.join("claimed"), b"").map_err(|_| "Session already used.")?;
    let result = (|| -> Result<(), Progress> {
        if dir.join("cancel").exists() {
            return Err(Progress::Cancelled);
        }
        let bytes = read_private(&dir.join("request.json"), 16 * 1024)
            .map_err(|_| Progress::IdentityFailed)?;
        let plan: Plan = serde_json::from_slice(&bytes).map_err(|_| Progress::IdentityFailed)?;
        plan.validate().map_err(|_| Progress::KeyFailed)?;
        // Resolve also ensures the daemon's pinned file has been flushed.
        let t = pinned_target(client, &plan, dir).map_err(|_| Progress::IdentityFailed)?;
        write_progress(dir, Progress::Configuring).map_err(|_| Progress::Unavailable)?;
        println!("LabLink SSH setup\nEnter passwords and private-key passphrases only at OpenSSH's terminal prompts.\nClose this terminal or cancel in LabLink to stop.\n");
        let identity = match plan.identity {
            Some(path) => path,
            None => {
                let base = lablink_core::paths::home().join(".ssh");
                if !base.exists() {
                    use std::os::unix::fs::DirBuilderExt;
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&base)
                        .map_err(|_| Progress::KeyFailed)?;
                }
                if !base.to_str().is_some_and(valid_ssh_identity_path)
                    || lablink_core::paths::writable_by_others(&base).is_some()
                {
                    return Err(Progress::KeyFailed);
                }
                let key_dir = tempfile::Builder::new()
                    .prefix("lablink-key-")
                    .tempdir_in(&base)
                    .map_err(|_| Progress::KeyFailed)?;
                std::fs::set_permissions(key_dir.path(), std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| Progress::KeyFailed)?;
                let path = key_dir.path().join("id_ed25519");
                let mut cmd = lablink_core::program::command("ssh-keygen")
                    .map_err(|_| Progress::Unavailable)?;
                cmd.args(["-t", "ed25519", "-f"])
                    .arg(&path)
                    .args(["-C", "LabLink"]);
                if !interactive(dir, cmd)? {
                    return Err(Progress::KeyFailed);
                }
                validate_identity(&path).map_err(|_| Progress::KeyFailed)?;
                // Keep the new key even if a later step fails; never remove
                // an existing credential or silently generate another key.
                let _ = key_dir.keep();
                let value = path.to_str().ok_or(Progress::KeyFailed)?.as_bytes();
                private_write(&dir.join("generated_identity"), value)
                    .map_err(|_| Progress::KeyFailed)?;
                path
            }
        };
        validate_identity(&identity).map_err(|_| Progress::KeyFailed)?;
        let mut args = vec!["-F".into(), "/dev/null".into()];
        args.extend(copy_id_args(&t, &public_path(&identity)).map_err(|_| Progress::KeyFailed)?);
        let mut cmd =
            lablink_core::program::command("ssh-copy-id").map_err(|_| Progress::Unavailable)?;
        // ssh-copy-id's own scratch directory must stay private and have a
        // safe path. TMPDIR alone does not control all versions of the script.
        let scratch_home = dir.join("home");
        std::fs::create_dir(&scratch_home).map_err(|_| Progress::Unavailable)?;
        std::fs::set_permissions(&scratch_home, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Progress::Unavailable)?;
        std::fs::create_dir(scratch_home.join(".ssh")).map_err(|_| Progress::Unavailable)?;
        cmd.args(args).env("HOME", &scratch_home).env("TMPDIR", dir);
        if !interactive(dir, cmd)? {
            return Err(Progress::AuthenticationFailed);
        }
        write_progress(dir, Progress::Testing).map_err(|_| Progress::Unavailable)?;
        let mut cmd =
            lablink_core::program::command(&t.binary).map_err(|_| Progress::Unavailable)?;
        cmd.args(test_args(&t, &identity));
        if !interactive(dir, cmd)? {
            return Err(Progress::TestFailed);
        }
        if dir.join("cancel").exists() {
            return Err(Progress::Cancelled);
        }
        // Persist the selected key only after a successful fresh test.
        client
            .call(&Request::Set {
                device: plan.device,
                changes: DeviceChanges {
                    identity_file: Some(identity.display().to_string()),
                    recheck: true,
                    ..Default::default()
                },
            })
            .map_err(|_| Progress::Unavailable)?;
        Ok(())
    })();
    let progress = result.err().unwrap_or(Progress::Connected);
    write_progress(dir, progress).map_err(|_| "Cannot report terminal result.")?;
    println!("\n{}", progress.message());
    if progress == Progress::Connected {
        Ok(())
    } else {
        Err(progress.message().into())
    }
}

pub fn generated_identity(dir: &Path) -> Option<PathBuf> {
    let bytes = read_private(&dir.join("generated_identity"), 4096).ok()?;
    let path = PathBuf::from(String::from_utf8(bytes).ok()?);
    validate_identity(&path).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            device: "home/device-a".into(),
            username: "tester".into(),
            fingerprints: vec!["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
            identity: None,
            generate_consent: true,
        }
    }
    #[test]
    fn consent_and_site_qualification_are_required() {
        let mut p = plan();
        assert!(p.validate().is_ok());
        p.generate_consent = false;
        assert!(p.validate().is_err());
        p.generate_consent = true;
        p.device = "device-a".into();
        assert!(p.validate().is_err());
        p.device = "other/device-a".into();
        assert!(p.validate().is_ok());
        p.fingerprints.clear();
        assert!(p.validate().is_err());
    }
    #[test]
    fn hostile_inputs_and_paths_fail_before_execution() {
        for input in [
            "-oProxyCommand=x",
            "x;touch /tmp/pwn",
            "$(id)",
            "a\nb",
            "a@b",
            "a/b",
            "",
            "a b",
            "`id`",
        ] {
            let mut p = plan();
            p.username = input.into();
            assert!(p.validate().is_err(), "{input}");
        }
        for path in [
            "key",
            "-i/key",
            "/tmp/a b",
            "/tmp/$(id)",
            "/tmp/`id`",
            "/tmp/a\nb",
            "/tmp/a%h",
            "/tmp/a'",
            "/tmp/a\"",
            "/tmp/~/key",
        ] {
            assert!(!valid_ssh_identity_path(path), "{path}");
        }
        assert!(valid_ssh_identity_path("/tmp/valid-key_1.pub"));
    }
    #[test]
    fn sessions_have_only_typed_status_and_private_files() {
        let s = Session::new(&plan()).unwrap();
        assert_eq!(s.progress(), Some(Progress::Waiting));
        assert_eq!(std::fs::metadata(s.path()).unwrap().mode() & 0o777, 0o700);
        for n in ["request.json", "progress.json"] {
            assert_eq!(
                std::fs::metadata(s.path().join(n)).unwrap().mode() & 0o777,
                0o600
            );
        }
        write_progress(s.path(), Progress::AuthenticationFailed).unwrap();
        assert_eq!(s.progress(), Some(Progress::AuthenticationFailed));
        assert!(!std::fs::read_to_string(s.path().join("request.json"))
            .unwrap()
            .contains("password"));
        s.cancel();
        assert!(s.path().join("cancel").exists());
        assert!(serde_json::from_str::<Progress>("\"password-sentinel\"").is_err());
        let mut value = serde_json::to_value(plan()).unwrap();
        value["password"] = "secret".into();
        assert!(serde_json::from_value::<Plan>(value).is_err());
    }
    #[test]
    fn existing_keys_require_a_protected_pair_and_are_never_modified() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("key");
        private_write(&p, b"private-test-sentinel").unwrap();
        assert!(validate_identity(&p).is_err());
        private_write(&public_path(&p), b"public-key").unwrap();
        assert!(validate_identity(&p).is_ok());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_identity(&p).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(validate_identity(&link).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"private-test-sentinel");
    }
    #[test]
    fn terminal_test_is_fresh_key_only_and_cannot_forward_agents() {
        let t = Target {
            binary: "ssh".into(),
            ip: "127.0.0.1".into(),
            port: 2222,
            ssh_host: "device".into(),
            username: Some("tester".into()),
            host_key_alias: Some("lablink.home.device".into()),
            known_hosts_file: Some("/tmp/known_hosts".into()),
            connect_timeout_s: 5,
            options: Default::default(),
            proxy_command: None,
        };
        let args = test_args(&t, Path::new("/tmp/key"));
        for flag in [
            "ControlPath=none",
            "ControlMaster=no",
            "PreferredAuthentications=publickey",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "IdentityAgent=none",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
            "GlobalKnownHostsFile=/dev/null",
        ] {
            assert!(args.iter().any(|a| a == flag), "{flag}");
        }
        assert!(
            !args.iter().any(|a| a == "BatchMode=yes"),
            "encrypted private keys may prompt"
        );
        assert_eq!(args.last().unwrap(), "true");
        let copy = copy_id_args(&t, Path::new("/tmp/key.pub")).unwrap();
        for flag in [
            "ControlPath=none",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
        ] {
            assert!(copy.iter().any(|a| a == flag));
        }
        assert!(copy_id_args(&t, Path::new("/tmp/$(id).pub")).is_err());
    }
    #[test]
    fn progress_only_succeeds_after_both_steps() {
        for p in [Progress::Waiting, Progress::Configuring, Progress::Testing] {
            assert!(!p.finished());
        }
        for p in [
            Progress::Connected,
            Progress::Cancelled,
            Progress::AuthenticationFailed,
            Progress::TestFailed,
            Progress::IdentityFailed,
            Progress::KeyFailed,
            Progress::Unavailable,
        ] {
            assert!(p.finished());
        }
    }
}
