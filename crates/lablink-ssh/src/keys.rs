//! Parsing `ssh-keyscan` / `ssh-keygen -F` output and writing LabLink's own
//! known_hosts file.

use crate::fingerprint::fingerprint_of_blob;
use lablink_core::identity::HostKey;
use std::io::Write;
use std::path::Path;

/// Key types LabLink accepts from scans (others are ignored).
const ACCEPTED_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn parse_key_fields(key_type: &str, blob: &str) -> Option<HostKey> {
    if !ACCEPTED_TYPES.contains(&key_type) {
        return None;
    }
    let fingerprint = fingerprint_of_blob(key_type, blob).ok()?;
    Some(HostKey {
        key_type: key_type.to_string(),
        fingerprint,
        public_key: Some(blob.to_string()),
    })
}

/// Parse `ssh-keyscan` stdout: `host keytype base64 [comment]` per line.
/// Comment lines and malformed lines are skipped. Output is sorted and deduplicated.
pub fn parse_keyscan_output(out: &str) -> Vec<HostKey> {
    let mut keys: Vec<HostKey> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3)
                .then(|| parse_key_fields(f[1], f[2]))
                .flatten()
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Parse known_hosts lines as printed by `ssh-keygen -F`. Lines carrying
/// `@revoked` or `@cert-authority` markers are never treated as host keys,
/// and a key the user marked `@revoked` is dropped even where another line
/// lists it: LabLink's own known_hosts would not carry the marker, so OpenSSH
/// would otherwise accept a key the user revoked.
pub fn parse_known_hosts_lines(out: &str) -> Vec<HostKey> {
    let lines: Vec<Vec<&str>> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
        .collect();
    let revoked: Vec<&str> = lines
        .iter()
        .filter(|f| f.len() >= 4 && f[0] == "@revoked")
        .map(|f| f[3])
        .collect();
    let mut keys: Vec<HostKey> = lines
        .iter()
        .filter(|f| f.len() >= 3 && !f[0].starts_with('@') && !revoked.contains(&f[2]))
        .filter_map(|f| parse_key_fields(f[1], f[2]))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// One line of LabLink's managed known_hosts file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsEntry {
    pub alias: String,
    pub key_type: String,
    pub public_key: String,
}

/// Atomically rewrite LabLink's known_hosts file (mode 0600). The directory
/// is judged again before every write (it was checked when the daemon
/// started, but a path can change since), and the new file is created
/// exclusively under a fresh name without following a link, so nothing
/// planted in the directory can redirect the write.
pub fn write_known_hosts(path: &Path, entries: &[KnownHostsEntry]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    if let Some(why) = lablink_core::paths::writable_by_others(dir) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("refusing to write {}: {why}", path.display()),
        ));
    }
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{n}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)?;
        writeln!(
            f,
            "# Managed by lablinkd. Pinned host keys, keyed by HostKeyAlias. Do not edit."
        )?;
        for e in entries {
            writeln!(f, "{} {} {}", e.alias, e.key_type, e.public_key)?;
        }
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    let r = write();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn keyscan_parsing() {
        let out = format!(
            "# 192.168.10.70:22 SSH-2.0-OpenSSH_8.9p1\n192.168.10.70 ssh-ed25519 {BLOB}\n192.168.10.70 ssh-ed25519 {BLOB}\n192.168.10.70 ssh-dss AAAAB3\ngarbage\n192.168.10.70 ssh-rsa !!!notbase64\n"
        );
        let keys = parse_keyscan_output(&out);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].public_key.as_deref(), Some(BLOB));
    }

    #[test]
    fn revoked_key_is_never_taken_from_another_line() {
        let out = format!("10.0.0.1 ssh-ed25519 {BLOB}\n@revoked * ssh-ed25519 {BLOB}\n");
        assert!(parse_known_hosts_lines(&out).is_empty());
    }

    /// Hostile or corrupt scanner output never panics and only yields keys
    /// whose blob decodes to the declared type.
    #[test]
    fn fuzz_keyscan_and_known_hosts_parsers() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pieces = [
            "ssh-ed25519",
            "ssh-rsa",
            "@revoked",
            "@cert-authority",
            "#",
            " ",
            "\n",
            "\t",
            "\0",
            "|1|",
            "*",
            "10.0.0.1",
            BLOB,
            "AAAA",
            "====",
            "\u{202e}",
            "é",
        ];
        for _ in 0..20_000 {
            let mut s = String::new();
            for _ in 0..(next() % 24) {
                if next() % 4 == 0 {
                    s.push(char::from_u32((next() % 0x2_0000) as u32).unwrap_or('?'));
                } else {
                    s.push_str(pieces[(next() % pieces.len() as u64) as usize]);
                }
            }
            for k in parse_keyscan_output(&s)
                .into_iter()
                .chain(parse_known_hosts_lines(&s))
            {
                let blob = k.public_key.as_deref().unwrap();
                assert_eq!(
                    crate::fingerprint::fingerprint_of_blob(&k.key_type, blob).as_deref(),
                    Ok(k.fingerprint.as_str())
                );
            }
        }
    }

    #[test]
    fn known_hosts_markers_ignored() {
        let out = format!(
            "# Host 10.0.0.1 found: line 3\n|1|abc=|def= ssh-ed25519 {BLOB}\n@revoked 10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEY\n@cert-authority *.lab ssh-ed25519 {BLOB}\n"
        );
        assert_eq!(parse_known_hosts_lines(&out).len(), 1);
        let only_revoked = format!("@revoked 10.0.0.1 ssh-ed25519 {BLOB}\n");
        assert!(parse_known_hosts_lines(&only_revoked).is_empty());
    }

    #[test]
    fn known_hosts_file_written_atomically_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/known_hosts");
        let e = KnownHostsEntry {
            alias: "lablink.jetson-a".into(),
            key_type: "ssh-ed25519".into(),
            public_key: BLOB.into(),
        };
        write_known_hosts(&p, &[e]).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains(&format!("lablink.jetson-a ssh-ed25519 {BLOB}")));
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!p.with_extension("tmp").exists());
    }

    #[test]
    fn a_planted_link_never_redirects_the_pin_file() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep\n").unwrap();
        let kh = dir.join("known_hosts");
        // The old fixed temporary name, planted as a link: never followed.
        std::os::unix::fs::symlink(&victim, kh.with_extension("tmp")).unwrap();
        let e = KnownHostsEntry {
            alias: "lablink.a".into(),
            key_type: "ssh-ed25519".into(),
            public_key: BLOB.into(),
        };
        write_known_hosts(&kh, std::slice::from_ref(&e)).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep\n");
        assert!(std::fs::read_to_string(&kh).unwrap().contains("lablink.a"));
        assert!(!std::fs::symlink_metadata(&kh)
            .unwrap()
            .file_type()
            .is_symlink());
        // A directory others can write is refused before anything is written.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = write_known_hosts(&kh, &[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(std::fs::read_to_string(&kh).unwrap().contains("lablink.a"));
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
    }
}
