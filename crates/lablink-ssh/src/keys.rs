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
/// `@revoked` or `@cert-authority` markers are never treated as host keys.
pub fn parse_known_hosts_lines(out: &str) -> Vec<HostKey> {
    let mut keys: Vec<HostKey> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('@'))
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

/// One line of LabLink's managed known_hosts file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHostsEntry {
    pub alias: String,
    pub key_type: String,
    pub public_key: String,
}

/// Atomically rewrite LabLink's known_hosts file (mode 0600).
pub fn write_known_hosts(path: &Path, entries: &[KnownHostsEntry]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
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
    }
    std::fs::rename(&tmp, path)
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
    fn known_hosts_markers_ignored() {
        let out = format!(
            "# Host 10.0.0.1 found: line 3\n|1|abc=|def= ssh-ed25519 {BLOB}\n@revoked 10.0.0.1 ssh-ed25519 {BLOB}\n"
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
}
