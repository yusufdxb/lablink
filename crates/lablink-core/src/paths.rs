//! Default filesystem locations (XDG-style, per user, no root required).

use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// `$LABLINK_CONFIG`, else `$XDG_CONFIG_HOME/lablink/config.yaml`.
pub fn default_config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("LABLINK_CONFIG") {
        return PathBuf::from(p);
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("lablink")
        .join("config.yaml")
}

/// `$LABLINK_STATE_DIR`, else `$XDG_STATE_HOME/lablink` (cache DB, known_hosts).
pub fn default_state_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("LABLINK_STATE_DIR") {
        return PathBuf::from(p);
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local").join("state"))
        .join("lablink")
}

/// `$LABLINK_SOCKET`, else `$XDG_RUNTIME_DIR/lablink/lablinkd.sock`,
/// else `/tmp/lablink-<uid>/lablinkd.sock`.
pub fn default_socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("LABLINK_SOCKET") {
        return PathBuf::from(p);
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("lablink").join("lablinkd.sock"),
        _ => PathBuf::from(format!("/tmp/lablink-{}", uid())).join("lablinkd.sock"),
    }
}

/// The OpenSSH known_hosts file LabLink maintains for pinned identities.
pub fn known_hosts_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("known_hosts")
}

/// The SQLite cache database.
pub fn cache_db_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("cache.db")
}

/// The user's own known_hosts file (read-only for LabLink).
pub fn user_known_hosts() -> PathBuf {
    home().join(".ssh").join("known_hosts")
}
