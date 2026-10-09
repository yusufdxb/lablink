//! Bash completion script installation (per user, no root).

use std::path::PathBuf;

const SHELL_SCRIPT: &str = include_str!("../assets/lablink.bash");
/// Where the `.deb` installs the script for every user.
pub const SYSTEM_SCRIPT: &str = "/usr/share/bash-completion/completions/lablink";

pub fn bash_script() -> &'static str {
    SHELL_SCRIPT
}

/// `$XDG_DATA_HOME/bash-completion/completions/lablink`.
pub fn user_script_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .ok_or("cannot determine the data directory (HOME unset)")?;
    Ok(base
        .join("bash-completion")
        .join("completions")
        .join("lablink"))
}

/// Outcome of [`install`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installed {
    /// Written to this per-user path.
    User(PathBuf),
    /// The package already installed it for every user; nothing written.
    System(PathBuf),
}

/// Install the script for the current user, unless a package already
/// installed the identical script system-wide.
pub fn install() -> Result<Installed, String> {
    let system = PathBuf::from(SYSTEM_SCRIPT);
    if std::fs::read_to_string(&system).is_ok_and(|s| s == SHELL_SCRIPT) {
        return Ok(Installed::System(system));
    }
    let path = user_script_path()?;
    let dir = path.parent().ok_or("bad completion path")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::write(&path, SHELL_SCRIPT)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(Installed::User(path))
}

/// Whether completion is installed (per user or system-wide).
pub fn installed() -> Option<PathBuf> {
    let system = PathBuf::from(SYSTEM_SCRIPT);
    if system.is_file() {
        return Some(system);
    }
    user_script_path().ok().filter(|p| p.is_file())
}
