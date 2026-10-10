//! systemd user-service control. A user service (not a system service) is
//! the right fit: lablinkd needs the user's ~/.ssh config, known_hosts and
//! ssh-agent, and none of its operations require root.
//!
//! Two unit locations are supported: the `.deb` ships
//! `/usr/lib/systemd/user/lablinkd.service`; tarball and source installs get
//! a unit written to `~/.config/systemd/user/` pointing at their `lablinkd`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const UNIT_NAME: &str = "lablinkd.service";
/// Where distribution packages put user units.
pub const PACKAGED_UNIT_DIRS: [&str; 2] = ["/usr/lib/systemd/user", "/lib/systemd/user"];

/// `~/.config/systemd/user/lablinkd.service`.
pub fn user_unit_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("cannot determine the config directory (HOME unset)")?;
    Ok(base.join("systemd").join("user").join(UNIT_NAME))
}

/// The unit installed by a package, if any.
pub fn packaged_unit_path() -> Option<PathBuf> {
    PACKAGED_UNIT_DIRS
        .iter()
        .map(|d| Path::new(d).join(UNIT_NAME))
        .find(|p| p.is_file())
}

/// `lablinkd` next to the running executable, else on `$PATH`.
pub fn find_daemon() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("lablinkd");
            if p.is_file() {
                return Ok(p.canonicalize().unwrap_or(p));
            }
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("lablinkd");
            if p.is_file() {
                // A relative PATH entry must not become a relative ExecStart.
                return p
                    .canonicalize()
                    .map_err(|e| format!("cannot resolve {}: {e}", p.display()));
            }
        }
    }
    Err("cannot find the lablinkd binary next to lablink or on PATH".into())
}

/// The daemon path as one systemd `ExecStart` word: absolute, no control
/// characters (a newline would start a new unit directive), quoted when it
/// contains anything beyond `[A-Za-z0-9_./+-]`, with systemd's `%` and `$`
/// expansion escaped.
fn exec_word(daemon: &Path) -> Result<String, String> {
    let s = daemon
        .to_str()
        .ok_or_else(|| format!("{} is not valid UTF-8", daemon.display()))?;
    if !daemon.is_absolute() || s.chars().any(char::is_control) {
        return Err(format!(
            "the daemon path must be absolute and without control characters: {s:?}"
        ));
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./+-".contains(c))
    {
        return Ok(s.to_string());
    }
    let mut q = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                q.push('\\');
                q.push(c);
            }
            '%' => q.push_str("%%"),
            '$' => q.push_str("$$"),
            _ => q.push(c),
        }
    }
    q.push('"');
    Ok(q)
}

pub fn unit_text(daemon: &Path) -> Result<String, String> {
    let exec = exec_word(daemon)?;
    Ok(format!(
        "[Unit]
Description=LabLink daemon (device discovery, SSH health, identity tracking)

[Service]
Type=simple
ExecStart={} --no-color
Restart=on-failure
RestartSec=5s
# Stop cleanly on SIGTERM; the daemon flushes its cache and removes its socket.
KillSignal=SIGTERM
TimeoutStopSec=15s
Environment=LABLINK_LOG=info
# Guard rails: the daemon needs a handful of threads and no privileges.
NoNewPrivileges=yes
TasksMax=64

[Install]
WantedBy=default.target
",
        exec
    ))
}

fn systemctl_output(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run systemctl: {e}"))
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = systemctl_output(args)?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        Err(format!(
            "systemctl --user {} failed ({}){}",
            args.join(" "),
            out.status,
            if err.is_empty() {
                String::new()
            } else {
                format!(": {err}")
            }
        ))
    }
}

/// The config directory a process with this environment uses:
/// `$XDG_CONFIG_HOME`, else `$HOME/.config`.
fn config_base(xdg: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    let p = match (
        xdg.filter(|x| !x.is_empty()),
        home.filter(|h| !h.is_empty()),
    ) {
        (Some(x), _) => PathBuf::from(x),
        (None, Some(h)) => PathBuf::from(h).join(".config"),
        (None, None) => return None,
    };
    Some(p.canonicalize().unwrap_or(p))
}

/// Whether the user manager would use the same unit and config directory
/// as this process. Pure, for tests: `manager_env` is the output of
/// `systemctl --user show-environment`.
pub fn same_config_dir(manager_env: &str, xdg: Option<&str>, home: Option<&str>) -> bool {
    let get = |k: &str| {
        manager_env
            .lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
    };
    match (
        config_base(get("XDG_CONFIG_HOME"), get("HOME")),
        config_base(xdg, home),
    ) {
        (Some(m), Some(me)) => m == me,
        _ => false,
    }
}

/// Whether a systemd user manager answers (false in plain containers and in
/// some SSH sessions without a login session) and manages the units and
/// config of *this* environment. A process with another `HOME` or
/// `XDG_CONFIG_HOME` (a sandbox, a test, `sudo -u` without a login) must
/// never install, start or restart the real user's service.
pub fn systemd_available() -> bool {
    let Ok(o) = systemctl_output(&["show-environment"]) else {
        return false;
    };
    if !o.status.success() {
        return false;
    }
    let env = String::from_utf8_lossy(&o.stdout);
    same_config_dir(
        &env,
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// What the service looks like right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub systemd: bool,
    /// The unit file systemd will use (user unit wins over the packaged one).
    pub unit: Option<PathBuf>,
    pub packaged: bool,
    /// `enabled`, `disabled`, `static`, `not-found`, ...
    pub enabled: String,
    /// `active`, `inactive`, `failed`, `activating`, ...
    pub active: String,
}

impl ServiceStatus {
    pub fn is_enabled(&self) -> bool {
        self.enabled == "enabled"
    }
    pub fn is_active(&self) -> bool {
        self.active == "active"
    }
    /// One line for humans.
    pub fn describe(&self) -> String {
        if !self.systemd {
            return "systemd user session not available".into();
        }
        match &self.unit {
            None => "not installed".into(),
            Some(u) => format!(
                "{}, {} at login ({})",
                self.active,
                if self.is_enabled() {
                    "starts"
                } else {
                    "does not start"
                },
                u.display()
            ),
        }
    }
}

fn first_word(o: Result<std::process::Output, String>) -> String {
    o.ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".into())
}

pub fn status() -> ServiceStatus {
    let user = user_unit_path().ok().filter(|p| p.is_file());
    let packaged = packaged_unit_path();
    let systemd = systemd_available();
    ServiceStatus {
        systemd,
        packaged: user.is_none() && packaged.is_some(),
        unit: user.or(packaged),
        enabled: if systemd {
            first_word(systemctl_output(&["is-enabled", UNIT_NAME]))
        } else {
            "unknown".into()
        },
        active: if systemd {
            first_word(systemctl_output(&["is-active", UNIT_NAME]))
        } else {
            "unknown".into()
        },
    }
}

const NO_SYSTEMD: &str = "the systemd user manager is not available in this session (containers and some SSH sessions have none), or it manages a different home/config directory than this shell. Start the daemon yourself with `lablinkd &`, or log in to a desktop session and run this again";

/// Install (or reuse the packaged unit) and optionally enable + start it.
/// Returns human-readable progress lines.
pub fn install(enable: bool) -> Result<Vec<String>, String> {
    if !systemd_available() {
        return Err(NO_SYSTEMD.into());
    }
    let mut log = Vec::new();
    let user = user_unit_path()?;
    match packaged_unit_path() {
        Some(p) if !user.is_file() => {
            log.push(format!("using the packaged unit {}", p.display()));
        }
        _ => {
            let daemon = find_daemon()?;
            if let Some(d) = user.parent() {
                std::fs::create_dir_all(d)
                    .map_err(|e| format!("cannot create {}: {e}", d.display()))?;
            }
            std::fs::write(&user, unit_text(&daemon)?)
                .map_err(|e| format!("cannot write {}: {e}", user.display()))?;
            log.push(format!("wrote {}", user.display()));
        }
    }
    systemctl(&["daemon-reload"])?;
    if enable {
        systemctl(&["enable", "--now", UNIT_NAME])?;
        log.push(format!(
            "enabled and started {UNIT_NAME}; logs: journalctl --user -u lablinkd -f"
        ));
    } else {
        log.push(format!(
            "not enabled; start with: systemctl --user enable --now {UNIT_NAME}"
        ));
    }
    Ok(log)
}

/// Stop and disable the service, and remove the user unit (a packaged unit
/// belongs to the package and stays).
pub fn uninstall() -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let path = user_unit_path()?;
    let systemd = systemd_available();
    if systemd {
        let _ = systemctl(&["disable", "--now", UNIT_NAME]);
        log.push(format!("stopped and disabled {UNIT_NAME}"));
    } else {
        log.push("systemd not touched: no user manager for this home directory".into());
    }
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        log.push(format!("removed {}", path.display()));
    }
    if systemd {
        systemctl(&["daemon-reload"])?;
    }
    Ok(log)
}

/// `start`, `stop`, `restart`, `enable`, `disable` (autostart at login).
pub fn control(action: &str) -> Result<(), String> {
    if !systemd_available() {
        return Err(NO_SYSTEMD.into());
    }
    match action {
        "start" | "stop" | "restart" | "enable" | "disable" => systemctl(&[action, UNIT_NAME]),
        _ => Err(format!("unknown service action '{action}'")),
    }
}

/// Restart the daemon if it runs as a service, so a rewritten config takes
/// effect. Returns what happened, for display.
pub fn restart_if_active() -> String {
    let st = status();
    if st.systemd && st.is_active() {
        match systemctl(&["restart", UNIT_NAME]) {
            Ok(()) => "restarted lablinkd to apply the new configuration".into(),
            Err(e) => format!("could not restart lablinkd: {e}"),
        }
    } else {
        "lablinkd is not running as a service; restart it yourself to apply the new configuration"
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::same_config_dir;

    #[test]
    fn foreign_home_never_drives_the_real_user_manager() {
        let env = "LANG=C.UTF-8\nHOME=/home/alice\nPATH=/usr/bin\n";
        assert!(same_config_dir(env, None, Some("/home/alice")));
        assert!(same_config_dir(
            env,
            Some("/home/alice/.config"),
            Some("/home/alice")
        ));
        // A test or sandbox with its own HOME / XDG_CONFIG_HOME.
        assert!(!same_config_dir(env, None, Some("/tmp/.tmpXYZ")));
        assert!(!same_config_dir(
            env,
            Some("/tmp/.tmpXYZ/.config"),
            Some("/home/alice")
        ));
        let env2 = "HOME=/home/alice\nXDG_CONFIG_HOME=/srv/cfg\n";
        assert!(same_config_dir(env2, Some("/srv/cfg"), Some("/home/bob")));
        assert!(!same_config_dir(env2, None, Some("/home/alice")));
        assert!(
            !same_config_dir("", None, Some("/home/alice")),
            "unknown manager env"
        );
    }

    #[test]
    fn unit_has_absolute_exec_and_install_target() {
        let t = super::unit_text(std::path::Path::new("/opt/lablink/lablinkd")).unwrap();
        assert!(t.contains("ExecStart=/opt/lablink/lablinkd --no-color"));
        assert!(t.contains("WantedBy=default.target"));
        assert!(t.contains("Restart=on-failure"));
    }

    #[test]
    fn exec_start_is_one_quoted_word_and_never_a_new_directive() {
        let t = super::unit_text(std::path::Path::new("/opt/my apps/50%$x\"/lablinkd")).unwrap();
        assert!(
            t.contains("ExecStart=\"/opt/my apps/50%%$$x\\\"/lablinkd\" --no-color"),
            "{t}"
        );
        for bad in [
            "/opt/x\nExecStartPre=/bin/sh",
            "relative/lablinkd",
            "/opt/\u{1b}x",
        ] {
            assert!(
                super::unit_text(std::path::Path::new(bad)).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn packaged_unit_matches_the_generated_one() {
        let shipped = include_str!("../../../packaging/lablinkd.service");
        assert_eq!(
            shipped,
            super::unit_text(std::path::Path::new("/usr/bin/lablinkd")).unwrap(),
            "packaging/lablinkd.service is stale: regenerate it with `lablink install-service --print --daemon-path /usr/bin/lablinkd`"
        );
    }
}
