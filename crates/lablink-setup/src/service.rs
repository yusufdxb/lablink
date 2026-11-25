//! systemd user-service control. A user service (not a system service) is
//! the right fit: lablinkd needs the user's ~/.ssh config, known_hosts and
//! ssh-agent, and none of its operations require root.
//!
//! Two unit locations are supported: the `.deb` ships
//! `/usr/lib/systemd/user/lablinkd.service`; tarball and source installs get
//! a unit written to `~/.config/systemd/user/` pointing at their `lablinkd`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

pub const UNIT_NAME: &str = "lablinkd.service";
/// Where distribution packages put user units.
pub const PACKAGED_UNIT_DIRS: [&str; 2] = ["/usr/lib/systemd/user", "/lib/systemd/user"];

/// `~/.config/systemd/user/lablinkd.service`.
pub fn user_unit_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| Some(lablink_core::paths::home().join(".config")))
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
            if lablink_core::program::trusted_executable(&p).is_ok() {
                return Ok(p.canonicalize().unwrap_or(p));
            }
        }
    }
    let p = lablink_core::program::find("lablinkd")
        .map_err(|e| format!("cannot find a trusted lablinkd next to lablink or on PATH: {e}"))?;
    p.canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", p.display()))
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
    lablink_core::program::command("systemctl")
        .map_err(|e| format!("cannot run systemctl: {e}"))?
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
    /// The daemon's last log line when the service is installed but not
    /// active: usually why it exited.
    pub last_message: Option<String>,
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
    let unit = user.clone().or_else(|| packaged.clone());
    let active = if systemd {
        first_word(systemctl_output(&["is-active", UNIT_NAME]))
    } else {
        "unknown".into()
    };
    let last_message = (systemd && unit.is_some() && active != "active")
        .then(|| last_log_lines(1).pop())
        .flatten();
    ServiceStatus {
        last_message,
        systemd,
        packaged: user.is_none() && packaged.is_some(),
        unit,
        enabled: if systemd {
            first_word(systemctl_output(&["is-enabled", UNIT_NAME]))
        } else {
            "unknown".into()
        },
        active,
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
        match run_verified("restart", &lablink_core::paths::default_socket_path()) {
            Ok(_) => "restarted lablinkd to apply the new configuration".into(),
            Err(e) => format!("lablinkd did not restart cleanly: {e}"),
        }
    } else {
        "lablinkd is not running as a service; restart it yourself to apply the new configuration"
            .into()
    }
}

/// What the user manager reports about the unit (`systemctl --user show`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitState {
    /// `active`, `activating`, `failed`, `inactive`, ...
    pub active: String,
    /// `running`, `auto-restart`, `dead`, `failed`, ...
    pub sub: String,
    /// Automatic restarts since the unit was last started by hand.
    pub restarts: u32,
    /// 0 when no process runs.
    pub main_pid: u32,
    /// The exit status of the last daemon process.
    pub exit_status: Option<i32>,
}

/// Parse `systemctl show -p ActiveState -p SubState -p NRestarts -p MainPID
/// -p ExecMainStatus` output (`Key=value` lines).
pub fn parse_unit_state(show: &str) -> UnitState {
    let get = |k: &str| {
        show.lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .unwrap_or_default()
            .trim()
    };
    UnitState {
        active: get("ActiveState").to_string(),
        sub: get("SubState").to_string(),
        restarts: get("NRestarts").parse().unwrap_or(0),
        main_pid: get("MainPID").parse().unwrap_or(0),
        exit_status: get("ExecMainStatus").parse().ok(),
    }
}

/// The unit's state, if a user manager for this environment answers.
pub fn unit_state() -> Option<UnitState> {
    let o = systemctl_output(&[
        "show",
        UNIT_NAME,
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "NRestarts",
        "-p",
        "MainPID",
        "-p",
        "ExecMainStatus",
    ])
    .ok()?;
    o.status
        .success()
        .then(|| parse_unit_state(&String::from_utf8_lossy(&o.stdout)))
}

/// The daemon's last `n` log lines from the user journal (empty when the
/// journal is not readable here). Only what lablinkd itself wrote:
/// systemd's lines about the unit ("Failed with result 'exit-code'") say
/// that it exited, not why.
pub fn last_log_lines(n: usize) -> Vec<String> {
    let Ok(mut c) = lablink_core::program::command("journalctl") else {
        return Vec::new();
    };
    let n = n.to_string();
    let unit = format!("_SYSTEMD_USER_UNIT={UNIT_NAME}");
    c.args(["--user", &unit, "-n", &n, "-o", "cat", "--no-pager"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    c.output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| lablink_core::printable(l.trim()))
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Watches a just-started service for a daemon that exits instead of
/// serving: the first process seen running is the one being started; if it
/// goes away, systemd schedules a restart, or the unit fails or stops, the
/// start failed.
#[derive(Debug, Default)]
pub struct ExitWatch {
    pid: Option<u32>,
}

impl ExitWatch {
    /// Begin watching; `before` is the unit state before the start, if
    /// known. Only what happens after the start is judged.
    pub fn new(_before: Option<&UnitState>) -> Self {
        Self { pid: None }
    }

    /// Why the start failed, if `now` shows it did.
    pub fn failed(&mut self, now: &UnitState) -> Option<String> {
        let status = now
            .exit_status
            .filter(|s| *s != 0)
            .map(|s| format!(" with status {s}"))
            .unwrap_or_default();
        if now.active == "failed" {
            return Some(format!("lablinkd exited{status} and the service failed"));
        }
        // Not NRestarts: `systemctl start` of a unit waiting in auto-restart
        // counts as one more restart of a healthy daemon, and a manual
        // restart resets the counter. A new PID is the reliable sign.
        if now.sub == "auto-restart" {
            return Some(format!(
                "lablinkd exited{status}; systemd keeps restarting it"
            ));
        }
        if now.active == "inactive" {
            return Some(format!("lablinkd exited{status} and the service stopped"));
        }
        if now.main_pid != 0 {
            match self.pid {
                None => self.pid = Some(now.main_pid),
                Some(p) if p != now.main_pid => {
                    return Some(format!(
                        "lablinkd exited{status}; systemd restarted it (pid {p} -> {})",
                        now.main_pid
                    ))
                }
                Some(_) => {}
            }
        }
        None
    }
}

/// The socket a daemon started by the user manager listens on, from
/// `systemctl --user show-environment` output (the same rules as
/// [`lablink_core::paths::default_socket_path`]).
pub fn manager_socket(manager_env: &str) -> Option<PathBuf> {
    let get = |k: &str| {
        manager_env
            .lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(p) = get("LABLINK_SOCKET") {
        return Some(p);
    }
    if let Some(d) = get("XDG_RUNTIME_DIR") {
        return Some(d.join("lablink").join("lablinkd.sock"));
    }
    let state = get("LABLINK_STATE_DIR").or_else(|| {
        get("XDG_STATE_HOME")
            .or_else(|| get("HOME").map(|h| h.join(".local").join("state")))
            .map(|d| d.join("lablink"))
    })?;
    Some(state.join("run").join("lablinkd.sock"))
}

fn ping(socket: &Path) -> Result<String, String> {
    let v = lablink_core::client::Client::new(socket)
        .with_timeout(std::time::Duration::from_secs(2))
        .call(&lablink_core::protocol::Request::Ping)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "lablinkd {} answers on {} (pid {})",
        v["version"].as_str().unwrap_or("?"),
        socket.display(),
        v["pid"]
    ))
}

/// Wait until a daemon answers a ping on `socket`, at most `timeout`.
/// `failed` is asked between attempts and ends the wait early with its
/// reason (the daemon exited); `explain` adds what is known about a daemon
/// that never answered. Polls every 100 ms: readiness has no event to wait
/// on without changing the unit type.
pub fn wait_ready(
    socket: &Path,
    timeout: std::time::Duration,
    mut failed: impl FnMut() -> Option<String>,
    explain: impl FnOnce() -> Vec<String>,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let last = match ping(socket) {
            Ok(m) => return Ok(m),
            Err(e) => e,
        };
        if let Some(why) = failed() {
            let mut msg = why;
            for line in explain() {
                msg.push_str("; ");
                msg.push_str(&line);
            }
            return Err(msg);
        }
        if std::time::Instant::now() >= deadline {
            let mut msg = format!(
                "lablinkd did not answer on {} within {} s ({last})",
                socket.display(),
                timeout.as_secs()
            );
            for line in explain() {
                msg.push_str("; ");
                msg.push_str(&line);
            }
            return Err(msg);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// What the user manager and the journal say about a daemon that did not
/// answer on `socket`: its state, its last message, a socket path that
/// differs between this session and the service, and the next step.
pub fn explain_down(socket: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(st) = unit_state() {
        out.push(format!(
            "service {} ({}{})",
            st.active,
            st.sub,
            if st.main_pid != 0 {
                format!(", pid {}", st.main_pid)
            } else {
                String::new()
            }
        ));
    }
    if let Some(line) = last_log_lines(1).pop() {
        out.push(format!("its last message: {line}"));
    }
    if let Ok(o) = systemctl_output(&["show-environment"]) {
        if let Some(theirs) = o
            .status
            .success()
            .then(|| manager_socket(&String::from_utf8_lossy(&o.stdout)))
            .flatten()
        {
            if theirs != socket {
                out.push(format!(
                    "the service listens on {} but this session uses {} (XDG_RUNTIME_DIR or LABLINK_SOCKET differs from the user manager's)",
                    theirs.display(),
                    socket.display()
                ));
            }
        }
    }
    out.push("details: journalctl --user -u lablinkd -n 20".into());
    out
}

/// How long a started service may take to answer. Startup before the
/// socket is bound takes well under a second; the network snapshot it waits
/// for is bounded at 3 s.
pub const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run a service action and, for those that start the daemon (`install`,
/// `start`, `restart`), report success only once it answers a ping on
/// `socket`. A daemon that exits during startup is reported with its last
/// message as soon as systemd sees it go.
pub fn run_verified(action: &str, socket: &Path) -> Result<String, String> {
    let before = unit_state();
    if matches!(action, "install" | "start" | "restart")
        && before.as_ref().is_some_and(|b| b.active == "failed")
    {
        // A crash loop can leave the unit failed (start limit hit), and a
        // failed unit refuses to start: once the cause is fixed, Start must
        // work.
        let _ = systemctl(&["reset-failed", UNIT_NAME]);
    }
    // systemctl itself can fail the start (a daemon that exits before the
    // job completes): say why the daemon exited, not only that it did.
    let why = |e: String| {
        let mut m = e;
        for line in explain_down(socket) {
            m.push_str("; ");
            m.push_str(&line);
        }
        m
    };
    let done = match action {
        "install" => install(true).map_err(why)?.join("; "),
        "start" | "restart" => {
            control(action).map_err(why)?;
            format!("{action}ed {UNIT_NAME}")
        }
        other => {
            control(other)?;
            return Ok(format!("service: {other} done"));
        }
    };
    let mut watch = ExitWatch::new(before.as_ref());
    let ready = wait_ready(
        socket,
        READY_TIMEOUT,
        || unit_state().and_then(|st| watch.failed(&st)),
        || explain_down(socket),
    )?;
    Ok(format!("{done}; {ready}"))
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

    fn st(active: &str, sub: &str, restarts: u32, pid: u32, status: i32) -> super::UnitState {
        super::UnitState {
            active: active.into(),
            sub: sub.into(),
            restarts,
            main_pid: pid,
            exit_status: Some(status),
        }
    }

    #[test]
    fn unit_state_is_read_from_systemctl_show() {
        let s = super::parse_unit_state(
            "ActiveState=activating\nSubState=auto-restart\nNRestarts=7\nMainPID=0\nExecMainStatus=1\n",
        );
        assert_eq!(s, st("activating", "auto-restart", 7, 0, 1));
        assert_eq!(super::parse_unit_state("").exit_status, None);
    }

    /// `systemctl start` of a Type=simple unit returns once the process is
    /// forked: a daemon that then exits must not read as started.
    #[test]
    fn a_daemon_that_exits_after_start_is_a_failed_start() {
        let before = st("inactive", "dead", 3, 0, 0);
        // Running and not answering yet: keep waiting.
        let mut w = super::ExitWatch::new(Some(&before));
        assert_eq!(w.failed(&st("active", "running", 3, 100, 0)), None);
        assert_eq!(w.failed(&st("active", "running", 3, 100, 0)), None);
        // Between a crash and the next restart.
        let why = w
            .failed(&st("activating", "auto-restart", 4, 0, 1))
            .unwrap();
        assert!(
            why.contains("status 1") && why.contains("restarting"),
            "{why}"
        );
        // A restart already happened between two looks.
        let mut w = super::ExitWatch::new(Some(&before));
        assert_eq!(w.failed(&st("active", "running", 3, 100, 0)), None);
        assert!(w
            .failed(&st("active", "running", 3, 200, 1))
            .unwrap()
            .contains("pid 100 -> 200"));
        // `systemctl start` of a unit waiting in auto-restart: one more
        // restart, a healthy new daemon. Not a failure.
        let looping = st("activating", "auto-restart", 4, 0, 1);
        let mut w = super::ExitWatch::new(Some(&looping));
        assert_eq!(w.failed(&st("active", "running", 5, 300, 0)), None);
        assert_eq!(w.failed(&st("active", "running", 5, 300, 0)), None);
        // A manual restart resets the counter: still judged by PID.
        let mut w = super::ExitWatch::new(Some(&st("active", "running", 9, 50, 0)));
        assert_eq!(w.failed(&st("active", "running", 0, 60, 0)), None);
        assert!(w.failed(&st("active", "running", 0, 61, 1)).is_some());
        let mut w = super::ExitWatch::new(None);
        assert!(w
            .failed(&st("failed", "failed", 0, 0, 2))
            .unwrap()
            .contains("failed"));
        let mut w = super::ExitWatch::new(None);
        assert!(w
            .failed(&st("inactive", "dead", 0, 0, 0))
            .unwrap()
            .contains("stopped"));
        let mut w = super::ExitWatch::new(None);
        assert_eq!(w.failed(&st("activating", "start", 0, 0, 0)), None);
    }

    #[test]
    fn the_service_socket_follows_the_user_managers_environment() {
        use std::path::PathBuf;
        let env = "HOME=/home/bob\nXDG_RUNTIME_DIR=/run/user/1001\n";
        assert_eq!(
            super::manager_socket(env),
            Some(PathBuf::from("/run/user/1001/lablink/lablinkd.sock"))
        );
        assert_eq!(
            super::manager_socket("XDG_RUNTIME_DIR=/run/user/1001\nLABLINK_SOCKET=/srv/l.sock\n"),
            Some(PathBuf::from("/srv/l.sock"))
        );
        assert_eq!(
            super::manager_socket("HOME=/home/bob\n"),
            Some(PathBuf::from(
                "/home/bob/.local/state/lablink/run/lablinkd.sock"
            ))
        );
        assert_eq!(super::manager_socket("XDG_RUNTIME_DIR=relative\n"), None);
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
