//! Launching the user's terminal emulator running `lablink ssh <device>` (or
//! another `lablink` command that needs a terminal, such as `copy-id`).
//!
//! This is the documented fallback instead of an embedded PTY terminal.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Terminal emulators tried after the preference and `$TERMINAL`, in order.
const CANDIDATES: [&str; 7] = [
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xfce4-terminal",
    "alacritty",
    "kitty",
    "xterm",
];

/// Program and arguments that run `<lablink> <args...>` in terminal `found`
/// (a program name or path). Each emulator has its own "run this command"
/// flag: gnome-terminal `--`, xfce4-terminal `-x`, kitty none, others `-e`.
pub fn terminal_command(
    found: &str,
    lablink: &Path,
    lablink_args: &[&str],
) -> (String, Vec<String>) {
    let base = Path::new(found)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(found);
    let mut args: Vec<String> = match base {
        "gnome-terminal" => vec!["--".into()],
        "xfce4-terminal" => vec!["-x".into()],
        "kitty" => vec![],
        _ => vec!["-e".into()],
    };
    // Keep failures visible even in emulators that close when the child exits.
    // Arguments stay separate from the script, including device names and paths.
    args.extend(["/bin/sh".into(), "-c".into(),
        "\"$@\"; status=$?; if [ \"$status\" -ne 0 ]; then printf '\\nLabLink exited with status %s. Press Enter to close.\\n' \"$status\"; read -r reply; fi; exit \"$status\"".into(),
        "lablink-terminal".into()]);
    args.push(lablink.to_string_lossy().into_owned());
    args.extend(lablink_args.iter().map(|a| a.to_string()));
    (found.to_string(), args)
}

/// First usable terminal: the preference / `$TERMINAL` (if set), then the
/// fixed candidates. `exists` says whether a program name or path can be run.
pub fn find_terminal(env_terminal: Option<&str>, exists: &dyn Fn(&str) -> bool) -> Option<String> {
    env_terminal
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .into_iter()
        .chain(CANDIDATES)
        .find(|c| exists(c))
        .map(str::to_string)
}

/// Whether `name` (a path, or a program looked up on `$PATH`) is executable.
pub fn runnable(name: &str) -> bool {
    let is_exec = |p: &Path| {
        p.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    // Bare names only from absolute $PATH directories, never the current one.
    lablink_core::program::find(name).is_ok_and(|p| is_exec(&p))
}

/// Terminal emulators from the built-in list that are installed.
pub fn installed_terminals() -> Vec<&'static str> {
    CANDIDATES.into_iter().filter(|c| runnable(c)).collect()
}

/// The `lablink` the terminal runs: the one next to the current executable
/// if it is trusted, else the first in an absolute `$PATH` directory. Always
/// an absolute path to an executable file no other user could have replaced;
/// never a bare name, which the terminal would look up on its own `PATH` and
/// from its own current directory.
pub fn lablink_binary() -> Result<PathBuf, String> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("lablink")))
        .filter(|p| p.is_file());
    first_trusted(beside, || lablink_core::program::find("lablink").ok())
}

/// `beside` if it is a trusted executable, else the one `on_path` finds,
/// which must be trusted too.
fn first_trusted(
    beside: Option<PathBuf>,
    on_path: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf, String> {
    let beside = beside.map(|p| trusted_executable(&p));
    if let Some(Ok(p)) = beside {
        return Ok(p);
    }
    match on_path() {
        Some(p) => trusted_executable(&p),
        None => Err(beside.and_then(Result::err).unwrap_or_else(|| {
            "cannot find the lablink program next to the app or in $PATH".to_string()
        })),
    }
}

/// `p` if it is an absolute path to an executable regular file that no other
/// user could have written or replaced.
fn trusted_executable(p: &Path) -> Result<PathBuf, String> {
    lablink_core::program::trusted_executable(p)
        .map_err(|why| format!("not running {}: {why}", p.display()))
}

/// Spawn a detached terminal running `lablink <args...>`, for commands that
/// talk to the user (for example `copy-id`, which may ask for the device
/// password there; the GUI never sees it). Returns the terminal used; the
/// preference from Settings wins over `$TERMINAL`.
pub fn open_lablink_in_terminal(
    lablink_args: &[&str],
    preferred: Option<&str>,
) -> Result<String, String> {
    let env = preferred
        .map(str::to_string)
        .filter(|p| !p.trim().is_empty())
        .or_else(|| std::env::var("TERMINAL").ok());
    let found = find_terminal(env.as_deref(), &runnable).ok_or_else(|| {
        "no terminal emulator found (choose one in Settings, set $TERMINAL, or install gnome-terminal, konsole or xterm)"
            .to_string()
    })?;
    let (program, args) = terminal_command(&found, &lablink_binary()?, lablink_args);
    let mut child = lablink_core::program::command(&program)
        .map_err(|e| format!("failed to start {program}: {e}"))?
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("failed to start {program}: {e}"))?;
    // Reap the child when it exits so it does not linger as a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(found: &str) -> (String, Vec<String>) {
        terminal_command(found, Path::new("/opt/ll/lablink"), &["ssh", "jetson-a"])
    }

    #[test]
    fn gnome_terminal_uses_double_dash() {
        let (p, a) = cmd("gnome-terminal");
        assert_eq!(p, "gnome-terminal");
        assert_eq!(&a[..3], ["--", "/bin/sh", "-c"]);
        assert_eq!(&a[5..], ["/opt/ll/lablink", "ssh", "jetson-a"]);
    }

    #[test]
    fn konsole_alacritty_xterm_use_dash_e() {
        for t in ["konsole", "alacritty", "xterm", "x-terminal-emulator"] {
            assert_eq!(&cmd(t).1[..3], ["-e", "/bin/sh", "-c"], "{t}");
        }
    }

    #[test]
    fn xfce_dash_x_and_kitty_bare() {
        assert_eq!(cmd("xfce4-terminal").1[0], "-x");
        assert_eq!(&cmd("kitty").1[..2], ["/bin/sh", "-c"]);
    }

    #[test]
    fn path_to_terminal_matches_by_basename() {
        let (p, a) = cmd("/usr/bin/gnome-terminal");
        assert_eq!(p, "/usr/bin/gnome-terminal");
        assert_eq!(a[0], "--");
    }

    #[test]
    fn other_lablink_commands() {
        let (_, a) = terminal_command("xterm", Path::new("/l"), &["copy-id", "robot"]);
        assert_eq!(&a[5..], ["/l", "copy-id", "robot"]);
    }

    #[test]
    fn terminal_failures_wait_for_enter_and_arguments_are_never_shell_code() {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("lab link");
        std::fs::write(&fake, "#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 7\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let literal = "$(echo should-never-execute) ; \"quoted\"";
        let (_, args) = terminal_command("kitty", &fake, &[literal]);
        let mut child = std::process::Command::new(&args[0])
            .args(&args[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), literal);
        line.clear();
        output.read_line(&mut line).unwrap(); // blank separator
        line.clear();
        output.read_line(&mut line).unwrap();
        assert!(line.contains("status 7. Press Enter"), "{line}");
        assert!(child.try_wait().unwrap().is_none());
        child.stdin.take().unwrap().write_all(b"\n").unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(7));
        let (_, args) = terminal_command("kitty", Path::new("/bin/true"), &[]);
        assert!(std::process::Command::new(&args[0])
            .args(&args[1..])
            .stdin(Stdio::null())
            .status()
            .unwrap()
            .success());
    }

    /// The terminal is only ever handed an absolute, executable `lablink`
    /// that no other user could have replaced, never a bare name it would
    /// look up itself.
    #[test]
    fn only_a_trusted_absolute_lablink_is_run() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join("lablink");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        let mode = |m: u32| std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(m));
        mode(0o755).unwrap();
        assert_eq!(trusted_executable(&exe).unwrap(), exe);
        assert!(trusted_executable(Path::new("lablink")).is_err());
        mode(0o644).unwrap();
        assert!(trusted_executable(&exe).is_err(), "not executable");
        mode(0o757).unwrap();
        let why = trusted_executable(&exe).unwrap_err();
        assert!(why.contains("writable by every user"), "{why}");
        assert!(trusted_executable(&d.path().join("missing")).is_err());
        assert!(trusted_executable(d.path()).is_err(), "a directory");
        // An untrusted `lablink` beside the app gives way to a trusted one
        // on `$PATH`; with none there, its refusal is the answer.
        let good = d.path().join("good");
        std::fs::create_dir(&good).unwrap();
        let other = good.join("lablink");
        std::fs::write(&other, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            first_trusted(Some(exe.clone()), || Some(other.clone())).unwrap(),
            other
        );
        let why = first_trusted(Some(exe.clone()), || None).unwrap_err();
        assert!(why.contains("writable by every user"), "{why}");
        mode(0o755).unwrap();
        assert_eq!(
            first_trusted(Some(exe.clone()), || Some(other.clone())).unwrap(),
            exe
        );
        assert!(first_trusted(None, || None)
            .unwrap_err()
            .contains("cannot find"));
        assert!(first_trusted(None, || Some(PathBuf::from("lablink"))).is_err());
        // Whatever is found, the result is absolute.
        if let Ok(p) = lablink_binary() {
            assert!(p.is_absolute(), "{}", p.display());
        }
    }

    #[test]
    fn find_prefers_env_then_candidate_order() {
        let have = |n: &str| n == "konsole" || n == "xterm" || n == "mine";
        assert_eq!(find_terminal(Some("mine"), &have).as_deref(), Some("mine"));
        assert_eq!(find_terminal(None, &have).as_deref(), Some("konsole"));
        assert_eq!(find_terminal(Some("  "), &have).as_deref(), Some("konsole"));
        assert_eq!(
            find_terminal(Some("absent"), &have).as_deref(),
            Some("konsole")
        );
        assert_eq!(find_terminal(None, &|_| false), None);
    }
}

/// Onboarding needs a terminal whose lifetime follows the helper, including
/// when GNOME Terminal uses its D-Bus server. Unknown emulator argument
/// conventions are not guessed for security-sensitive setup.
pub fn onboarding_command(
    found: &str,
    lablink: &Path,
    socket: &Path,
    session: &Path,
) -> Result<std::process::Command, String> {
    let base = Path::new(found)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let flags: &[&str] = match base {
        "gnome-terminal" => &["--wait", "--"],
        "xterm" => &["-e"],
        "konsole" => &["--nofork", "-e"],
        _ => return Err(
            "SSH onboarding supports GNOME Terminal, Konsole, or xterm. Choose one in Settings."
                .into(),
        ),
    };
    if !lablink.is_absolute() || !lablink.is_file() {
        return Err("The onboarding CLI must be installed beside this development GUI.".into());
    }
    let mut cmd = lablink_core::program::command(found)
        .map_err(|_| "Terminal is unavailable.".to_string())?;
    cmd.args(flags)
        .arg(lablink)
        .arg("--socket")
        .arg(socket)
        .arg("onboard-ssh")
        .arg("--session")
        .arg(session)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(cmd)
}

pub fn onboarding_terminal(preferred: Option<&str>) -> Result<String, String> {
    if let Some(p) = preferred.filter(|p| !p.trim().is_empty()) {
        let base = Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !["gnome-terminal", "konsole", "xterm"].contains(&base) || !runnable(p) {
            return Err(
                "Choose GNOME Terminal, Konsole, or xterm in Settings for SSH onboarding.".into(),
            );
        }
        return Ok(p.to_string());
    }
    ["gnome-terminal", "konsole", "xterm"]
        .into_iter()
        .find(|p| runnable(p))
        .map(str::to_string)
        .ok_or_else(|| "Install GNOME Terminal, Konsole, or xterm to configure SSH.".into())
}

/// Pair the helper with this GUI build; never accidentally run an older
/// installed CLI while testing a development GUI.
pub fn onboarding_binary() -> Result<PathBuf, String> {
    let gui = std::env::current_exe().map_err(|_| "Cannot locate this GUI build.".to_string())?;
    onboarding_binary_next_to(&gui)
}

fn onboarding_binary_next_to(gui: &Path) -> Result<PathBuf, String> {
    gui.parent()
        .map(|dir| dir.join("lablink"))
        .filter(|cli| cli.is_absolute() && cli.is_file())
        .ok_or_else(|| {
            "Build the development lablink CLI beside lablink-gui before configuring SSH.".into()
        })
}

#[cfg(test)]
mod onboarding_tests {
    use super::*;
    #[test]
    fn onboarding_only_runs_the_cli_paired_with_its_gui() {
        let dir = tempfile::tempdir().unwrap();
        let gui = dir.path().join("lablink-gui");
        assert!(onboarding_binary_next_to(&gui).is_err());
        let cli = dir.path().join("lablink");
        std::fs::write(&cli, "").unwrap();
        assert_eq!(onboarding_binary_next_to(&gui).unwrap(), cli);
        assert!(onboarding_binary_next_to(Path::new("relative/lablink-gui")).is_err());
    }
    #[test]
    fn supported_terminals_use_a_waiting_argument_vector_without_a_shell() {
        let d = tempfile::tempdir().unwrap();
        let cli = d.path().join("lablink");
        std::fs::write(&cli, "").unwrap();
        let socket = d.path().join("socket;$(id)");
        let session = d.path().join("session with spaces");
        for (terminal, flags) in [
            ("gnome-terminal", vec!["--wait", "--"]),
            ("konsole", vec!["--nofork", "-e"]),
            ("xterm", vec!["-e"]),
        ] {
            // Stand-in executables, so argument construction does not depend
            // on which emulators happen to be installed in a test environment.
            let fake = d.path().join(terminal);
            std::fs::write(&fake, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            let cmd = onboarding_command(fake.to_str().unwrap(), &cli, &socket, &session).unwrap();
            let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
            assert_eq!(&args[..flags.len()], flags.as_slice());
            assert!(args.contains(&socket.to_str().unwrap()));
            assert!(args.contains(&session.to_str().unwrap()));
            assert!(!args.contains(&"-c"));
            assert!(args.contains(&"onboard-ssh"));
        }
        assert!(onboarding_command("/usr/bin/unknown", &cli, &socket, &session).is_err());
    }
}
