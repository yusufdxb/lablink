//! Launching the user's terminal emulator running `lablink ssh <device>` (or
//! another `lablink` command that needs a terminal, such as `copy-id`).
//!
//! This is the documented fallback instead of an embedded PTY terminal.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    if name.contains('/') {
        return is_exec(Path::new(name));
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| is_exec(&d.join(name))))
        .unwrap_or(false)
}

/// Terminal emulators from the built-in list that are installed.
pub fn installed_terminals() -> Vec<&'static str> {
    CANDIDATES.into_iter().filter(|c| runnable(c)).collect()
}

/// `lablink` next to the current executable, else resolved on `$PATH`.
pub fn lablink_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("lablink")))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("lablink"))
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
    let (program, args) = terminal_command(&found, &lablink_binary(), lablink_args);
    let mut child = Command::new(&program)
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
        assert_eq!(a, ["--", "/opt/ll/lablink", "ssh", "jetson-a"]);
    }

    #[test]
    fn konsole_alacritty_xterm_use_dash_e() {
        for t in ["konsole", "alacritty", "xterm", "x-terminal-emulator"] {
            assert_eq!(
                cmd(t).1,
                ["-e", "/opt/ll/lablink", "ssh", "jetson-a"],
                "{t}"
            );
        }
    }

    #[test]
    fn xfce_dash_x_and_kitty_bare() {
        assert_eq!(cmd("xfce4-terminal").1[0], "-x");
        assert_eq!(cmd("kitty").1, ["/opt/ll/lablink", "ssh", "jetson-a"]);
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
        assert_eq!(a, ["-e", "/l", "copy-id", "robot"]);
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
