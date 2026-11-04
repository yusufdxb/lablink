//! `lablink update`: upgrade to the latest release with the official
//! installer. This is the documented one-command installation run for you:
//! the script is downloaded completely (HTTPS only) before it runs, and the
//! script itself verifies the release checksum, installs the Debian package
//! with apt and restarts a running user daemon. Nothing is installed by this
//! process directly, and nothing runs as root except the installer's apt
//! step under sudo.

use crate::{Fail, R};
use lablink_core::exit;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The same URL the README's installation command uses.
pub const INSTALLER_URL: &str =
    "https://raw.githubusercontent.com/yusufdxb/lablink/main/scripts/install-linux.sh";

/// `--check` exit code when a newer release is available.
pub const UPDATE_AVAILABLE: i32 = exit::STATUS_YELLOW;

fn fail(m: impl Into<String>) -> Fail {
    Fail::new(exit::FAILURE, "update_failed", m)
}

/// Fetch the installer completely into memory; a partial download never runs.
fn download() -> Result<Vec<u8>, Fail> {
    let out = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--show-error",
            "--silent",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "--max-time",
            "120",
            "--retry",
            "2",
            INSTALLER_URL,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                fail("`lablink update` needs curl: sudo apt install curl")
            } else {
                fail(format!("could not run curl: {e}"))
            }
        })?;
    if !out.status.success() {
        return Err(fail(format!(
            "could not download the installer from {INSTALLER_URL}. Check your connection and try again. Nothing was changed."
        )));
    }
    Ok(out.stdout)
}

/// The release a given installer script installs (`readonly RELEASE_VERSION='x.y.z'`).
pub fn release_version(script: &str) -> Option<String> {
    let rest = script.split("readonly RELEASE_VERSION='").nth(1)?;
    let v = rest.split('\'').next()?;
    (!v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+~".contains(c)))
    .then(|| v.to_string())
}

/// Numeric dotted comparison of the release part (`0.4.10` > `0.4.9`).
/// A pre-release suffix (`-rc1`) sorts before the same release.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> (Vec<u64>, bool) {
        let (core, pre) = match v.split_once(['-', '~', '+']) {
            Some((c, _)) => (c, true),
            None => (v, false),
        };
        (
            core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
            pre,
        )
    }
    let (mut a, a_pre) = parts(candidate);
    let (mut b, b_pre) = parts(current);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => b_pre && !a_pre,
    }
}

fn is_package_install() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .is_some_and(|d| d == Path::new("/usr/bin"))
}

/// Run the installer script with bash, feeding it on stdin like the README's
/// `bash <<< "$installer"`. sudo reads its password from the terminal.
fn run_installer(script: &[u8], args: &[&str]) -> Result<i32, Fail> {
    let mut child = Command::new("bash")
        .arg("-s")
        .arg("--")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| fail(format!("could not run bash: {e}")))?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        // A write error means the installer exited early; its exit code says why.
        let _ = stdin.write_all(script);
    }
    let status = child
        .wait()
        .map_err(|e| fail(format!("installer did not finish: {e}")))?;
    Ok(status.code().unwrap_or(exit::FAILURE))
}

pub fn cmd_update(check: bool, migrate: bool, installer: Option<PathBuf>) -> R {
    if !cfg!(target_os = "linux") {
        return Err(fail(
            "`lablink update` supports Linux (Ubuntu) only; see docs/INSTALL.md.",
        ));
    }
    let script = match &installer {
        Some(p) => std::fs::read(p).map_err(|e| fail(format!("{}: {e}", p.display())))?,
        None => download()?,
    };
    let text = String::from_utf8_lossy(&script);
    let Some(latest) = release_version(&text) else {
        return Err(fail(
            "the downloaded installer names no release; nothing was changed. Try again later or see docs/INSTALL.md.",
        ));
    };
    let current = lablink_core::VERSION;
    let newer = is_newer(&latest, current);
    if check {
        if newer {
            println!("LabLink {latest} is available (this is {current}). Run `lablink update` to install it.");
            return Ok(UPDATE_AVAILABLE);
        }
        println!("LabLink {current} is up to date (latest release: {latest}).");
        return Ok(exit::OK);
    }
    if !newer && is_package_install() && !migrate {
        println!("LabLink {current} is up to date (latest release: {latest}). Nothing to do.");
        return Ok(exit::OK);
    }
    if !is_package_install() && !migrate {
        eprintln!(
            "Note: this lablink is not the Debian package. If the installer reports an older per-user\n\
             installation, run `lablink update --migrate` to move it aside (restorable) and use the package."
        );
    }
    println!("Updating LabLink {current} -> {latest} with the official installer...");
    let args: &[&str] = if migrate { &["--migrate"] } else { &[] };
    run_installer(&script, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_version() {
        assert_eq!(
            release_version("x\n    readonly RELEASE_VERSION='0.4.1'\n").as_deref(),
            Some("0.4.1")
        );
        assert_eq!(release_version("no version here"), None);
        assert_eq!(release_version("readonly RELEASE_VERSION=''"), None);
        assert_eq!(release_version("readonly RELEASE_VERSION='1;rm -rf'"), None);
    }

    #[test]
    fn compares_versions_numerically() {
        assert!(is_newer("0.4.2", "0.4.1"));
        assert!(is_newer("0.4.10", "0.4.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.5", "0.4.9"));
        assert!(!is_newer("0.4.1", "0.4.1"));
        assert!(!is_newer("0.4.0", "0.4.1"));
        assert!(!is_newer("0.4.1-rc1", "0.4.1"));
        assert!(is_newer("0.4.1", "0.4.1-rc1"));
    }
}
