//! Version guards for scripts and machines that depend on one LabLink build.
//!
//! * `lablink version --require RANGE`: exit 0 when this CLI's version is in
//!   RANGE, exit 7 (refused by policy) when it is not.
//! * The update hold (`lablink update --hold` / `--unhold`): a file in the
//!   state dir. While it exists `lablink update` refuses with exit 7, and the
//!   official installer (scripts/install-linux.sh) refuses too, so an older
//!   CLI that downloads the newest installer is held as well.
//!
//! The hold fails closed: a hold file that exists but cannot be read or parsed
//! still holds.

use crate::update::is_newer;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};

/// Name of the hold file inside the state dir. The installer checks the same
/// path; keep them in sync.
pub const HOLD_FILE: &str = "update-hold";

/// One comparator of a range, e.g. `>=0.4.3`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Comparator {
    op: Op,
    version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

/// A version range: comma-separated comparators that must all hold, e.g.
/// `>=0.4.3,<0.4.4`. A bare version (`0.4.3`) means exactly that version.
/// A pre-release build (`0.4.4-rc1`) matches only a range that names a
/// pre-release, so `<0.4.4` never admits a 0.4.4 release candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    parts: Vec<Comparator>,
}

fn valid_version(v: &str) -> bool {
    let core = v.split(['-', '~', '+']).next().unwrap_or("");
    !core.is_empty()
        && core
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+~".contains(c))
}

/// Numeric order of two versions, the same rules `lablink update` uses
/// (`0.4.10` > `0.4.9`, missing parts are 0, a pre-release sorts first).
pub fn compare(a: &str, b: &str) -> Ordering {
    if is_newer(a, b) {
        Ordering::Greater
    } else if is_newer(b, a) {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

impl Range {
    pub fn parse(s: &str) -> Result<Range, String> {
        let mut parts = Vec::new();
        for raw in s.split(',') {
            let t = raw.trim();
            if t.is_empty() {
                return Err(format!("empty comparator in version range {s:?}"));
            }
            let (op, rest) = if let Some(r) = t.strip_prefix(">=") {
                (Op::Ge, r)
            } else if let Some(r) = t.strip_prefix("<=") {
                (Op::Le, r)
            } else if let Some(r) = t.strip_prefix("==") {
                (Op::Eq, r)
            } else if let Some(r) = t.strip_prefix('>') {
                (Op::Gt, r)
            } else if let Some(r) = t.strip_prefix('<') {
                (Op::Lt, r)
            } else if let Some(r) = t.strip_prefix('=') {
                (Op::Eq, r)
            } else {
                (Op::Eq, t)
            };
            let version = rest.trim();
            if !valid_version(version) {
                return Err(format!(
                    "invalid version {version:?} in range {s:?}; use comparators like \">=0.4.3,<0.4.4\""
                ));
            }
            parts.push(Comparator {
                op,
                version: version.to_string(),
            });
        }
        Ok(Range { parts })
    }

    pub fn matches(&self, version: &str) -> bool {
        let is_pre = |v: &str| v.contains(['-', '~', '+']);
        if is_pre(version) && !self.parts.iter().any(|c| is_pre(&c.version)) {
            return false;
        }
        self.parts.iter().all(|c| {
            let o = compare(version, &c.version);
            match c.op {
                Op::Eq => o == Ordering::Equal,
                Op::Gt => o == Ordering::Greater,
                Op::Ge => o != Ordering::Less,
                Op::Lt => o == Ordering::Less,
                Op::Le => o != Ordering::Greater,
            }
        })
    }
}

/// What the hold file records. Unknown fields are ignored so a newer build
/// can add some.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hold {
    #[serde(default)]
    pub reason: Option<String>,
    /// Unix seconds when the hold was placed.
    #[serde(default)]
    pub since: Option<u64>,
    /// The LabLink version that placed the hold (the version being kept).
    #[serde(default)]
    pub version: Option<String>,
}

pub fn hold_path(state_dir: &Path) -> PathBuf {
    state_dir.join(HOLD_FILE)
}

/// Is an update hold in place? `Some` when the hold file exists, also when it
/// cannot be read or parsed (fail closed: the reason then says so).
pub fn read_hold(state_dir: &Path) -> Option<Hold> {
    let p = hold_path(state_dir);
    match std::fs::symlink_metadata(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        _ => {}
    }
    let unreadable = |why: String| Hold {
        reason: Some(format!(
            "hold file {} could not be read ({why}); it still holds",
            p.display()
        )),
        since: None,
        version: None,
    };
    match std::fs::read(&p) {
        Ok(bytes) => match serde_json::from_slice::<Hold>(&bytes) {
            Ok(h) => Some(h),
            // A hand-written file (`echo "frozen for GROOT" > update-hold`)
            // holds with its text as the reason.
            Err(_) => {
                let text: String = String::from_utf8_lossy(&bytes)
                    .chars()
                    .filter(|c| !c.is_control() || *c == ' ')
                    .take(500)
                    .collect();
                let text = text.trim().to_string();
                Some(Hold {
                    reason: (!text.is_empty()).then_some(text),
                    since: None,
                    version: None,
                })
            }
        },
        Err(e) => Some(unreadable(e.to_string())),
    }
}

/// Place (or replace) the hold. The state dir is created private (0700).
pub fn write_hold(state_dir: &Path, hold: &Hold) -> Result<PathBuf, String> {
    std::fs::create_dir_all(state_dir).map_err(|e| format!("{}: {e}", state_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700));
    }
    let p = hold_path(state_dir);
    let tmp = state_dir.join(format!(".{HOLD_FILE}.{}", std::process::id()));
    let mut body = serde_json::to_vec_pretty(hold).map_err(|e| e.to_string())?;
    body.push(b'\n');
    std::fs::write(&tmp, body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", p.display())
    })?;
    Ok(p)
}

/// Remove the hold. `Ok(false)` when there was none.
pub fn remove_hold(state_dir: &Path) -> Result<bool, String> {
    let p = hold_path(state_dir);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_like_the_docs_say() {
        let r = Range::parse(">=0.4.3,<0.4.4").unwrap();
        assert!(r.matches("0.4.3"));
        assert!(!r.matches("0.4.4"));
        assert!(!r.matches("0.4.2"));
        // A pre-release matches only a range that names a pre-release
        // (it may carry the next release's changes).
        assert!(!r.matches("0.4.4-rc1"));
        assert!(!r.matches("0.4.3-rc1"));
        assert!(Range::parse(">=0.4.4-rc1").unwrap().matches("0.4.4-rc2"));
        assert!(Range::parse("0.4.3").unwrap().matches("0.4.3"));
        assert!(!Range::parse("=0.4.3").unwrap().matches("0.4.4"));
        assert!(Range::parse("==0.4").unwrap().matches("0.4.0"));
        assert!(Range::parse("<0.5").unwrap().matches("0.4.99"));
        assert!(!Range::parse("<0.5").unwrap().matches("0.5.0"));
        assert!(Range::parse(">0.4.9").unwrap().matches("0.4.10"));
        assert!(Range::parse("<=0.4.4").unwrap().matches("0.4.4"));
        assert!(Range::parse(" >= 0.4.3 , < 0.4.4 ")
            .unwrap()
            .matches("0.4.3"));
    }

    #[test]
    fn bad_ranges_are_rejected() {
        for bad in [
            "", ">=", "^0.4", "~0.4", ">=0.4.x", "0.4,,0.5", ">=a.b", "0..4", ">=0.4;rm",
        ] {
            assert!(Range::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn hold_round_trip_and_unhold() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        assert_eq!(read_hold(&state), None);
        let h = Hold {
            reason: Some("GROOT Stage 2".into()),
            since: Some(1),
            version: Some("0.4.3".into()),
        };
        write_hold(&state, &h).unwrap();
        assert_eq!(read_hold(&state), Some(h));
        assert!(remove_hold(&state).unwrap());
        assert!(!remove_hold(&state).unwrap());
        assert_eq!(read_hold(&state), None);
    }

    #[test]
    fn hand_written_or_corrupt_hold_still_holds() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(hold_path(d.path()), "frozen for the demo\n").unwrap();
        let h = read_hold(d.path()).expect("plain-text hold holds");
        assert_eq!(h.reason.as_deref(), Some("frozen for the demo"));
        std::fs::write(hold_path(d.path()), b"").unwrap();
        assert!(read_hold(d.path()).is_some(), "an empty hold file holds");
        std::fs::write(hold_path(d.path()), [0xff, 0xfe, b'{']).unwrap();
        assert!(read_hold(d.path()).is_some(), "a corrupt hold file holds");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_hold_still_holds() {
        let d = tempfile::tempdir().unwrap();
        // A directory where the file should be: exists, cannot be read as a file.
        std::fs::create_dir(hold_path(d.path())).unwrap();
        let h = read_hold(d.path()).expect("unreadable hold holds");
        assert!(h.reason.unwrap().contains("could not be read"));
    }
}
