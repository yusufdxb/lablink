//! Pure logic for the adopt, trust and doctor workflows. No egui layout here,
//! so everything is unit-testable.

use crate::view::Level;
use lablink_core::model::{Color, DiscoveredHost, KeyView, TrustReport};
use lablink_doctor::{CheckStatus, Report, Verdict};

/// Unmatched hosts (candidates for adoption) first, then hosts that already
/// match a tracked device.
pub fn split_discovered(list: &[DiscoveredHost]) -> (Vec<&DiscoveredHost>, Vec<&DiscoveredHost>) {
    list.iter().partition(|h| h.matched_device.is_none())
}

/// Why `name` cannot be used for adoption (None when it is fine).
pub fn adopt_name_error(name: &str, existing: &[String]) -> Option<String> {
    let n = name.trim();
    if !lablink_core::config::valid_name(n) {
        return Some("use 1-64 characters from A-Z a-z 0-9 _ . - (not starting with '-')".into());
    }
    if existing.iter().any(|e| e.eq_ignore_ascii_case(n)) {
        return Some(format!("a device named '{n}' already exists"));
    }
    None
}

/// Settings chosen in the Adopt dialog, checked before anything is sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdoptForm {
    pub name: String,
    pub label: String,
    pub username: String,
    pub profile: Option<lablink_core::profile::Profile>,
    pub ssh: bool,
}

impl AdoptForm {
    /// Defaults for a discovered host: SSH on when its SSH port answered.
    pub fn for_host(h: &DiscoveredHost) -> Self {
        Self {
            ssh: h.ssh_port != lablink_core::model::PortState::Closed
                && h.ssh_port != lablink_core::model::PortState::Filtered,
            ..Default::default()
        }
    }

    /// Why the form cannot be sent (None when it is fine).
    pub fn error(&self, existing: &[String]) -> Option<String> {
        if let Some(e) = adopt_name_error(&self.name, existing) {
            return Some(e);
        }
        if self.label.len() > 64 || self.label.chars().any(char::is_control) {
            return Some("label: at most 64 printable characters".into());
        }
        let u = self.username.trim();
        if !u.is_empty() && !lablink_core::config::valid_username(u) {
            return Some(format!("'{u}' is not a valid login name"));
        }
        None
    }

    /// `(label, username, profile, ssh)` for the Adopt request.
    #[allow(clippy::type_complexity)]
    pub fn request(&self) -> (Option<String>, Option<String>, Option<String>, Option<bool>) {
        let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
        let ssh = self.ssh && self.profile.is_none_or(|p| p.uses_ssh());
        (
            opt(&self.label),
            if ssh { opt(&self.username) } else { None },
            self.profile.map(|p| p.as_str().to_string()),
            (!ssh).then_some(false),
        )
    }
}

/// Where a device is in Discover -> Adopt -> Trust -> Connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Done,
    /// The next thing to do.
    Next,
    /// Waits for an earlier step.
    Later,
    /// Security stop (host-key mismatch).
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifeStep {
    pub title: &'static str,
    pub state: StepState,
    pub hint: String,
}

pub fn lifecycle(d: &lablink_core::model::DeviceStatus) -> Vec<LifeStep> {
    use lablink_core::model::{AuthState, IdentityState, NetworkState, PortState};
    let step = |title, state, hint: &str| LifeStep {
        title,
        state,
        hint: hint.to_string(),
    };
    let mut v = vec![step(
        "Adopted",
        StepState::Done,
        "LabLink tracks this device by name",
    )];
    let online = matches!(d.network, NetworkState::Online | NetworkState::Degraded);
    if d.ssh_port == PortState::Disabled {
        v.push(if online {
            step("Online", StepState::Done, "answers on the network")
        } else {
            step(
                "Online",
                StepState::Next,
                "waiting for the device to answer",
            )
        });
    } else {
        let trusted = match d.identity {
            IdentityState::Verified => {
                step("Host key trusted", StepState::Done, "identity verified")
            }
            IdentityState::Mismatch => step(
                "Host key trusted",
                StepState::Stop,
                "SECURITY STOP: the host key changed",
            ),
            _ if online => step(
                "Host key trusted",
                StepState::Next,
                "compare the fingerprint with the device, then pin it",
            ),
            _ => step(
                "Host key trusted",
                StepState::Later,
                "waiting for the device to answer",
            ),
        };
        let trusted_done = trusted.state == StepState::Done;
        v.push(trusted);
        v.push(match d.ssh_auth {
            AuthState::Ok => step("SSH login", StepState::Done, "key login works"),
            AuthState::Disabled => step("SSH login", StepState::Done, "login checks are off"),
            AuthState::Failed if trusted_done => step(
                "SSH login",
                StepState::Next,
                "install your key with SSH Setup, or fix the username",
            ),
            _ if trusted_done => step("SSH login", StepState::Next, "test the login"),
            _ => step(
                "SSH login",
                StepState::Later,
                "after the host key is trusted",
            ),
        });
    }
    let all = v.iter().all(|s| s.state == StepState::Done);
    v.push(if all && d.color == lablink_core::model::Color::Green {
        step(
            "Managed",
            StepState::Done,
            "GREEN: ssh, exec and doctor by name",
        )
    } else {
        step("Managed", StepState::Later, "when every step above is done")
    });
    v
}

/// The two-step trust flow. The preview never pins anything; pinning sends
/// exactly the previewed fingerprints, as `lablink trust` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPlan {
    pub device: String,
    pub ip: String,
    pub scanned: Vec<KeyView>,
    pub pinned_before: Vec<KeyView>,
    /// Scanned keys differ from the existing pins: pinning needs `replace`.
    pub replace_required: bool,
    /// The daemon currently reports a host-key mismatch for the device.
    pub identity_mismatch: bool,
    /// The user ticked "verified out of band".
    pub verified_oob: bool,
}

impl TrustPlan {
    pub fn from_preview(r: &TrustReport, identity_mismatch: bool) -> Self {
        let replace_required = !r.pinned_before.is_empty()
            && r.scanned.iter().any(|k| {
                !r.pinned_before
                    .iter()
                    .any(|p| p.fingerprint == k.fingerprint)
            });
        Self {
            device: r.device.clone(),
            ip: r.ip.clone(),
            scanned: r.scanned.clone(),
            pinned_before: r.pinned_before.clone(),
            replace_required,
            identity_mismatch,
            verified_oob: false,
        }
    }

    /// Show the red warning.
    pub fn warn(&self) -> bool {
        self.replace_required || self.identity_mismatch
    }

    pub fn can_pin(&self) -> bool {
        !self.scanned.is_empty() && (!self.replace_required || self.verified_oob)
    }

    /// `(confirm, replace)` for the pin request; None while pinning is not allowed.
    pub fn request(&self) -> Option<(Vec<String>, bool)> {
        self.can_pin().then(|| {
            (
                self.scanned.iter().map(|k| k.fingerprint.clone()).collect(),
                self.replace_required && self.verified_oob,
            )
        })
    }
}

pub fn check_level(s: CheckStatus) -> Level {
    match s {
        CheckStatus::Ok => Level::Good,
        CheckStatus::Warn => Level::Warn,
        CheckStatus::Fail => Level::Bad,
        CheckStatus::Skip => Level::Neutral,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRow {
    pub label: String,
    pub word: &'static str,
    pub level: Level,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorDevice {
    pub name: String,
    pub color: Color,
    pub address: String,
    pub duration_ms: u64,
    pub rows: Vec<DoctorRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorView {
    pub header: &'static str,
    pub level: Level,
    pub devices: Vec<DoctorDevice>,
}

pub fn doctor_view(r: &Report) -> DoctorView {
    let (header, level) = match r.verdict {
        Verdict::Ready => ("LAB READY", Level::Good),
        Verdict::Degraded => ("LAB DEGRADED", Level::Warn),
        Verdict::NotReady => ("LAB NOT READY", Level::Bad),
    };
    DoctorView {
        header,
        level,
        devices: r.devices.iter().map(doctor_device).collect(),
    }
}

/// One device of a doctor report, ready to lay out.
pub fn doctor_device(d: &lablink_doctor::DeviceReport) -> DoctorDevice {
    DoctorDevice {
        name: d.name.clone(),
        color: d.color,
        address: match (&d.ip, &d.via) {
            (Some(ip), Some(g)) => format!("{ip} via {g}"),
            (Some(ip), None) => ip.clone(),
            (None, _) => "no address".into(),
        },
        duration_ms: d.duration_ms,
        rows: d
            .checks
            .iter()
            .map(|c| DoctorRow {
                label: c.label.clone(),
                word: c.status.word(),
                level: check_level(c.status),
                detail: c.detail.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_core::model::PortState;
    use lablink_doctor::{CheckResult, DeviceReport};

    fn key(fp: &str) -> KeyView {
        KeyView {
            key_type: "ssh-ed25519".into(),
            fingerprint: fp.into(),
            source: None,
        }
    }

    fn host(ip: &str, matched: Option<&str>) -> DiscoveredHost {
        DiscoveredHost {
            ip: ip.into(),
            site: None,
            mac: None,
            hostname: None,
            network_name: None,
            interface: None,
            sources: vec![],
            ssh_port: PortState::Open,
            fingerprints: vec![],
            matched_device: matched.map(String::from),
            note: None,
            first_seen_ms_ago: 0,
            last_seen_ms_ago: 0,
        }
    }

    fn preview(scanned: &[&str], pinned: &[&str]) -> TrustReport {
        TrustReport {
            schema_version: 1,
            device: "jetson-a".into(),
            ip: "10.0.0.5".into(),
            action: "preview".into(),
            scanned: scanned.iter().map(|f| key(f)).collect(),
            pinned_before: pinned.iter().map(|f| key(f)).collect(),
            pinned_now: vec![],
        }
    }

    #[test]
    fn adopt_form_validates_and_builds_the_request() {
        use lablink_core::profile::Profile;
        let mut h = host("10.0.0.9", None);
        let mut f = AdoptForm::for_host(&h);
        assert!(f.ssh);
        h.ssh_port = PortState::Closed;
        assert!(
            !AdoptForm::for_host(&h).ssh,
            "closed SSH port: network-only by default"
        );
        assert!(f.error(&[]).is_some(), "name required");
        f.name = "bench".into();
        assert_eq!(f.error(&[]), None);
        f.username = "-oProxyCommand=x".into();
        assert!(f.error(&[]).unwrap().contains("login name"));
        f.username = " ops ".into();
        f.label = "Bench PC".into();
        f.profile = Some(Profile::GpuWorkstation);
        assert_eq!(
            f.request(),
            (
                Some("Bench PC".into()),
                Some("ops".into()),
                Some("gpu_workstation".into()),
                None
            )
        );
        f.profile = Some(Profile::NetworkOnly);
        let (_, user, _, ssh) = f.request();
        assert_eq!((user, ssh), (None, Some(false)));
    }

    #[test]
    fn lifecycle_walks_trust_then_login_then_managed() {
        use lablink_core::model::*;
        let mut d = crate::view::tests_support::dev();
        d.identity = IdentityState::Unverified;
        d.ssh_auth = AuthState::Unknown;
        d.color = Color::Yellow;
        let st = |d: &DeviceStatus| lifecycle(d).iter().map(|s| s.state).collect::<Vec<_>>();
        use StepState::*;
        assert_eq!(st(&d), [Done, Next, Later, Later]);
        d.identity = IdentityState::Verified;
        d.ssh_auth = AuthState::Failed;
        assert_eq!(st(&d), [Done, Done, Next, Later]);
        d.ssh_auth = AuthState::Ok;
        d.color = Color::Green;
        assert_eq!(st(&d), [Done, Done, Done, Done]);
        d.identity = IdentityState::Mismatch;
        d.color = Color::Red;
        assert_eq!(st(&d)[1], Stop);
        // Network-only devices skip trust and login.
        let mut r = crate::view::tests_support::dev();
        r.ssh_port = PortState::Disabled;
        r.ssh_auth = AuthState::Disabled;
        r.identity = IdentityState::Unknown;
        assert_eq!(
            lifecycle(&r).iter().map(|s| s.title).collect::<Vec<_>>(),
            ["Adopted", "Online", "Managed"]
        );
        assert_eq!(st(&r), [Done, Done, Done]);
    }

    #[test]
    fn unmatched_filter() {
        let l = vec![
            host("10.0.0.1", None),
            host("10.0.0.2", Some("jetson-a")),
            host("10.0.0.3", None),
        ];
        let (un, m) = split_discovered(&l);
        assert_eq!(
            un.iter().map(|h| h.ip.as_str()).collect::<Vec<_>>(),
            ["10.0.0.1", "10.0.0.3"]
        );
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn adopt_names_are_validated() {
        let existing = vec!["jetson-a".to_string(), "robot-a".to_string()];
        assert_eq!(adopt_name_error("gpu-ws", &existing), None);
        assert_eq!(adopt_name_error(" lab-pc.1 ", &existing), None);
        for bad in [
            "",
            "   ",
            "has space",
            "semi;colon",
            "-lead",
            "a/b",
            &"x".repeat(65),
        ] {
            assert!(adopt_name_error(bad, &existing).is_some(), "{bad:?}");
        }
        assert!(adopt_name_error("JETSON-A", &existing)
            .unwrap()
            .contains("already exists"));
    }

    #[test]
    fn first_trust_confirms_exactly_the_previewed_keys_without_replace() {
        let p = TrustPlan::from_preview(&preview(&["SHA256:a", "SHA256:b"], &[]), false);
        assert!(!p.replace_required && !p.warn());
        assert_eq!(
            p.request(),
            Some((vec!["SHA256:a".to_string(), "SHA256:b".to_string()], false))
        );
    }

    #[test]
    fn replacing_pins_needs_the_explicit_checkbox() {
        let mut p = TrustPlan::from_preview(&preview(&["SHA256:new"], &["SHA256:old"]), true);
        assert!(p.replace_required && p.warn());
        assert_eq!(p.request(), None, "no pin before the checkbox");
        p.verified_oob = true;
        assert_eq!(p.request(), Some((vec!["SHA256:new".to_string()], true)));
        // Unchecking takes it away again.
        p.verified_oob = false;
        assert!(!p.can_pin());
    }

    #[test]
    fn known_keys_never_ask_for_replace_and_empty_scans_cannot_pin() {
        let mut p =
            TrustPlan::from_preview(&preview(&["SHA256:a"], &["SHA256:a", "SHA256:z"]), false);
        assert!(!p.replace_required);
        p.verified_oob = true; // a stray tick must not turn into replace=true
        assert_eq!(p.request(), Some((vec!["SHA256:a".to_string()], false)));
        let empty = TrustPlan::from_preview(&preview(&[], &[]), false);
        assert_eq!(empty.request(), None);
        // A reported mismatch alone warns but does not require replace.
        let m = TrustPlan::from_preview(&preview(&["SHA256:a"], &["SHA256:a"]), true);
        assert!(m.warn() && !m.replace_required);
    }

    #[test]
    fn doctor_rows_map_status_words_and_levels() {
        let c = |label: &str, status, detail: &str| CheckResult {
            id: label.to_lowercase(),
            kind: "x".into(),
            label: label.into(),
            status,
            detail: detail.into(),
        };
        let r = Report::new(vec![
            DeviceReport {
                name: "robot-a".into(),
                id: format!("default/{}", "robot-a"),
                site: "default".into(),
                away: false,
                color: Color::Gray,
                ip: Some("192.168.50.161".into()),
                via: Some("jetson-a".into()),
                checks: vec![c(
                    "Reachable",
                    CheckStatus::Skip,
                    "not located: gateway 'jetson-a' is not reachable",
                )],
                duration_ms: 3,
            },
            DeviceReport {
                name: "gpu-ws".into(),
                id: format!("default/{}", "gpu-ws"),
                site: "default".into(),
                away: false,
                color: Color::Yellow,
                ip: None,
                via: None,
                checks: vec![
                    c("SSH", CheckStatus::Ok, "host key pinned"),
                    c("Disk", CheckStatus::Warn, "88% used"),
                    c("GPU", CheckStatus::Fail, "gone"),
                ],
                duration_ms: 640,
            },
        ]);
        let v = doctor_view(&r);
        assert_eq!((v.header, v.level), ("LAB NOT READY", Level::Bad));
        assert_eq!(v.devices[0].name, "gpu-ws");
        assert_eq!(v.devices[0].address, "no address");
        let rows: Vec<(&str, Level)> = v.devices[0]
            .rows
            .iter()
            .map(|r| (r.word, r.level))
            .collect();
        assert_eq!(
            rows,
            [
                ("OK", Level::Good),
                ("WARN", Level::Warn),
                ("FAIL", Level::Bad)
            ]
        );
        assert_eq!(v.devices[1].address, "192.168.50.161 via jetson-a");
        assert_eq!(
            (v.devices[1].rows[0].word, v.devices[1].rows[0].level),
            ("SKIP", Level::Neutral)
        );
        assert_eq!(v.devices[0].duration_ms, 640);
    }
}
