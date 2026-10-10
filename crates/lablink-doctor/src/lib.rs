//! Read-only health checks for lab machines (`lablink doctor`).
//!
//! One SSH session per device runs a generated POSIX script made only of fixed
//! read-only command templates (see [`script`]). The session target and its
//! identity checks go through the same path as `lablink exec`: the daemon's
//! `Resolve`, `Target::from_resolve` (which refuses identity mismatches),
//! `build_args` in batch mode, and `run_captured`. This crate is used by the
//! CLI and the GUI and does not depend on either.

pub mod script;

use lablink_core::checks::CheckSpec;
use lablink_core::client::{Client, ClientError};
use lablink_core::exit;
use lablink_core::model::{
    Color, DeviceStatus, PortState, ResolveResult, StatusReport, SCHEMA_VERSION,
};
use lablink_core::protocol::{ErrorCode, Request};
use lablink_ssh::{
    build_args, classify_ssh_failure, run_captured, shell_quote, Mode, OutputMode, Target,
};
use script::{build_script, evaluate, parse_sections, ScriptEntry, Section};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl CheckStatus {
    pub fn word(self) -> &'static str {
        match self {
            CheckStatus::Ok => "OK",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceReport {
    pub name: String,
    /// Canonical `site/name`.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub site: String,
    /// The device's site is AWAY: reported, but never counted as a failure.
    #[serde(default)]
    pub away: bool,
    pub color: Color,
    pub ip: Option<String>,
    pub via: Option<String>,
    pub checks: Vec<CheckResult>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ready,
    Degraded,
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub verdict: Verdict,
    /// What was checked: a site's name, or "All sites".
    #[serde(default)]
    pub scope: String,
    pub devices: Vec<DeviceReport>,
}

impl Report {
    /// Devices are sorted by site and name; the verdict is derived from the
    /// colors of devices whose site is not AWAY.
    pub fn new(mut devices: Vec<DeviceReport>) -> Self {
        devices.sort_by(|a, b| (&a.site, &a.name).cmp(&(&b.site, &b.name)));
        Self {
            schema_version: SCHEMA_VERSION,
            verdict: verdict(&devices),
            scope: String::new(),
            devices,
        }
    }

    /// 0 when ready, else the exit code of the worst device color
    /// (red > gray > yellow).
    pub fn exit_code(&self) -> i32 {
        let rank = |c: Color| match c {
            Color::Green => 0,
            Color::Yellow => 1,
            Color::Gray => 2,
            Color::Red => 3,
        };
        match self
            .devices
            .iter()
            .filter(|d| !d.away)
            .map(|d| d.color)
            .max_by_key(|c| rank(*c))
        {
            None | Some(Color::Green) => exit::OK,
            Some(Color::Yellow) => exit::STATUS_YELLOW,
            Some(Color::Gray) => exit::STATUS_GRAY,
            Some(Color::Red) => exit::STATUS_RED,
        }
    }
}

pub fn verdict(devices: &[DeviceReport]) -> Verdict {
    let here: Vec<&DeviceReport> = devices.iter().filter(|d| !d.away).collect();
    if here
        .iter()
        .any(|d| matches!(d.color, Color::Red | Color::Gray))
    {
        Verdict::NotReady
    } else if here.iter().any(|d| d.color == Color::Yellow) {
        Verdict::Degraded
    } else {
        Verdict::Ready
    }
}

/// Fail beats warn beats ok; `skip` alone does not degrade.
pub fn aggregate(checks: &[CheckResult]) -> Color {
    if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        Color::Red
    } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
        Color::Yellow
    } else {
        Color::Green
    }
}

// ---- planning ---------------------------------------------------------------

/// One planned check (the implicit `ssh` check has no spec).
#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub spec: Option<CheckSpec>,
    pub reach_ip: Option<IpAddr>,
    pub via: Option<String>,
    /// Result known without running anything (e.g. no address for a target).
    pub immediate: Option<(CheckStatus, String)>,
}

fn default_label(spec: &CheckSpec) -> String {
    match spec {
        CheckSpec::Disk(_) => "Disk".into(),
        CheckSpec::NvidiaGpu(_) | CheckSpec::JetsonGpu => "GPU".into(),
        CheckSpec::Thermal(_) => "Thermal".into(),
        CheckSpec::Ros2(_) => "ROS2".into(),
        CheckSpec::Dds(_) => "DDS".into(),
        CheckSpec::Reach(r) => match (&r.label, &r.target) {
            (Some(l), _) => l.clone(),
            (None, Some(t)) => format!("{t} link"),
            (None, None) => "Reachable".into(),
        },
    }
}

/// Plan the checks for one device. `own_ip` and `gateway` describe the device;
/// `lookup` maps a device name to its known IP (from the daemon's status).
pub fn plan(
    specs: &[CheckSpec],
    ssh_enabled: bool,
    own_ip: Option<&str>,
    gateway: Option<&str>,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<Item> {
    let mut items = Vec::new();
    if ssh_enabled {
        items.push(Item {
            id: "ssh".into(),
            kind: "ssh".into(),
            label: "SSH".into(),
            spec: None,
            reach_ip: None,
            via: None,
            immediate: None,
        });
    }
    let default_specs;
    let specs = if specs.is_empty() && !ssh_enabled && gateway.is_some() {
        default_specs = vec![CheckSpec::Reach(Default::default())];
        &default_specs[..]
    } else {
        specs
    };
    for spec in specs {
        let kind = spec.kind().to_string();
        let n = items.iter().filter(|i| i.kind == kind).count();
        let id = if n == 0 {
            kind.clone()
        } else {
            format!("{kind}_{}", n + 1)
        };
        let mut item = Item {
            id,
            kind,
            label: default_label(spec),
            spec: Some(spec.clone()),
            reach_ip: None,
            via: None,
            immediate: None,
        };
        if let CheckSpec::Reach(r) = spec {
            let (addr, who) = match &r.target {
                Some(t) => (lookup(t), t.clone()),
                None => (own_ip.map(String::from), "this device".into()),
            };
            match (&r.target, gateway) {
                (None, None) => {
                    item.immediate = Some((
                        CheckStatus::Fail,
                        "reach needs a target, or a device reached via a gateway".into(),
                    ))
                }
                _ => match addr.and_then(|a| a.parse::<IpAddr>().ok()) {
                    Some(ip) => {
                        item.reach_ip = Some(ip);
                        if r.target.is_none() {
                            item.via = gateway.map(String::from);
                        }
                    }
                    None => {
                        item.immediate =
                            Some((CheckStatus::Fail, format!("no known address for {who}")))
                    }
                },
            }
        }
        items.push(item);
    }
    items
}

// ---- outcome -> results --------------------------------------------------------

/// What happened when the session was attempted.
#[derive(Debug)]
pub enum Outcome {
    /// The script ran to its end marker. The string describes the identity.
    Ran(BTreeMap<usize, Section>, String),
    /// The SSH session failed (connection, auth, timeout, no end marker).
    SessionFailed(String),
    /// Host key does not match the pin: nothing was attempted.
    Mismatch(String),
    /// The device (or its gateway) has never been located.
    NotLocated(String),
}

fn result(i: &Item, status: CheckStatus, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        id: i.id.clone(),
        kind: i.kind.clone(),
        label: i.label.clone(),
        status,
        detail: detail.into(),
    }
}

/// Combine the plan and the session outcome into check results and a color.
pub fn finish(items: &[Item], outcome: Outcome) -> (Color, Vec<CheckResult>) {
    match outcome {
        Outcome::NotLocated(d) => (
            Color::Gray,
            items
                .iter()
                .map(|i| result(i, CheckStatus::Skip, d.clone()))
                .collect(),
        ),
        Outcome::Mismatch(d) | Outcome::SessionFailed(d) => {
            let out: Vec<CheckResult> = items
                .iter()
                .enumerate()
                .map(|(n, i)| {
                    if n == 0 {
                        result(i, CheckStatus::Fail, d.clone())
                    } else {
                        result(i, CheckStatus::Skip, "no SSH session")
                    }
                })
                .collect();
            (Color::Red, out)
        }
        Outcome::Ran(sections, identity) => {
            let out: Vec<CheckResult> = items
                .iter()
                .enumerate()
                .map(|(idx, i)| match (&i.spec, &i.immediate) {
                    (_, Some((st, d))) => result(i, *st, d.clone()),
                    (None, None) => result(i, CheckStatus::Ok, identity.clone()),
                    (Some(spec), None) => {
                        let (st, d) = evaluate(spec, i.via.as_deref(), sections.get(&idx));
                        result(i, st, d)
                    }
                })
                .collect();
            (aggregate(&out), out)
        }
    }
}

// ---- running ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Named devices (`name` or `site/name`); empty means the default set.
    pub devices: Vec<String>,
    /// Overall time limit for each device's SSH session.
    pub timeout: Duration,
    /// Only this site's devices (default: the site(s) you are at).
    pub site: Option<String>,
    /// Every site's devices (AWAY sites are listed but never fail the run).
    pub all: bool,
}

#[derive(Debug)]
pub enum DoctorError {
    Client(ClientError),
    UnknownDevice(String),
    NoDevices,
}

impl From<ClientError> for DoctorError {
    fn from(e: ClientError) -> Self {
        DoctorError::Client(e)
    }
}

/// The device called `name` at `site` (gateways and reach targets always
/// refer to devices of the same site).
fn find_in_site<'a>(status: &'a StatusReport, site: &str, name: &str) -> Option<&'a DeviceStatus> {
    status
        .devices
        .iter()
        .find(|d| d.site.eq_ignore_ascii_case(site) && d.name.eq_ignore_ascii_case(name))
}

/// Run the doctor. `checks` maps device ids (`site/name`) to their
/// configured checks ([`lablink_core::Config::checks_by_id`]; may be empty).
pub fn run(
    client: &Client,
    checks: &BTreeMap<String, Vec<CheckSpec>>,
    opts: &Options,
) -> Result<Report, DoctorError> {
    let status: StatusReport = client.call_typed(&Request::Status {
        device: None,
        site: opts.site.clone(),
        all: opts.all || !opts.devices.is_empty(),
    })?;
    let in_scope = |d: &DeviceStatus| match &opts.site {
        Some(s) => d.site.eq_ignore_ascii_case(s),
        None => true,
    };
    // (id, daemon status if known, configured checks)
    let mut selection: Vec<(String, Option<DeviceStatus>, Vec<CheckSpec>)> = Vec::new();
    // Configured checks win; otherwise the device profile's defaults.
    let specs_for = |id: &str, ds: Option<&DeviceStatus>| -> Vec<CheckSpec> {
        checks
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(id))
            .map(|(_, v)| v.clone())
            .or_else(|| ds.and_then(|d| d.profile).map(|p| p.default_checks()))
            .unwrap_or_default()
    };
    if !opts.devices.is_empty() {
        for n in &opts.devices {
            // The daemon resolves names, aliases and site/name, and refuses
            // a name that is ambiguous between sites.
            let r: Result<StatusReport, _> = client.call_typed(&Request::Status {
                device: Some(n.clone()),
                site: None,
                all: false,
            });
            let d = match r {
                Ok(r) if !r.devices.is_empty() => r.devices[0].clone(),
                Ok(_) => return Err(DoctorError::UnknownDevice(n.clone())),
                Err(ClientError::Api(a)) if a.code == ErrorCode::DeviceNotFound => {
                    return Err(DoctorError::UnknownDevice(n.clone()))
                }
                Err(e) => return Err(e.into()),
            };
            if selection.iter().all(|s| s.0 != d.id) {
                let specs = specs_for(&d.id, Some(&d));
                selection.push((d.id.clone(), Some(d), specs));
            }
        }
    } else {
        for d in status.devices.iter().filter(|d| in_scope(d)) {
            let configured = checks.keys().any(|k| k.eq_ignore_ascii_case(&d.id));
            if configured || (d.monitoring && (d.profile.is_some() || checks.is_empty())) {
                selection.push((d.id.clone(), Some(d.clone()), specs_for(&d.id, Some(d))));
            }
        }
    }
    if selection.is_empty() {
        return Err(DoctorError::NoDevices);
    }
    let devices: Vec<DeviceReport> = std::thread::scope(|s| {
        let handles: Vec<_> = selection
            .iter()
            .map(|(id, ds, specs)| {
                let status = &status;
                s.spawn(move || check_device(client, status, id, ds.as_ref(), specs, opts.timeout))
            })
            .collect();
        handles
            .into_iter()
            .zip(&selection)
            .map(|(h, (id, ds, _))| {
                h.join().unwrap_or_else(|_| DeviceReport {
                    name: ds.as_ref().map_or_else(|| id.clone(), |d| d.name.clone()),
                    id: id.clone(),
                    site: ds.as_ref().map(|d| d.site.clone()).unwrap_or_default(),
                    away: false,
                    color: Color::Red,
                    ip: ds.as_ref().and_then(|d| d.ip.clone()),
                    via: ds.as_ref().and_then(|d| d.via.clone()),
                    checks: vec![CheckResult {
                        id: "ssh".into(),
                        kind: "ssh".into(),
                        label: "SSH".into(),
                        status: CheckStatus::Fail,
                        detail: "internal error".into(),
                    }],
                    duration_ms: 0,
                })
            })
            .collect()
    });
    let mut report = Report::new(devices);
    report.scope = match (&opts.site, opts.all) {
        (Some(s), _) => status
            .sites
            .iter()
            .find(|x| x.id.eq_ignore_ascii_case(s))
            .map_or_else(|| s.clone(), |x| x.name.clone()),
        (None, true) => "All sites".into(),
        (None, false) => {
            let active: Vec<&str> = status
                .sites
                .iter()
                .filter(|s| s.state == lablink_core::site::SiteState::Active)
                .map(|s| s.name.as_str())
                .collect();
            match active.as_slice() {
                [one] if status.sites.len() > 1 => one.to_string(),
                _ => String::new(),
            }
        }
    };
    Ok(report)
}

fn check_device(
    client: &Client,
    status: &StatusReport,
    id: &str,
    ds: Option<&DeviceStatus>,
    specs: &[CheckSpec],
    timeout: Duration,
) -> DeviceReport {
    let started = Instant::now();
    let name = ds.map_or(id, |d| d.name.as_str()).to_string();
    let site = ds.map(|d| d.site.clone()).unwrap_or_default();
    let away = ds.is_some_and(|d| d.site_state == lablink_core::site::SiteState::Away);
    let ssh_enabled = ds.is_none_or(|d| d.ssh_port != PortState::Disabled);
    let own_ip = ds.and_then(|d| d.ip.clone());
    let via = ds.and_then(|d| d.via.clone());
    let via_id = via
        .as_ref()
        .map(|g| lablink_core::config::device_id(&site, g));
    let lookup = |n: &str| find_in_site(status, &site, n).and_then(|d| d.ip.clone());
    let mut items = plan(
        specs,
        ssh_enabled,
        own_ip.as_deref(),
        via.as_deref(),
        &lookup,
    );
    // A network-only device that is directly attached: the daemon's own
    // reachability state is the check; nothing needs an SSH session.
    if let (false, None, Some(d)) = (ssh_enabled, &via, ds) {
        if d.color != Color::Gray && d.ip.is_some() {
            items.insert(0, network_item(d));
            for i in items.iter_mut().skip(1) {
                i.immediate.get_or_insert((
                    CheckStatus::Skip,
                    "needs SSH; this device is network-only".into(),
                ));
            }
            let (color, checks) = finish(&items, Outcome::Ran(BTreeMap::new(), String::new()));
            return DeviceReport {
                name,
                id: id.to_string(),
                site,
                away,
                color,
                ip: own_ip,
                via,
                checks,
                duration_ms: started.elapsed().as_millis() as u64,
            };
        }
    }
    let outcome = session(
        client,
        id,
        ds,
        ssh_enabled,
        via_id.as_deref(),
        via.as_deref(),
        &items,
        timeout,
    );
    let (color, checks) = finish(&items, outcome);
    DeviceReport {
        name,
        id: id.to_string(),
        site,
        away,
        color,
        ip: own_ip,
        via,
        checks,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

#[allow(clippy::too_many_arguments)]
fn session(
    client: &Client,
    id: &str,
    ds: Option<&DeviceStatus>,
    ssh_enabled: bool,
    via_id: Option<&str>,
    via_name: Option<&str>,
    items: &[Item],
    timeout: Duration,
) -> Outcome {
    let Some(ds) = ds else {
        return Outcome::NotLocated("not known to the daemon".into());
    };
    if ds.color == Color::Gray || ds.ip.is_none() {
        return Outcome::NotLocated(not_located_detail(ds.monitoring, &ds.reasons));
    }
    let host = if ssh_enabled {
        id
    } else {
        via_id.unwrap_or("")
    };
    if host.is_empty() {
        return Outcome::NotLocated("no SSH and no gateway: nothing can be checked".into());
    }
    let who = if ssh_enabled {
        String::new()
    } else {
        format!("gateway {}: ", via_name.unwrap_or(host))
    };
    let entries: Vec<ScriptEntry> = items
        .iter()
        .enumerate()
        .filter(|(_, i)| i.immediate.is_none())
        .filter_map(|(idx, i)| {
            i.spec.as_ref().map(|spec| ScriptEntry {
                idx,
                spec,
                reach_ip: i.reach_ip,
            })
        })
        .collect();
    let script = match build_script(&entries) {
        Ok(s) => s,
        Err(e) => return Outcome::SessionFailed(format!("invalid check: {e}")),
    };
    let r: ResolveResult = match client.call_typed(&Request::Resolve {
        device: host.to_string(),
    }) {
        Ok(r) => r,
        Err(ClientError::Api(a)) => {
            return match a.code {
                ErrorCode::IdentityMismatch => Outcome::Mismatch(mismatch_text(&who)),
                ErrorCode::Unreachable | ErrorCode::DeviceNotFound if ssh_enabled => {
                    Outcome::NotLocated(not_located_detail(ds.monitoring, &ds.reasons))
                }
                _ => Outcome::SessionFailed(format!("{who}{}", a.message)),
            }
        }
        Err(e) => return Outcome::SessionFailed(format!("{who}{e}")),
    };
    let t = match Target::from_resolve(&r) {
        Ok(t) => t,
        Err(_) => return Outcome::Mismatch(mismatch_text(&who)),
    };
    // Automated sessions only reach machines whose host key LabLink pinned:
    // never OpenSSH's own (prompting or trust-on-first-use) policy.
    if r.host_key_alias.is_none() {
        return Outcome::SessionFailed(format!(
            "{who}host key not pinned: check the fingerprint and run `lablink trust {}` before LabLink runs checks there",
            r.name
        ));
    }
    let args = build_args(
        &t,
        &Mode::Exec {
            command: format!("sh -c {}", shell_quote(&script)),
            batch: true,
        },
        &lablink_ssh::automated_session_args(),
    );
    let out = match run_captured(&t.binary, &args, timeout, OutputMode::Capture, true) {
        Ok(o) => o,
        Err(e) => return Outcome::SessionFailed(format!("{who}cannot run {}: {e}", t.binary)),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.timed_out {
        if let Some(sections) = parse_sections(&stdout) {
            return Outcome::Ran(sections, "host key pinned".into());
        }
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let why = if out.timed_out {
        format!("timed out after {}s", timeout.as_secs())
    } else if out.exit_code == Some(255) {
        classify_ssh_failure(&stderr).describe()
    } else if let Some(sig) = out.signal {
        format!("session killed by signal {sig}")
    } else {
        let line = stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("no output");
        format!(
            "session ended without completing (exit {}): {line}",
            out.exit_code.unwrap_or(-1)
        )
    };
    Outcome::SessionFailed(format!("{who}{why}"))
}

/// The reachability check of a network-only device, from the daemon's state.
pub fn network_item(d: &DeviceStatus) -> Item {
    use lablink_core::model::NetworkState as N;
    let latency = d
        .latency_ms
        .map(|m| {
            if m == 0 {
                ", <1 ms".to_string()
            } else {
                format!(", {m} ms")
            }
        })
        .unwrap_or_default();
    let r = match d.network {
        N::Online => (CheckStatus::Ok, format!("online{latency}")),
        N::Degraded => (CheckStatus::Warn, "recent checks failed".to_string()),
        N::Offline => (CheckStatus::Fail, "unreachable".to_string()),
        N::Unknown => (CheckStatus::Skip, "not checked yet".to_string()),
    };
    Item {
        id: "network".into(),
        kind: "network".into(),
        label: "Network".into(),
        spec: None,
        reach_ip: None,
        via: None,
        immediate: Some(r),
    }
}

/// Skip detail for a device that is not located: the daemon's first reason,
/// e.g. `not located: gateway 'jetson-a' is not reachable`.
pub fn not_located_detail(monitoring: bool, reasons: &[String]) -> String {
    if !monitoring {
        return "monitoring disabled".into();
    }
    // "not checked yet" says nothing once a more specific reason exists
    // (e.g. "gateway 'jetson-a' is not reachable" right after a restart).
    let specific: Vec<&str> = reasons
        .iter()
        .map(String::as_str)
        .filter(|r| *r != "not checked yet")
        .collect();
    let shown = if specific.is_empty() {
        reasons.iter().map(String::as_str).collect()
    } else {
        specific
    };
    if shown.is_empty() {
        "not located".into()
    } else {
        format!("not located: {}", shown.join("; "))
    }
}

/// Load the `checks:` map the way the CLI does. A missing file is fine unless
/// the path was given explicitly.
pub fn load_checks(
    path: &std::path::Path,
    explicit: bool,
) -> Result<BTreeMap<String, Vec<CheckSpec>>, String> {
    match lablink_core::Config::load(path) {
        Ok(c) => Ok(c.checks_by_id()),
        Err(lablink_core::config::ConfigError::Io { .. }) if !explicit => Ok(BTreeMap::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn mismatch_text(who: &str) -> String {
    format!("{who}identity mismatch: security stop")
}

// ---- rendering ---------------------------------------------------------------------

/// The one-line human text for a check.
pub fn human_text(c: &CheckResult) -> String {
    match c.status {
        CheckStatus::Ok => match c.kind.as_str() {
            "ssh" if c.detail.contains("NOT") => format!("OK, {}", c.detail),
            "ssh" => "OK".into(),
            "disk" | "reach" | "thermal" | "dds" | "jetson_gpu" | "network"
                if !c.detail.is_empty() =>
            {
                format!("OK {}", c.detail)
            }
            _ if c.detail.is_empty() => "OK".into(),
            _ => c.detail.clone(),
        },
        st => format!("{} {}", st.word(), c.detail).trim_end().to_string(),
    }
}

fn paint(on: bool, code: &str, text: &str) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn color_code(c: Color) -> &'static str {
    match c {
        Color::Green => "32",
        Color::Yellow => "33",
        Color::Red => "31",
        Color::Gray => "90",
    }
}

/// Compact human report. `color` enables ANSI (the caller decides: tty and no NO_COLOR).
pub fn render_human(r: &Report, color: bool) -> String {
    let scope = if r.scope.is_empty() {
        "LAB"
    } else {
        r.scope.as_str()
    };
    let head = match r.verdict {
        Verdict::Ready => (format!("{scope} READY"), Color::Green),
        Verdict::Degraded => (format!("{scope} DEGRADED"), Color::Yellow),
        Verdict::NotReady => (format!("{scope} NOT READY"), Color::Red),
    };
    // Names repeat across sites: show site/name then.
    let label = |d: &DeviceReport| {
        let dup = r.devices.iter().filter(|o| o.name == d.name).count() > 1;
        if dup && !d.id.is_empty() {
            d.id.clone()
        } else {
            d.name.clone()
        }
    };
    let name_w = r
        .devices
        .iter()
        .map(|d| label(d).len())
        .max()
        .unwrap_or(0)
        .max(7)
        + 2;
    let label_w = r
        .devices
        .iter()
        .flat_map(|d| d.checks.iter().map(|c| c.label.len()))
        .max()
        .unwrap_or(0)
        .max(9)
        + 2;
    let mut s = format!("{}\n\n", paint(color, color_code(head.1), &head.0));
    for d in &r.devices {
        let shown = label(d);
        let pad = " ".repeat(name_w.saturating_sub(shown.len()));
        let word = if d.away { "AWAY" } else { d.color.as_str() };
        s.push_str(&format!(
            "{shown}{pad}{}\n",
            paint(color, color_code(d.color), word)
        ));
        for c in &d.checks {
            let code = match c.status {
                CheckStatus::Ok => "32",
                CheckStatus::Warn => "33",
                CheckStatus::Fail => "31",
                CheckStatus::Skip => "90",
            };
            let pad = " ".repeat(label_w.saturating_sub(c.label.len()));
            s.push_str(&format!(
                "  {}{pad}{}\n",
                c.label,
                paint(color, code, &human_text(c))
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use script::Section;

    fn item(kind: &str, spec: Option<CheckSpec>) -> Item {
        Item {
            id: kind.into(),
            kind: kind.into(),
            label: kind.into(),
            spec,
            reach_ip: None,
            via: None,
            immediate: None,
        }
    }

    fn items() -> Vec<Item> {
        vec![
            item("ssh", None),
            item("disk", Some(CheckSpec::Disk(Default::default()))),
            item("thermal", Some(CheckSpec::Thermal(Default::default()))),
        ]
    }

    fn sections(df_pct: u32, thermal: &str) -> BTreeMap<usize, Section> {
        let mut m = BTreeMap::new();
        m.insert(
            1,
            Section {
                lines: vec!["Filesystem a".into(), format!("/dev/a 1 1 1 {df_pct}% /")],
                rc: Some(0),
            },
        );
        m.insert(
            2,
            Section {
                lines: thermal.lines().map(String::from).collect(),
                rc: Some(0),
            },
        );
        m
    }

    #[test]
    fn aggregation_paths() {
        let (c, r) = finish(
            &items(),
            Outcome::Ran(sections(75, "cpu 60000"), "host key pinned".into()),
        );
        assert_eq!(c, Color::Green);
        assert_eq!(r[0].detail, "host key pinned");
        assert_eq!(r[1].detail, "75% used");
        // warn degrades to yellow, fail to red.
        assert_eq!(
            finish(
                &items(),
                Outcome::Ran(sections(90, "cpu 60000"), String::new())
            )
            .0,
            Color::Yellow
        );
        assert_eq!(
            finish(
                &items(),
                Outcome::Ran(sections(99, "cpu 60000"), String::new())
            )
            .0,
            Color::Red
        );
        // skip alone does not degrade.
        let (c, r) = finish(&items(), Outcome::Ran(sections(10, ""), String::new()));
        assert_eq!((c, r[2].status), (Color::Green, CheckStatus::Skip));
        // identity mismatch: red, ssh fails, nothing else runs.
        let (c, r) = finish(&items(), Outcome::Mismatch(mismatch_text("")));
        assert_eq!(c, Color::Red);
        assert_eq!(
            (r[0].status, r[0].detail.as_str()),
            (CheckStatus::Fail, "identity mismatch: security stop")
        );
        assert!(r[1..].iter().all(|c| c.status == CheckStatus::Skip));
        // ssh failure: red.
        let (c, r) = finish(
            &items(),
            Outcome::SessionFailed("timed out after 25s".into()),
        );
        assert_eq!(
            (c, r[0].status, r[1].status),
            (Color::Red, CheckStatus::Fail, CheckStatus::Skip)
        );
        // not located: gray, everything skipped.
        let (c, r) = finish(&items(), Outcome::NotLocated("not located".into()));
        assert_eq!(c, Color::Gray);
        assert!(r
            .iter()
            .all(|c| c.status == CheckStatus::Skip && c.detail == "not located"));
        // an immediate result is kept without a section.
        let mut it = items();
        it[1].immediate = Some((CheckStatus::Fail, "no known address for robot-a".into()));
        let (c, r) = finish(&it, Outcome::Ran(BTreeMap::new(), String::new()));
        assert_eq!(
            (c, r[1].detail.as_str()),
            (Color::Red, "no known address for robot-a")
        );
    }

    fn dev(name: &str, color: Color) -> DeviceReport {
        DeviceReport {
            name: name.into(),
            id: String::new(),
            site: String::new(),
            away: false,
            color,
            ip: None,
            via: None,
            checks: vec![],
            duration_ms: 1,
        }
    }

    #[test]
    fn not_located_carries_the_daemon_reason() {
        let r = vec![
            "not checked yet".to_string(),
            "gateway 'jetson-a' is not reachable".to_string(),
        ];
        assert_eq!(
            not_located_detail(true, &r),
            "not located: gateway 'jetson-a' is not reachable"
        );
        assert_eq!(
            not_located_detail(true, &["not checked yet".to_string()]),
            "not located: not checked yet"
        );
        assert_eq!(not_located_detail(true, &[]), "not located");
        assert_eq!(not_located_detail(false, &r), "monitoring disabled");
        let missing = std::path::Path::new("/nonexistent/lablink/config.yaml");
        assert!(load_checks(missing, false).unwrap().is_empty());
        assert!(load_checks(missing, true).is_err());
    }

    #[test]
    fn verdict_and_exit_codes() {
        let r = |cs: &[Color]| {
            Report::new(
                cs.iter()
                    .enumerate()
                    .map(|(i, c)| dev(&format!("d{i}"), *c))
                    .collect(),
            )
        };
        let ready = r(&[Color::Green, Color::Green]);
        assert_eq!(
            (ready.verdict, ready.exit_code()),
            (Verdict::Ready, exit::OK)
        );
        let deg = r(&[Color::Green, Color::Yellow]);
        assert_eq!(
            (deg.verdict, deg.exit_code()),
            (Verdict::Degraded, exit::STATUS_YELLOW)
        );
        let gray = r(&[Color::Yellow, Color::Gray]);
        assert_eq!(
            (gray.verdict, gray.exit_code()),
            (Verdict::NotReady, exit::STATUS_GRAY)
        );
        let red = r(&[Color::Gray, Color::Red, Color::Yellow]);
        assert_eq!(
            (red.verdict, red.exit_code()),
            (Verdict::NotReady, exit::STATUS_RED)
        );
    }

    #[test]
    fn planning() {
        let lookup = |n: &str| (n == "robot-a").then(|| "192.168.50.161".to_string());
        let specs = vec![
            CheckSpec::Disk(Default::default()),
            CheckSpec::Disk(Default::default()),
            CheckSpec::Reach(lablink_core::checks::ReachCheck {
                target: Some("robot-a".into()),
                label: Some("robot link".into()),
            }),
            CheckSpec::Reach(lablink_core::checks::ReachCheck {
                target: Some("ghost".into()),
                label: None,
            }),
            CheckSpec::Reach(Default::default()),
        ];
        let p = plan(&specs, true, Some("10.0.0.2"), None, &lookup);
        let ids: Vec<&str> = p.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            ["ssh", "disk", "disk_2", "reach", "reach_2", "reach_3"]
        );
        assert_eq!(p[3].label, "robot link");
        assert_eq!(p[3].reach_ip, Some("192.168.50.161".parse().unwrap()));
        assert_eq!(p[4].label, "ghost link");
        assert_eq!(
            p[4].immediate.as_ref().unwrap().1,
            "no known address for ghost"
        );
        assert!(p[5]
            .immediate
            .as_ref()
            .unwrap()
            .1
            .contains("needs a target"));
        // A gateway-reached device defaults to reach-via-gateway, no ssh check.
        let p = plan(
            &[],
            false,
            Some("192.168.50.161"),
            Some("jetson-a"),
            &lookup,
        );
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].label.as_str(), p[0].via.as_deref()),
            ("Reachable", Some("jetson-a"))
        );
        assert_eq!(p[0].reach_ip, Some("192.168.50.161".parse().unwrap()));
    }

    pub fn fixture() -> Report {
        let c = |id: &str, kind: &str, label: &str, st, d: &str| CheckResult {
            id: id.into(),
            kind: kind.into(),
            label: label.into(),
            status: st,
            detail: d.into(),
        };
        use CheckStatus::*;
        Report::new(vec![
            DeviceReport {
                name: "jetson-a".into(),
                id: String::new(),
                site: String::new(),
                away: false,
                color: Color::Green,
                ip: Some("192.168.10.71".into()),
                via: None,
                duration_ms: 812,
                checks: vec![
                    c("ssh", "ssh", "SSH", Ok, "host key pinned"),
                    c(
                        "jetson_gpu",
                        "jetson_gpu",
                        "GPU",
                        Ok,
                        "L4T R36.4.7, GPU device present",
                    ),
                    c(
                        "thermal",
                        "thermal",
                        "Thermal",
                        Ok,
                        "max 61.3 C (tj-thermal)",
                    ),
                    c("ros2", "ros2", "ROS2", Ok, "Humble / OK"),
                    c("disk", "disk", "Disk", Ok, "75% used"),
                ],
            },
            DeviceReport {
                name: "robot-a".into(),
                id: String::new(),
                site: String::new(),
                away: false,
                color: Color::Green,
                ip: Some("192.168.50.161".into()),
                via: Some("jetson-a".into()),
                duration_ms: 790,
                checks: vec![c(
                    "reach",
                    "reach",
                    "Reachable",
                    Ok,
                    "via jetson-a, rtt 0.2 ms",
                )],
            },
            DeviceReport {
                name: "gpu-ws".into(),
                id: String::new(),
                site: String::new(),
                away: false,
                color: Color::Yellow,
                ip: Some("192.168.10.80".into()),
                via: None,
                duration_ms: 640,
                checks: vec![
                    c("ssh", "ssh", "SSH", Ok, "host key NOT pinned"),
                    c(
                        "nvidia_gpu",
                        "nvidia_gpu",
                        "GPU",
                        Ok,
                        "NVIDIA RTX A4000, 0% util, 28 C, 457/16303 MiB",
                    ),
                    c("disk", "disk", "Disk", Warn, "88% used"),
                ],
            },
        ])
    }

    #[test]
    fn json_is_deterministic_with_stable_key_order() {
        let r = fixture();
        let a = serde_json::to_string_pretty(&r).unwrap();
        assert_eq!(a, serde_json::to_string_pretty(&r).unwrap());
        let names: Vec<&str> = r.devices.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["gpu-ws", "jetson-a", "robot-a"]);
        let v: serde_json::Value = serde_json::from_str(&a).unwrap();
        assert_eq!(v["verdict"], "degraded");
        // Golden key order (serde struct order).
        let pos = |k: &str| a.find(&format!("\"{k}\"")).unwrap();
        let order = [
            "schema_version",
            "verdict",
            "scope",
            "devices",
            "name",
            "id",
            "site",
            "away",
            "color",
            "ip",
            "via",
            "checks",
            "kind",
            "label",
            "status",
            "detail",
            "duration_ms",
        ];
        let positions: Vec<usize> = order.iter().map(|k| pos(k)).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");
        assert!(a.contains("\"status\": \"warn\"") && a.contains("\"color\": \"yellow\""));
        let back: Report = serde_json::from_str(&a).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn human_format() {
        let h = render_human(&fixture(), false);
        let expect = "LAB DEGRADED\n\ngpu-ws    YELLOW\n  SSH        OK, host key NOT pinned\n  GPU        NVIDIA RTX A4000, 0% util, 28 C, 457/16303 MiB\n  Disk       WARN 88% used\njetson-a  GREEN\n  SSH        OK\n  GPU        OK L4T R36.4.7, GPU device present\n  Thermal    OK max 61.3 C (tj-thermal)\n  ROS2       Humble / OK\n  Disk       OK 75% used\nrobot-a   GREEN\n  Reachable  OK via jetson-a, rtt 0.2 ms\n";
        assert_eq!(h, expect);
        assert!(render_human(&fixture(), true).contains("\x1b[33mLAB DEGRADED\x1b[0m"));
        let ready = Report::new(vec![dev("jetson-a", Color::Green)]);
        assert!(render_human(&ready, false).starts_with("LAB READY\n\n"));
    }

    #[test]
    fn network_only_devices_are_judged_by_the_daemon_state() {
        use lablink_core::model::*;
        let mut d = DeviceStatus {
            name: "robot".into(),
            id: String::new(),
            site: "default".into(),
            site_name: "Default".into(),
            site_state: lablink_core::site::SiteState::Active,
            label: None,
            color: Color::Green,
            ip: Some("10.0.0.9".into()),
            discovery: DiscoveryState::Located,
            network: NetworkState::Online,
            ssh_port: PortState::Disabled,
            ssh_auth: AuthState::Disabled,
            identity: IdentityState::Unknown,
            latency_ms: Some(0),
            last_seen_ms: Some(1),
            username: None,
            interface: None,
            network_name: None,
            via: None,
            monitoring: true,
            reasons: vec![],
            services: vec![],
            profile: Some(lablink_core::profile::Profile::NetworkOnly),
            capabilities: vec![],
        };
        let run = |d: &DeviceStatus| {
            let items = vec![network_item(d)];
            finish(&items, Outcome::Ran(BTreeMap::new(), String::new()))
        };
        let (c, checks) = run(&d);
        assert_eq!((c, checks[0].status), (Color::Green, CheckStatus::Ok));
        assert_eq!(human_text(&checks[0]), "OK online, <1 ms");
        d.network = NetworkState::Degraded;
        assert_eq!(run(&d).0, Color::Yellow);
        d.network = NetworkState::Offline;
        assert_eq!(run(&d).0, Color::Red);
        // Profiles pick catalog checks; a network-only profile picks none.
        assert!(lablink_core::profile::Profile::NetworkOnly
            .default_checks()
            .is_empty());
        assert_eq!(
            lablink_core::profile::Profile::GpuWorkstation.default_checks()[1].kind(),
            "nvidia_gpu"
        );
    }
}
