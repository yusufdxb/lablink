//! Background threads. The UI thread never touches the socket or runs ssh:
//! it sends a [`Cmd`], and the answer comes back as an [`Event`] over mpsc
//! followed by `request_repaint()`.

use eframe::egui;
use lablink_core::client::{Client, ClientError};
use lablink_core::model::{
    DeviceDetail, DiscoverReport, DiscoveredHost, HistoryEvent, ResolveResult, StatusReport,
    TrustReport,
};
use lablink_core::protocol::{DeviceChanges, Request};
use lablink_ssh::{build_args, run_captured, Mode, OutputMode, Target};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Discovery can take about a minute on a large subnet.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(150);
const RUN_TIMEOUT: Duration = Duration::from_secs(30);
const HISTORY_LIMIT: u32 = 200;

/// A failed request, reduced to what the UI needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub message: String,
    /// The daemon socket is missing or refused the connection.
    pub unavailable: bool,
}

impl Fail {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unavailable: false,
        }
    }
}

impl From<ClientError> for Fail {
    fn from(e: ClientError) -> Self {
        Self {
            unavailable: matches!(e, ClientError::Unavailable { .. }),
            message: e.to_string(),
        }
    }
}

/// Result of one remote command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

pub enum Cmd {
    Inspect(String),
    History(String),
    Discovered,
    Discover,
    Apply {
        device: String,
        changes: DeviceChanges,
    },
    Run {
        device: String,
        command: String,
    },
    /// Start tracking a discovered host (only sent from the explicit Adopt click).
    Adopt {
        ip: String,
        name: String,
        label: Option<String>,
        username: Option<String>,
        profile: Option<String>,
        ssh: Option<bool>,
        site: Option<String>,
    },
    /// Every site with its state, evidence and the local detection signals.
    Sites,
    /// Choose the active site by hand (`Some(id)`), or go back to Auto.
    SetSiteMode(Option<String>),
    /// First-run setup (the wizard): config, service, completion, verify.
    Setup(Box<lablink_setup::init::InitOptions>),
    /// Query the systemd user service.
    Service,
    /// `install`, `start`, `stop`, `restart`, `enable` or `disable`.
    ServiceControl(&'static str),
    /// Validate and write config.yaml, then restart the daemon if it runs as a service.
    SaveConfig {
        cfg: Box<lablink_core::Config>,
        expected: Box<lablink_core::Config>,
        path: std::path::PathBuf,
    },
    /// Batch-mode test login, then ask the daemon to re-check the login.
    TestSsh(String),
    /// Scan host keys without pinning anything (the CLI's trust preview).
    TrustPreview(String),
    /// Pin exactly the previewed fingerprints (the CLI's confirmed trust).
    TrustPin {
        device: String,
        confirm: Vec<String>,
        replace: bool,
    },
    /// Read-only doctor run. `scope` labels the result ("all" or a device).
    Doctor {
        scope: String,
        devices: Vec<String>,
    },
}

pub enum Event {
    Poll {
        status: Result<StatusReport, Fail>,
        version: Option<String>,
        build_warning: Option<String>,
    },
    Detail(String, Result<Box<DeviceDetail>, Fail>),
    History(String, Result<Vec<HistoryEvent>, Fail>),
    Discovered(Result<Vec<DiscoveredHost>, Fail>),
    DiscoverDone(Result<DiscoverReport, Fail>),
    Applied(String, Result<(), Fail>),
    Ran(String, Result<RunResult, Fail>),
    /// `(ip, name, the new device's id)`.
    Adopted(String, String, Result<String, Fail>),
    Sites(Result<lablink_core::site::SitesReport, Fail>),
    SiteModeSet(Result<lablink_core::site::SitesReport, Fail>),
    TrustPreview(String, Result<TrustReport, Fail>),
    TrustPinned(String, Result<TrustReport, Fail>),
    Doctor(String, Result<Box<lablink_doctor::Report>, Fail>),
    Setup(Vec<lablink_setup::init::Step>),
    Service(lablink_setup::service::ServiceStatus),
    ServiceDone(&'static str, Result<(), String>),
    ConfigSaved(Result<String, String>),
    TestSsh(String, Result<RunResult, Fail>),
}

/// Handle held by the UI.
pub struct Worker {
    cmd_tx: Sender<Cmd>,
    poke_tx: Sender<()>,
}

impl Worker {
    /// Start the poller (status every [`POLL_INTERVAL`]) and the command
    /// dispatcher. Returns the handle and the event receiver.
    pub fn spawn(socket: PathBuf, ctx: egui::Context) -> (Self, Receiver<Event>) {
        let (ev_tx, ev_rx) = mpsc::channel::<Event>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
        let (poke_tx, poke_rx) = mpsc::channel::<()>();

        {
            let (ev_tx, ctx, socket) = (ev_tx.clone(), ctx.clone(), socket.clone());
            std::thread::spawn(move || {
                let client = Client::new(socket);
                loop {
                    if ev_tx.send(poll_once(&client)).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                    match poke_rx.recv_timeout(POLL_INTERVAL) {
                        Ok(()) => while poke_rx.try_recv().is_ok() {},
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
        }

        // One short-lived thread per command, so a 60 s discovery never
        // blocks an inspect or the status poller.
        std::thread::spawn(move || {
            for cmd in cmd_rx {
                let (ev_tx, ctx, socket) = (ev_tx.clone(), ctx.clone(), socket.clone());
                std::thread::spawn(move || {
                    let _ = ev_tx.send(execute(&socket, cmd));
                    ctx.request_repaint();
                });
            }
        });

        (Self { cmd_tx, poke_tx }, ev_rx)
    }

    pub fn send(&self, cmd: Cmd) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Ask the poller to refresh now instead of waiting for the interval.
    pub fn refresh(&self) {
        let _ = self.poke_tx.send(());
    }
}

fn poll_once(client: &Client) -> Event {
    let (version, build_warning) = match client.call(&Request::Ping) {
        Ok(v) => (
            Some(parse_version(&v)),
            daemon_build_warning(&v, lablink_core::GIT_SHA),
        ),
        Err(e) => {
            return Event::Poll {
                status: Err(e.into()),
                version: None,
                build_warning: None,
            };
        }
    };
    // Every site: the UI filters by the site view it shows.
    let status = client
        .call_typed::<StatusReport>(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .map_err(Fail::from);
    Event::Poll {
        status,
        version,
        build_warning,
    }
}

fn execute(socket: &PathBuf, cmd: Cmd) -> Event {
    let client = Client::new(socket);
    match cmd {
        Cmd::Inspect(d) => {
            let r = client
                .call_typed::<DeviceDetail>(&Request::Inspect { device: d.clone() })
                .map(Box::new)
                .map_err(Fail::from);
            Event::Detail(d, r)
        }
        Cmd::History(d) => {
            let req = Request::History {
                device: Some(d.clone()),
                limit: HISTORY_LIMIT,
            };
            let r = client
                .call(&req)
                .map_err(Fail::from)
                .and_then(|v| parse_events(&v));
            Event::History(d, r)
        }
        Cmd::Discovered => {
            let r = client
                .call(&Request::Discovered)
                .map_err(Fail::from)
                .and_then(|v| parse_discovered(&v));
            Event::Discovered(r)
        }
        Cmd::Discover => {
            let r = client
                .with_timeout(DISCOVER_TIMEOUT)
                .call_typed::<DiscoverReport>(&Request::Discover { scan_cidr: None })
                .map_err(Fail::from);
            Event::DiscoverDone(r)
        }
        Cmd::Apply { device, changes } => {
            let r = client
                .call(&Request::Set {
                    device: device.clone(),
                    changes,
                })
                .map(|_| ())
                .map_err(Fail::from);
            Event::Applied(device, r)
        }
        Cmd::Run { device, command } => {
            let r = run_remote(&client, &device, &command);
            Event::Ran(device, r)
        }
        Cmd::Adopt {
            ip,
            name,
            label,
            username,
            profile,
            ssh,
            site,
        } => {
            let r = client
                .call_typed::<lablink_core::model::DeviceStatus>(&Request::Adopt {
                    ip: ip.clone(),
                    name: name.clone(),
                    label,
                    username,
                    profile,
                    ssh,
                    site,
                })
                .map(|s| s.id)
                .map_err(Fail::from);
            Event::Adopted(ip, name, r)
        }
        Cmd::Sites => Event::Sites(client.call_typed(&Request::Sites).map_err(Fail::from)),
        Cmd::SetSiteMode(site) => Event::SiteModeSet(
            client
                .call_typed(&Request::SetSiteMode { site })
                .map_err(Fail::from),
        ),
        Cmd::Setup(opts) => Event::Setup(lablink_setup::init::run(&opts)),
        Cmd::Service => Event::Service(lablink_setup::service::status()),
        Cmd::ServiceControl(action) => {
            let r = if action == "install" {
                lablink_setup::service::install(true).map(|_| ())
            } else {
                lablink_setup::service::control(action)
            };
            Event::ServiceDone(action, r)
        }
        Cmd::SaveConfig {
            cfg,
            expected,
            path,
        } => {
            let r = lablink_setup::configfile::update(&path, |current| {
                if current != expected.as_ref() {
                    return Err("Configuration changed since Settings was opened. Reload Settings and apply your changes again.".into());
                }
                *current = *cfg;
                Ok(())
            }).map(|backup| {
                let mut m = format!("saved {}", path.display());
                if let Some(b) = backup {
                    m.push_str(&format!(" (previous file: {})", b.display()));
                }
                format!("{m}; {}", lablink_setup::service::restart_if_active())
            });
            Event::ConfigSaved(r)
        }
        Cmd::TestSsh(device) => {
            let r = run_remote(&client, &device, "true");
            // Refresh identity and login after failures too: a changed key must
            // not leave the card showing a stale VERIFIED result.
            let _ = client.call(&Request::Set {
                device: device.clone(),
                changes: DeviceChanges {
                    recheck: true,
                    ..Default::default()
                },
            });
            Event::TestSsh(device, r)
        }
        Cmd::TrustPreview(device) => {
            let r = client
                .call_typed::<TrustReport>(&Request::Trust {
                    device: device.clone(),
                    confirm: None,
                    replace: false,
                })
                .map_err(Fail::from);
            Event::TrustPreview(device, r)
        }
        Cmd::TrustPin {
            device,
            confirm,
            replace,
        } => {
            let r = client
                .call_typed::<TrustReport>(&Request::Trust {
                    device: device.clone(),
                    confirm: Some(confirm),
                    replace,
                })
                .map_err(Fail::from);
            Event::TrustPinned(device, r)
        }
        Cmd::Doctor { scope, devices } => Event::Doctor(scope, run_doctor(&client, devices)),
    }
}

/// Resolve through the daemon (it refuses identity mismatches and unreachable
/// devices), then run one batch-mode command through the shared OpenSSH wrapper.
fn run_remote(client: &Client, device: &str, command: &str) -> Result<RunResult, Fail> {
    let resolved: ResolveResult = client.call_typed(&Request::Resolve {
        device: device.to_string(),
    })?;
    let target = Target::from_resolve(&resolved).map_err(Fail::msg)?;
    // Like the doctor: actions only run on a machine whose key is pinned.
    if target.host_key_alias.is_none() {
        return Err(Fail::msg(format!(
            "the host key of '{}' is not pinned yet: check its fingerprint and use Trust first",
            resolved.name
        )));
    }
    let mode = Mode::Exec {
        command: command.to_string(),
        batch: true,
    };
    let args = build_args(&target, &mode, &lablink_ssh::automated_session_args());
    let out = run_captured(
        &target.binary,
        &args,
        RUN_TIMEOUT,
        OutputMode::Capture,
        true,
    )
    .map_err(|e| Fail::msg(format!("failed to run {}: {e}", target.binary)))?;
    Ok(RunResult {
        exit_code: out.exit_code,
        signal: out.signal,
        timed_out: out.timed_out,
        truncated: out.stdout_truncated || out.stderr_truncated,
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        duration: out.duration,
    })
}

/// Same config loading as `lablink doctor`; reuses the read-only doctor run.
fn run_doctor(client: &Client, devices: Vec<String>) -> Result<Box<lablink_doctor::Report>, Fail> {
    let checks = lablink_doctor::load_checks(&lablink_core::paths::default_config_path(), false)
        .map_err(Fail::msg)?;
    let opts = lablink_doctor::Options {
        devices,
        timeout: Duration::from_secs(25),
        site: None,
        all: false,
    };
    lablink_doctor::run(client, &checks, &opts)
        .map(Box::new)
        .map_err(|e| match e {
            lablink_doctor::DoctorError::Client(c) => Fail::from(c),
            lablink_doctor::DoctorError::UnknownDevice(n) => {
                Fail::msg(format!("unknown device '{n}'"))
            }
            lablink_doctor::DoctorError::NoDevices => Fail::msg("no devices to check"),
        })
}

pub fn parse_version(v: &Value) -> String {
    let version = v.get("version").and_then(Value::as_str).unwrap_or("?");
    match v
        .get("git_sha")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(sha) => format!("{version} ({})", sha.chars().take(12).collect::<String>()),
        None => version.to_string(),
    }
}

fn daemon_build_warning(v: &Value, client_sha: Option<&str>) -> Option<String> {
    let mismatch = v["version"].as_str() != Some(lablink_core::VERSION)
        || client_sha.is_some_and(|sha| v["git_sha"].as_str() != Some(sha));
    mismatch.then(|| {
        "The running daemon is a different or unknown build. Restart lablinkd after upgrading."
            .into()
    })
}

/// `History` returns `{"events": [...]}`.
pub fn parse_events(v: &Value) -> Result<Vec<HistoryEvent>, Fail> {
    serde_json::from_value(v.get("events").cloned().unwrap_or(Value::Null))
        .map_err(|e| Fail::msg(format!("unexpected history shape: {e}")))
}

/// `Discovered` returns `{"discovered": [...]}`.
pub fn parse_discovered(v: &Value) -> Result<Vec<DiscoveredHost>, Fail> {
    serde_json::from_value(v.get("discovered").cloned().unwrap_or(Value::Null))
        .map_err(|e| Fail::msg(format!("unexpected discovered shape: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    #[test]
    fn history_and_discovered_shapes() {
        let ev = json!({"events":[{"ts_ms":1,"device":"a","kind":"up","message":"m"}]});
        let e = parse_events(&ev).unwrap();
        assert_eq!((e.len(), e[0].kind.as_str()), (1, "up"));
        assert!(parse_events(&json!({})).is_err());
        let d = json!({"discovered":[{"ip":"10.0.0.9","mac":null,"hostname":null,
            "network_name":null,"interface":null,"sources":["arp"],"ssh_port":"open",
            "fingerprints":[],"matched_device":null,"note":null,
            "first_seen_ms_ago":1,"last_seen_ms_ago":1}]});
        assert_eq!(parse_discovered(&d).unwrap()[0].ip, "10.0.0.9");
        assert_eq!(parse_version(&json!({"version":"0.1.0"})), "0.1.0");
        assert_eq!(parse_version(&json!({})), "?");
    }

    #[test]
    fn missing_socket_is_unavailable() {
        let c = Client::new("/nonexistent/lablink.sock");
        match poll_once(&c) {
            Event::Poll {
                status, version, ..
            } => {
                let f = status.unwrap_err();
                assert!(f.unavailable, "{}", f.message);
                assert!(version.is_none());
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn daemon_error_message_is_passed_through() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("d.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line).unwrap();
            assert!(line.contains("\"resolve\""), "{line}");
            (&s).write_all(
                b"{\"ok\":false,\"error\":{\"code\":\"identity_mismatch\",\"message\":\"host key changed\"}}\n",
            )
            .unwrap();
        });
        let err = run_remote(&Client::new(&sock), "jetson-a", "true").unwrap_err();
        t.join().unwrap();
        assert_eq!(err.message, "host key changed");
        assert!(!err.unavailable);
    }

    #[test]
    fn failed_test_ssh_requests_an_immediate_recheck() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("d.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            for cmd in ["resolve", "set"] {
                let (s, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(&s).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(req["method"], cmd, "{line}");
                let response = if cmd == "resolve" {
                    json!({"ok":false,"error":{"code":"identity_mismatch","message":"host key changed"}})
                } else {
                    assert_eq!(req["params"]["changes"]["recheck"], true, "{line}");
                    json!({"ok":true,"result":{}})
                };
                writeln!(&s, "{response}").unwrap();
            }
        });
        let Event::TestSsh(_, result) = execute(&sock, Cmd::TestSsh("lab/device".into())) else {
            panic!("wrong event");
        };
        assert_eq!(result.unwrap_err().message, "host key changed");
        t.join().unwrap();
    }

    #[test]
    fn stale_settings_cannot_overwrite_a_newer_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let orig = lablink_core::Config::default();
        let mut newer = orig.clone();
        newer.preferences.terminal = Some("xterm".into());
        lablink_setup::configfile::write(&path, &newer).unwrap();
        let mut edit = orig.clone();
        edit.preferences.terminal = Some("konsole".into());
        let event = execute(
            &dir.path().join("missing.sock"),
            Cmd::SaveConfig {
                cfg: Box::new(edit),
                expected: Box::new(orig),
                path: path.clone(),
            },
        );
        let Event::ConfigSaved(result) = event else {
            panic!("wrong event")
        };
        assert!(result.unwrap_err().contains("Reload Settings"));
        assert_eq!(lablink_core::Config::load(&path).unwrap(), newer);
    }

    #[test]
    fn daemon_build_display_warns_about_stale_or_unknown_release_builds() {
        let v = json!({"version":lablink_core::VERSION,"git_sha":"abcdef1234567890"});
        assert_eq!(
            parse_version(&v),
            format!("{} (abcdef123456)", lablink_core::VERSION)
        );
        assert!(daemon_build_warning(&v, Some("abcdef1234567890")).is_none());
        assert!(daemon_build_warning(&v, Some("old-client-sha")).is_some());
        assert!(daemon_build_warning(
            &json!({"version":lablink_core::VERSION}),
            Some("release-sha")
        )
        .is_some());
        assert!(daemon_build_warning(&json!({"version":lablink_core::VERSION}), None).is_none());
        assert!(daemon_build_warning(&json!({"version":"old-version"}), None).is_some());
    }
}
