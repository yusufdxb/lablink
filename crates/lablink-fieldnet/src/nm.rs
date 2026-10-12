//! The NetworkManager backend: one profile LabLink creates and owns
//! ("LabLink Field Network", autoconnect off), reused across starts.
//!
//! - Non-secret settings go on nmcli's command line. The password goes only
//!   through `nmcli connection edit` on stdin, whose stdout (it echoes its
//!   input) is discarded; NetworkManager keeps it in its root-only secret
//!   store. LabLink stores the profile's UUID, never the password.
//! - Mode `ap`, key management `wpa-psk` (RSN + CCMP, PMF off for client
//!   compatibility) or `sae` (PMF required). Never WEP, never open: the
//!   profile is read back and refused if it says otherwise.
//! - IPv4 `shared`: NetworkManager's own dnsmasq serves DHCP on the hotspot
//!   only; LabLink runs no DHCP server. IPv6 disabled.
//! - Activation is bounded (`--wait`), guarded by a NetworkManager
//!   checkpoint when this user may create one, and on failure the previous
//!   connection is restored.

use crate::host::{self, ActiveConnection, HostFacts};
use crate::preflight::Preflight;
use crate::state::{self, FieldState, Previous, Security};
use crate::system::{Cmd, System};
use crate::Error;
use ipnet::Ipv4Net;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

pub const PROFILE_NAME: &str = "LabLink Field Network";
const ACTIVATE_WAIT_S: u64 = 45;
const CHECKPOINT_ROLLBACK_S: u32 = 120;

fn nmcli(args: &[&str]) -> Cmd {
    Cmd::new("nmcli", args)
}

fn run_ok(sys: &dyn System, cmd: &Cmd) -> Result<String, Error> {
    match sys.run(cmd) {
        Ok(out) if out.ok() => Ok(out.stdout),
        Ok(out) => Err(Error::Failed(format!(
            "{} failed: {}",
            cmd.args
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            out.reason()
        ))),
        Err(e) => Err(Error::Failed(format!("cannot run {}: {e}", cmd.program))),
    }
}

/// Settings of the profile, as nmcli arguments (no secrets).
fn settings(
    iface: &str,
    ssid: &str,
    subnet: &Ipv4Net,
    security: Security,
    user: &str,
) -> Vec<String> {
    let gw = crate::subnet::gateway(subnet);
    let mut s: Vec<String> = vec![
        "connection.interface-name".into(),
        iface.into(),
        // Only this user can see, activate or edit the profile, and adding
        // it needs polkit settings.modify.own, not settings.modify.system.
        "connection.permissions".into(),
        format!("user:{user}"),
        "connection.autoconnect".into(),
        "no".into(),
        "802-11-wireless.ssid".into(),
        ssid.into(),
        "802-11-wireless.mode".into(),
        "ap".into(),
        // Clients must reach each other (robots, laptops, DDS discovery).
        "802-11-wireless.ap-isolation".into(),
        "0".into(),
        "802-11-wireless-security.key-mgmt".into(),
        security.key_mgmt().into(),
        "802-11-wireless-security.proto".into(),
        "rsn".into(),
        "802-11-wireless-security.pairwise".into(),
        "ccmp".into(),
        "802-11-wireless-security.group".into(),
        "ccmp".into(),
        "802-11-wireless-security.pmf".into(),
        match security {
            Security::Wpa2 => "1".into(), // disable: WPA2 clients that mishandle PMF still join
            Security::Wpa3 => "3".into(), // required by WPA3
        },
        "ipv4.method".into(),
        "shared".into(),
        "ipv4.addresses".into(),
        format!("{gw}/{}", subnet.prefix_len()),
        "ipv6.method".into(),
        "disabled".into(),
        // Stored by NetworkManager in its root-only keyfile, not an agent.
        "802-11-wireless-security.psk-flags".into(),
        "0".into(),
    ];
    s.shrink_to_fit();
    s
}

/// Set the password through the editor's stdin. Its stdout echoes every
/// line (the password included), so it is discarded.
fn set_password(sys: &dyn System, uuid: &str, psk: &str) -> Result<(), Error> {
    crate::password::validate_user(psk).map_err(Error::Refused)?;
    let mut cmd = nmcli(&["connection", "edit", "uuid", uuid]);
    cmd.stdin = Some(format!(
        "set 802-11-wireless-security.psk {psk}\nsave persistent\nquit\n"
    ));
    cmd.secret = Some(psk.to_string());
    cmd.discard_stdout = true;
    run_ok(sys, &cmd).map(|_| ())
}

/// The profile exists and is LabLink's (an access point).
fn profile_exists(sys: &dyn System, uuid: &str) -> bool {
    sys.run(&nmcli(&[
        "-t",
        "-f",
        "802-11-wireless.mode",
        "connection",
        "show",
        "uuid",
        uuid,
    ]))
    .is_ok_and(|o| o.ok() && o.stdout.trim().ends_with(":ap"))
}

/// Read the profile back and refuse anything but the secure configuration.
pub fn verify_profile(
    sys: &dyn System,
    uuid: &str,
    iface: &str,
    ssid: &str,
    subnet: &Ipv4Net,
    security: Security,
    user: &str,
) -> Result<(), Error> {
    let out = run_ok(
        sys,
        &nmcli(&[
            "-t",
            "-f",
            "connection.interface-name,connection.permissions,connection.autoconnect,802-11-wireless.ssid,802-11-wireless.mode,802-11-wireless-security.key-mgmt,802-11-wireless-security.proto,802-11-wireless-security.pairwise,802-11-wireless-security.group,ipv4.method,ipv4.addresses,802-11-wireless-security.psk-flags",
            "connection",
            "show",
            "uuid",
            uuid,
        ]),
    )?;
    let kv: std::collections::HashMap<String, String> = host::parse_kv(&out)
        .into_iter()
        .map(|(k, v)| (k, host::split_terse(&v).join(":")))
        .collect();
    let gw = crate::subnet::gateway(subnet);
    let want = [
        ("connection.interface-name", iface.to_string()),
        ("connection.permissions", format!("user:{user}")),
        ("connection.autoconnect", "no".into()),
        ("802-11-wireless.ssid", ssid.to_string()),
        ("802-11-wireless.mode", "ap".into()),
        (
            "802-11-wireless-security.key-mgmt",
            security.key_mgmt().into(),
        ),
        ("802-11-wireless-security.proto", "rsn".into()),
        ("802-11-wireless-security.pairwise", "ccmp".into()),
        ("802-11-wireless-security.group", "ccmp".into()),
        ("ipv4.method", "shared".into()),
        ("ipv4.addresses", format!("{gw}/{}", subnet.prefix_len())),
        ("802-11-wireless-security.psk-flags", "0".into()),
    ];
    let wrong: Vec<String> = want
        .iter()
        .filter(|(k, v)| kv.get(*k).map(String::as_str) != Some(v.as_str()))
        .map(|(k, v)| {
            format!(
                "{k} is '{}', expected '{v}'",
                kv.get(*k).cloned().unwrap_or_default()
            )
        })
        .collect();
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(Error::Failed(format!(
            "the hotspot profile is not configured securely, refusing to use it: {}",
            wrong.join("; ")
        )))
    }
}

/// Create LabLink's profile (or update the existing one) and return its
/// UUID. `psk`: a new password to store; `None` keeps the stored one.
#[allow(clippy::too_many_arguments)]
fn ensure_profile(
    sys: &dyn System,
    existing: Option<&str>,
    iface: &str,
    ssid: &str,
    subnet: &Ipv4Net,
    security: Security,
    psk: Option<&str>,
    user: &str,
) -> Result<(String, bool), Error> {
    let args = settings(iface, ssid, subnet, security, user);
    if let Some(uuid) = existing.filter(|u| profile_exists(sys, u)) {
        let mut cmd = nmcli(&["connection", "modify", "uuid", uuid]);
        cmd.args.extend(args);
        run_ok(sys, &cmd)?;
        if let Some(p) = psk {
            set_password(sys, uuid, p)?;
        }
        return Ok((uuid.to_string(), false));
    }
    let Some(psk) = psk else {
        return Err(Error::Failed(
            "no password for a new hotspot profile".into(),
        ));
    };
    let mut cmd = nmcli(&[
        "connection",
        "add",
        "save",
        "yes",
        "type",
        "wifi",
        "con-name",
        PROFILE_NAME,
    ]);
    cmd.args.extend(args);
    let out = run_ok(sys, &cmd)?;
    let uuid = parse_added_uuid(&out).ok_or_else(|| {
        Error::Failed(format!(
            "cannot read the new profile's UUID from: {}",
            out.trim()
        ))
    })?;
    if let Err(e) = set_password(sys, &uuid, psk) {
        // Never leave a profile without its password behind.
        let _ = sys.run(&nmcli(&["connection", "delete", "uuid", &uuid]));
        return Err(e);
    }
    Ok((uuid, true))
}

/// "Connection 'X' (UUID) successfully added."
pub fn parse_added_uuid(text: &str) -> Option<String> {
    let start = text.rfind('(')? + 1;
    let end = start + text[start..].find(')')?;
    let u = &text[start..end];
    (u.len() == 36 && u.chars().all(|c| c.is_ascii_hexdigit() || c == '-')).then(|| u.to_string())
}

/// NetworkManager checkpoint: if activation fails or LabLink dies before
/// committing, NetworkManager itself rolls the device back after
/// `CHECKPOINT_ROLLBACK_S`. Only when polkit allows it without a prompt.
struct Checkpoint(String);

fn busctl(method: &str, sig: &str, args: &[&str]) -> Cmd {
    let mut c = Cmd::new(
        "busctl",
        &[
            "--system",
            "--allow-interactive-authorization=no",
            "call",
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            method,
            sig,
        ],
    );
    c.args.extend(args.iter().map(|a| a.to_string()));
    c
}

/// `o "/org/freedesktop/NetworkManager/Devices/3"` -> the path.
pub fn parse_object_path(text: &str) -> Option<String> {
    let t = text.trim().strip_prefix("o ")?.trim_matches('"');
    (t.starts_with("/org/freedesktop/NetworkManager/")
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '_'))
    .then(|| t.to_string())
}

impl Checkpoint {
    fn create(sys: &dyn System, facts: &HostFacts, iface: &str) -> Result<Checkpoint, String> {
        if !facts
            .nm
            .as_ref()
            .is_some_and(|n| n.allowed("checkpoint-rollback"))
        {
            return Err("not permitted without administrator authorization".into());
        }
        let dev = sys
            .run(&busctl("GetDeviceByIpIface", "s", &[iface]))
            .ok()
            .filter(|o| o.ok())
            .and_then(|o| parse_object_path(&o.stdout))
            .ok_or("cannot find the device on D-Bus")?;
        let timeout = CHECKPOINT_ROLLBACK_S.to_string();
        sys.run(&busctl(
            "CheckpointCreate",
            "aouu",
            &["1", &dev, &timeout, "0"],
        ))
        .ok()
        .filter(|o| o.ok())
        .and_then(|o| parse_object_path(&o.stdout))
        .map(Checkpoint)
        .ok_or_else(|| "NetworkManager refused to create a checkpoint".into())
    }

    fn rollback(self, sys: &dyn System) -> bool {
        sys.run(&busctl("CheckpointRollback", "o", &[&self.0]))
            .is_ok_and(|o| o.ok())
    }

    fn commit(self, sys: &dyn System) {
        let _ = sys.run(&busctl("CheckpointDestroy", "o", &[&self.0]));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StartReport {
    pub ssid: String,
    pub interface: String,
    pub subnet: String,
    pub gateway: Ipv4Addr,
    pub security: &'static str,
    pub profile_uuid: String,
    pub profile_created: bool,
    pub previous: Option<Previous>,
    pub checkpoint: String,
    pub ip_forward_before: Option<bool>,
    pub ip_forward_after: Option<bool>,
    pub already_running: bool,
}

/// What `start` needs beyond the preflight.
pub struct StartOptions<'a> {
    /// A password to store (user-supplied, or freshly generated by the
    /// caller). `None`: keep the stored one, or generate one for a new
    /// profile.
    pub psk: Option<&'a str>,
    /// The user accepted the preflight warnings.
    pub confirmed: bool,
}

/// Start (or update and re-apply) the Field Network.
pub fn start(
    sys: &dyn System,
    state_dir: &Path,
    facts: &HostFacts,
    pf: &Preflight,
    opts: &StartOptions,
) -> Result<StartReport, Error> {
    if pf.blocked() {
        return Err(Error::Refused(format!(
            "preflight refused: {}",
            pf.blockers()
                .iter()
                .map(|b| match b.override_flag {
                    Some(flag) => format!("{} (accept with {flag})", b.message),
                    None => b.message.clone(),
                })
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    if pf.needs_confirmation() && !opts.confirmed {
        return Err(Error::Refused(
            "the preflight has warnings; review them (`lablink hotspot preflight`) and confirm, or pass --yes".into(),
        ));
    }
    let (Some(iface), Some(subnet), Some(gateway)) = (pf.interface.clone(), pf.subnet, pf.gateway)
    else {
        return Err(Error::Failed(
            "preflight produced no interface or subnet".into(),
        ));
    };
    let user = sys.username().ok_or_else(|| {
        Error::Refused(
            "cannot read this user's login name from the password database (or it has unusual characters), so the hotspot profile cannot be restricted to this user".into(),
        )
    })?;
    let old = state::load(state_dir).map_err(Error::Failed)?;
    let existing = old.as_ref().and_then(|s| s.profile_uuid.clone());
    let generated;
    let psk = match (
        opts.psk,
        existing.as_deref().filter(|u| profile_exists(sys, u)),
    ) {
        (Some(p), _) => Some(p),
        (None, Some(_)) => None,
        (None, None) => {
            generated = crate::password::generate(sys).map_err(|e| Error::Failed(e.to_string()))?;
            Some(generated.as_str())
        }
    };
    let (uuid, created) = ensure_profile(
        sys,
        existing.as_deref(),
        &iface,
        &pf.ssid,
        &subnet,
        pf.security,
        psk,
        &user,
    )?;
    verify_profile(sys, &uuid, &iface, &pf.ssid, &subnet, pf.security, &user)?;

    // Remember how to undo this before touching the adapter.
    let previous = pf
        .would_disconnect
        .as_ref()
        .map(|c: &ActiveConnection| Previous {
            uuid: c.uuid.clone(),
            name: c.name.clone(),
            device: c.device.clone(),
        })
        .or_else(|| {
            old.as_ref()
                .and_then(|s| s.previous.clone())
                .filter(|_| pf.already_running)
        });
    let mut st = FieldState {
        version: 1,
        profile_uuid: Some(uuid.clone()),
        interface: iface.clone(),
        ssid: pf.ssid.clone(),
        subnet: subnet.to_string(),
        security: pf.security,
        previous: previous.clone(),
        active: pf.already_running,
        started_ms: old
            .as_ref()
            .and_then(|s| s.started_ms)
            .filter(|_| pf.already_running),
        ip_forward_before: if pf.already_running {
            old.as_ref().and_then(|s| s.ip_forward_before)
        } else {
            facts.ip_forward
        },
    };
    state::save(state_dir, &st).map_err(Error::Failed)?;

    let checkpoint = Checkpoint::create(sys, facts, &iface);
    let checkpoint_note = match &checkpoint {
        Ok(_) => "created; NetworkManager rolls back by itself if activation does not complete"
            .to_string(),
        Err(why) => {
            format!("unavailable ({why}); LabLink restores the previous connection on failure")
        }
    };
    let up = run_ok(
        sys,
        &nmcli(&[
            "--wait",
            &ACTIVATE_WAIT_S.to_string(),
            "connection",
            "up",
            "uuid",
            &uuid,
            "ifname",
            &iface,
        ])
        .timeout(Duration::from_secs(ACTIVATE_WAIT_S + 15)),
    )
    .and_then(|_| verify_active(sys, &uuid, &iface, gateway));
    if let Err(e) = up {
        let rolled_back = checkpoint.is_ok_and(|cp| cp.rollback(sys));
        let undo = if rolled_back {
            "NetworkManager rolled the adapter back".to_string()
        } else {
            restore_previous(sys, previous.as_ref())
        };
        st.active = false;
        let _ = state::save(state_dir, &st);
        return Err(Error::Failed(format!("{e}. {undo}")));
    }
    if let Ok(cp) = checkpoint {
        cp.commit(sys);
    }
    st.active = true;
    st.started_ms.get_or_insert_with(state::now_ms);
    state::save(state_dir, &st).map_err(Error::Failed)?;
    Ok(StartReport {
        ssid: pf.ssid.clone(),
        interface: iface,
        subnet: subnet.to_string(),
        gateway,
        security: pf.security.label(),
        profile_uuid: uuid,
        profile_created: created,
        previous,
        checkpoint: checkpoint_note,
        ip_forward_before: st.ip_forward_before,
        ip_forward_after: sys
            .read_file(Path::new("/proc/sys/net/ipv4/ip_forward"))
            .map(|t| t.trim() == "1"),
        already_running: pf.already_running,
    })
}

/// The profile is active on the adapter and the gateway address is up.
fn verify_active(
    sys: &dyn System,
    uuid: &str,
    iface: &str,
    gateway: Ipv4Addr,
) -> Result<(), Error> {
    let active = run_ok(
        sys,
        &nmcli(&[
            "-t",
            "-f",
            "NAME,UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ]),
    )?;
    if !host::parse_active(&active)
        .iter()
        .any(|a| a.uuid == uuid && a.device == iface)
    {
        return Err(Error::Failed("the hotspot did not become active".into()));
    }
    let addrs = run_ok(
        sys,
        &Cmd::new("ip", &["-4", "-o", "addr", "show", "dev", iface]),
    )?;
    if !host::parse_addresses(&addrs)
        .iter()
        .any(|a| a.net.addr() == gateway)
    {
        return Err(Error::Failed(format!(
            "{iface} did not get the gateway address {gateway}"
        )));
    }
    Ok(())
}

fn restore_previous(sys: &dyn System, previous: Option<&Previous>) -> String {
    let Some(p) = previous else {
        return "There was no previous connection to restore.".into();
    };
    match run_ok(
        sys,
        &nmcli(&[
            "--wait",
            &ACTIVATE_WAIT_S.to_string(),
            "connection",
            "up",
            "uuid",
            &p.uuid,
        ])
        .timeout(Duration::from_secs(ACTIVATE_WAIT_S + 15)),
    ) {
        Ok(_) => format!("Reconnected '{}'.", p.name),
        Err(e) => format!(
            "Could not reconnect '{}' ({e}); reconnect it from your network settings.",
            p.name
        ),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StopReport {
    pub was_active: bool,
    pub restored: Option<String>,
}

/// Stop the hotspot and reconnect the previous connection. The profile
/// (and its password) stays for the next start; `forget` removes it.
pub fn stop(sys: &dyn System, state_dir: &Path, restore: bool) -> Result<StopReport, Error> {
    let Some(mut st) = state::load(state_dir).map_err(Error::Failed)? else {
        return Err(Error::NotFound("no Field Network has been set up".into()));
    };
    let Some(uuid) = st.profile_uuid.clone() else {
        return Err(Error::NotFound("no Field Network profile".into()));
    };
    let was_active = is_active(sys, &uuid)?;
    if was_active {
        refuse_cutting_sessions(sys, &st.interface, "stopping")?;
        run_ok(
            sys,
            &nmcli(&["--wait", "20", "connection", "down", "uuid", &uuid])
                .timeout(Duration::from_secs(35)),
        )?;
    }
    st.active = false;
    st.started_ms = None;
    state::save(state_dir, &st).map_err(Error::Failed)?;
    let restored = match (&st.previous, restore, was_active) {
        (Some(p), true, true) => Some(restore_previous(sys, Some(p))),
        _ => None,
    };
    Ok(StopReport {
        was_active,
        restored,
    })
}

/// Stopping or restarting the hotspot drops everything on its adapter. An
/// SSH session that rides on it (or might) is refused the same way start
/// refuses it: the operator would be cut off with no way back.
fn refuse_cutting_sessions(sys: &dyn System, iface: &str, action: &str) -> Result<(), Error> {
    let at_risk = host::gather(sys).sessions_at_risk(iface);
    if at_risk.is_empty() {
        return Ok(());
    }
    Err(Error::Refused(format!(
        "{action} the Field Network would cut {iface}, and {}. Run this at the machine itself.",
        at_risk.join("; ")
    )))
}

pub fn is_active(sys: &dyn System, uuid: &str) -> Result<bool, Error> {
    let out = run_ok(
        sys,
        &nmcli(&[
            "-t",
            "-f",
            "NAME,UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ]),
    )?;
    Ok(host::parse_active(&out).iter().any(|a| a.uuid == uuid))
}

/// Re-apply the profile to a running hotspot (after a password change).
pub fn restart(sys: &dyn System, state_dir: &Path) -> Result<(), Error> {
    let st = state::load(state_dir)
        .map_err(Error::Failed)?
        .ok_or_else(|| Error::NotFound("no Field Network has been set up".into()))?;
    let uuid = st
        .profile_uuid
        .ok_or_else(|| Error::NotFound("no Field Network profile".into()))?;
    if !is_active(sys, &uuid)? {
        return Err(Error::Refused(
            "the Field Network is not running; use `lablink hotspot start`".into(),
        ));
    }
    refuse_cutting_sessions(sys, &st.interface, "restarting")?;
    run_ok(
        sys,
        &nmcli(&[
            "--wait",
            &ACTIVATE_WAIT_S.to_string(),
            "connection",
            "up",
            "uuid",
            &uuid,
            "ifname",
            &st.interface,
        ])
        .timeout(Duration::from_secs(ACTIVATE_WAIT_S + 15)),
    )
    .map(|_| ())
}

/// The stored password, read from NetworkManager (never from LabLink's
/// files). Only for an explicit `lablink hotspot password`.
pub fn password(sys: &dyn System, state_dir: &Path) -> Result<String, Error> {
    let uuid = state::load(state_dir)
        .map_err(Error::Failed)?
        .and_then(|s| s.profile_uuid)
        .ok_or_else(|| Error::NotFound("no Field Network has been set up".into()))?;
    let out = run_ok(
        sys,
        &nmcli(&[
            "-s",
            "-g",
            "802-11-wireless-security.psk",
            "connection",
            "show",
            "uuid",
            &uuid,
        ]),
    )?;
    // `-g` escapes colons and backslashes like terse output.
    let psk = host::split_terse(out.trim_end_matches('\n')).join(":");
    if psk.is_empty() {
        return Err(Error::Failed(
            "NetworkManager did not return the password (reading secrets may need administrator authorization)".into(),
        ));
    }
    Ok(psk)
}

/// Store a new password. Takes effect at the next start or restart.
pub fn set_new_password(sys: &dyn System, state_dir: &Path, psk: &str) -> Result<(), Error> {
    let uuid = state::load(state_dir)
        .map_err(Error::Failed)?
        .and_then(|s| s.profile_uuid)
        .filter(|u| profile_exists(sys, u))
        .ok_or_else(|| Error::NotFound("no Field Network profile; start it once first".into()))?;
    set_password(sys, &uuid, psk)
}

/// Delete LabLink's profile and state. Refused while running.
pub fn forget(sys: &dyn System, state_dir: &Path) -> Result<bool, Error> {
    let Some(st) = state::load(state_dir).map_err(Error::Failed)? else {
        return Ok(false);
    };
    if let Some(uuid) = &st.profile_uuid {
        if is_active(sys, uuid)? {
            return Err(Error::Refused(
                "stop the Field Network first (`lablink hotspot stop`)".into(),
            ));
        }
        if profile_exists(sys, uuid) {
            run_ok(sys, &nmcli(&["connection", "delete", "uuid", uuid]))?;
        }
    }
    state::remove(state_dir).map_err(Error::Failed)?;
    Ok(true)
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub configured: bool,
    /// NetworkManager says the profile is active (the truth).
    pub active: bool,
    /// LabLink's record disagrees with NetworkManager (stopped elsewhere,
    /// started outside LabLink, or a start interrupted before it was
    /// recorded).
    pub out_of_sync: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<FieldState>,
    pub gateway: Option<Ipv4Addr>,
    pub security: Option<&'static str>,
    pub ip_forward: Option<bool>,
    /// While it runs: other devices holding a default route. Shared mode
    /// NATs hotspot clients onto them, so an uplink that appeared after the
    /// start (a USB tether, a cable) shares this machine's internet.
    pub uplinks: Vec<String>,
    /// While it runs: other networks this machine routes to ("dest
    /// (device)"), which forwarding lets hotspot clients reach; a VPN or
    /// cable that came up after the start shows here.
    pub routed: Vec<String>,
    pub clients: Vec<crate::clients::Client>,
}

pub fn status(sys: &dyn System, state_dir: &Path) -> Result<Status, Error> {
    let st = state::load(state_dir).map_err(Error::Failed)?;
    let mut s = Status {
        configured: st.as_ref().is_some_and(|s| s.profile_uuid.is_some()),
        active: false,
        out_of_sync: false,
        state: st.clone(),
        gateway: None,
        security: st.as_ref().map(|s| s.security.label()),
        ip_forward: sys
            .read_file(Path::new("/proc/sys/net/ipv4/ip_forward"))
            .map(|t| t.trim() == "1"),
        uplinks: Vec::new(),
        routed: Vec::new(),
        clients: Vec::new(),
    };
    let Some(st) = st else { return Ok(s) };
    if let Some(uuid) = &st.profile_uuid {
        s.active = is_active(sys, uuid)?;
    }
    s.out_of_sync = s.active != st.active;
    if let Ok(net) = st.subnet.parse::<Ipv4Net>() {
        s.gateway = Some(crate::subnet::gateway(&net));
        if s.active {
            s.clients = crate::clients::list(sys, &st.interface, &net);
        }
    }
    if s.active {
        if let Ok(out) = sys.run(&Cmd::new(
            "ip",
            &["-4", "-o", "route", "show", "table", "all"],
        )) {
            let routes = host::parse_routes(&out.stdout);
            let mut devs: Vec<String> = routes
                .iter()
                .filter(|r| r.is_default() && r.table == "main" && r.device != st.interface)
                .map(|r| r.device.clone())
                .collect();
            devs.dedup();
            s.uplinks = devs;
            s.routed = host::routed_elsewhere(&routes, &st.interface);
        }
    }
    Ok(s)
}
