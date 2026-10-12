//! [unit, simulated] The NetworkManager backend end to end against a
//! scripted system: what is run, in which order, with which arguments, and
//! where the password goes. No radio, root or NetworkManager involved.

use crate::host::{gather, script_host};
use crate::preflight::{self, Context, Request};
use crate::state::{self, Security};
use crate::system::{FakeSystem, Output};
use crate::{nm, Error};

const UUID: &str = "114930b6-edee-418c-bac6-3400a8517a6c";
const HOME: &str = "a21bc2fd-4952-487d-91c0-a3248f648037";

fn req() -> Request {
    Request {
        interface: None,
        ssid: "LabLink-TEST".into(),
        subnet: None,
        security: Security::Wpa2,
        allow_internet_sharing: false,
        allow_routing: true,
    }
}

fn profile_show(ssid: &str, key_mgmt: &str) -> String {
    format!(
        "connection.interface-name:wlan0\nconnection.permissions:user:tester\nconnection.autoconnect:no\n802-11-wireless.ssid:{ssid}\n802-11-wireless.mode:ap\n802-11-wireless-security.key-mgmt:{key_mgmt}\n802-11-wireless-security.proto:rsn\n802-11-wireless-security.pairwise:ccmp\n802-11-wireless-security.group:ccmp\nipv4.method:shared\nipv4.addresses:10.77.0.1/24\n802-11-wireless-security.psk-flags:0\n"
    )
}

/// A host where creating and activating the hotspot works.
fn working_host() -> FakeSystem {
    let f = FakeSystem::new();
    script_host(&f);
    f.ok(
        "nmcli connection add save yes type wifi con-name LabLink Field Network",
        &format!("Connection 'LabLink Field Network' ({UUID}) successfully added.\n"),
    );
    // The editor echoes its input, password included.
    f.ok(
        &format!("nmcli connection edit uuid {UUID}"),
        "nmcli> set 802-11-wireless-security.psk ECHOED\nnmcli> save persistent\n",
    );
    f.ok(
        "nmcli -t -f connection.interface-name",
        &profile_show("LabLink-TEST", "wpa-psk"),
    );
    f.ok(
        &format!("nmcli --wait 45 connection up uuid {UUID} ifname wlan0"),
        "Connection successfully activated\n",
    );
    f.ok(
        "ip -4 -o addr show dev wlan0",
        "3: wlan0    inet 10.77.0.1/24 brd 10.77.0.255 scope global noprefixroute wlan0\n",
    );
    f
}

fn hotspot_active(f: &FakeSystem) {
    f.ok(
        "nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active",
        &format!("LabLink Field Network:{UUID}:802-11-wireless:wlan0\n"),
    );
}

#[test]
fn start_creates_a_wpa2_profile_with_the_password_only_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    let psk = "Correct-Horse_42!";
    let r = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some(psk),
            confirmed: true,
        },
    )
    .unwrap();
    assert_eq!(r.profile_uuid, UUID);
    assert!(r.profile_created);
    assert_eq!(r.gateway.to_string(), "10.77.0.1");
    assert_eq!(r.previous.as_ref().unwrap().uuid, HOME);
    assert!(
        r.checkpoint.contains("unavailable"),
        "polkit says auth: no checkpoint"
    );

    let calls = f.calls();
    for c in &calls {
        assert!(
            !c.line().contains(psk),
            "password on a command line: {}",
            c.line()
        );
    }
    let add = calls
        .iter()
        .find(|c| c.line().contains("connection add"))
        .unwrap();
    let line = add.line();
    for want in [
        "802-11-wireless.mode ap",
        "802-11-wireless-security.key-mgmt wpa-psk",
        "802-11-wireless-security.proto rsn",
        "802-11-wireless-security.pairwise ccmp",
        "802-11-wireless-security.group ccmp",
        "802-11-wireless.ap-isolation 0",
        "ipv4.method shared",
        "ipv4.addresses 10.77.0.1/24",
        "ipv6.method disabled",
        "connection.autoconnect no",
        "connection.permissions user:tester",
        "802-11-wireless-security.psk-flags 0",
    ] {
        assert!(line.contains(want), "{want} missing from {line}");
    }
    let edit = calls
        .iter()
        .find(|c| c.line().contains("connection edit"))
        .unwrap();
    assert!(edit.discard_stdout, "the editor echoes the password");
    assert_eq!(
        edit.stdin.as_deref(),
        Some(format!("set 802-11-wireless-security.psk {psk}\nsave persistent\nquit\n").as_str())
    );
    // Order: create, password, verify, activate.
    let pos = |s: &str| calls.iter().position(|c| c.line().contains(s)).unwrap();
    assert!(pos("connection add") < pos("connection edit"));
    assert!(pos("connection edit") < pos("-f connection.interface-name"));
    assert!(pos("-f connection.interface-name") < pos("connection up"));
    assert!(
        !f.lines().iter().any(|l| l.starts_with("busctl")),
        "no checkpoint attempt without permission"
    );

    let st = state::load(dir.path()).unwrap().unwrap();
    assert!(st.active);
    let text = std::fs::read_to_string(state::path(dir.path())).unwrap();
    assert!(!text.contains(psk) && !text.contains("ECHOED"));
}

#[test]
fn a_generated_password_is_used_when_none_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: None,
            confirmed: true,
        },
    )
    .unwrap();
    let edit = f
        .calls()
        .into_iter()
        .find(|c| c.line().contains("connection edit"))
        .unwrap();
    let stdin = edit.stdin.unwrap();
    let psk = stdin
        .lines()
        .next()
        .unwrap()
        .strip_prefix("set 802-11-wireless-security.psk ")
        .unwrap();
    assert!(crate::password::validate_user(psk).is_ok());
    assert_eq!(psk.len(), 29);
}

#[test]
fn blocked_or_unconfirmed_preflight_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    f.set_env("SSH_CONNECTION", "192.168.8.20 51000 192.168.8.168 22");
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let before = f.calls().len();
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: None,
            confirmed: true,
        },
    )
    .unwrap_err();
    assert!(
        matches!(&e, Error::Refused(m) if m.contains("SSH")),
        "{e:?}"
    );
    assert_eq!(f.calls().len(), before, "nothing run");

    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let before = f.calls().len();
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: None,
            confirmed: false,
        },
    )
    .unwrap_err();
    assert!(matches!(e, Error::Refused(m) if m.contains("--yes")));
    assert_eq!(f.calls().len(), before);
    assert_eq!(state::load(dir.path()).unwrap(), None);
}

#[test]
fn failed_activation_restores_the_previous_connection() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    f.on(
        &format!("nmcli --wait 45 connection up uuid {UUID}"),
        Output::failure(
            4,
            "Error: Connection activation failed: No suitable device found",
        ),
    );
    f.ok(
        &format!("nmcli --wait 45 connection up uuid {HOME}"),
        "Connection successfully activated\n",
    );
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap_err();
    let Error::Failed(m) = e else { panic!() };
    assert!(
        m.contains("No suitable device") && m.contains("Reconnected 'Home WiFi'"),
        "{m}"
    );
    assert!(f
        .lines()
        .iter()
        .any(|l| l.contains(&format!("connection up uuid {HOME}"))));
    assert!(!state::load(dir.path()).unwrap().unwrap().active);
}

#[test]
fn checkpoint_guards_activation_when_permitted() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    f.ok(
        "nmcli -t general permissions",
        "org.freedesktop.NetworkManager.checkpoint-rollback:yes\norg.freedesktop.NetworkManager.network-control:yes\norg.freedesktop.NetworkManager.settings.modify.own:yes\norg.freedesktop.NetworkManager.settings.modify.system:yes\n",
    );
    f.ok("busctl --system --allow-interactive-authorization=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager GetDeviceByIpIface s wlan0", "o \"/org/freedesktop/NetworkManager/Devices/3\"\n");
    f.ok("busctl --system --allow-interactive-authorization=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager CheckpointCreate aouu 1 /org/freedesktop/NetworkManager/Devices/3 120 0", "o \"/org/freedesktop/NetworkManager/Checkpoint/7\"\n");
    f.ok("busctl --system --allow-interactive-authorization=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager CheckpointRollback o /org/freedesktop/NetworkManager/Checkpoint/7", "a{su} 1 \"/org/freedesktop/NetworkManager/Devices/3\" 0\n");
    f.ok("busctl --system --allow-interactive-authorization=no call org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager CheckpointDestroy", "");
    f.on(
        &format!("nmcli --wait 45 connection up uuid {UUID}"),
        Output::failure(4, "Error: activation failed"),
    );
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap_err();
    assert!(
        e.to_string()
            .contains("NetworkManager rolled the adapter back"),
        "{e}"
    );
    assert!(f.lines().iter().any(|l| l.contains("CheckpointRollback")));
    assert!(
        !f.lines()
            .iter()
            .any(|l| l.contains(&format!("connection up uuid {HOME}"))),
        "the checkpoint restores, not LabLink"
    );

    // Success commits (destroys) the checkpoint.
    let dir = tempfile::tempdir().unwrap();
    f.ok(
        &format!("nmcli --wait 45 connection up uuid {UUID}"),
        "ok\n",
    );
    hotspot_active(&f);
    let r = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap();
    assert!(r.checkpoint.starts_with("created"));
    assert!(f.lines().iter().any(|l| l.contains("CheckpointDestroy")));
}

#[test]
fn an_insecure_profile_is_refused_and_never_activated() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    f.ok(
        "nmcli -t -f connection.interface-name",
        &profile_show("LabLink-TEST", "none"),
    );
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap_err();
    assert!(e.to_string().contains("not configured securely"), "{e}");
    assert!(!f.lines().iter().any(|l| l.contains("connection up")));
}

#[test]
fn a_profile_visible_to_other_users_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    for perms in ["", "user:tester,user:mallory", "user:mallory"] {
        f.ok(
            "nmcli -t -f connection.interface-name",
            &profile_show("LabLink-TEST", "wpa-psk").replace(
                "connection.permissions:user:tester",
                &format!("connection.permissions:{perms}"),
            ),
        );
        let facts = gather(&f);
        let pf = preflight::check(
            &facts,
            &req(),
            &Context {
                sites: &[],
                equipment: &[],
                own_profile: None,
            },
        );
        let e = nm::start(
            &f,
            dir.path(),
            &facts,
            &pf,
            &nm::StartOptions {
                psk: Some("Correct-Horse_42!"),
                confirmed: true,
            },
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("connection.permissions"),
            "{perms}: {e}"
        );
    }
    assert!(!f.lines().iter().any(|l| l.contains("connection up")));
}

#[test]
fn without_a_plain_login_name_nothing_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let mut f = working_host();
    f.user = None;
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap_err();
    assert!(e.to_string().contains("login name"), "{e}");
    assert!(
        !f.lines()
            .iter()
            .any(|l| l.contains("connection add") || l.contains("connection modify")),
        "{:?}",
        f.lines()
    );
}

#[test]
fn a_failed_password_step_deletes_the_new_profile() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    f.on(
        &format!("nmcli connection edit uuid {UUID}"),
        Output::failure(1, "Error: failed to save: Correct-Horse_42! rejected"),
    );
    f.ok(&format!("nmcli connection delete uuid {UUID}"), "deleted\n");
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    let e = nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap_err();
    assert!(
        !e.to_string().contains("Correct-Horse_42!"),
        "stderr is scrubbed: {e}"
    );
    assert!(f.lines().iter().any(|l| l.contains("connection delete")));
}

#[test]
fn restart_reuses_the_profile_and_keeps_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap();
    // Stop: down, then the home network comes back.
    f.ok(
        &format!("nmcli --wait 20 connection down uuid {UUID}"),
        "deactivated\n",
    );
    f.ok(
        &format!("nmcli --wait 45 connection up uuid {HOME}"),
        "activated\n",
    );
    // Over SSH through the hotspot's adapter, stop and restart are refused
    // and nothing is taken down.
    f.set_env("SSH_CONNECTION", "192.168.8.20 51000 192.168.8.168 22");
    let n = f.lines().len();
    for r in [
        nm::stop(&f, dir.path(), true).map(|_| ()),
        nm::restart(&f, dir.path()),
    ] {
        match r {
            Err(e @ crate::Error::Refused(_)) => {
                assert!(e.to_string().contains("over SSH through wlan0"))
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(
        !f.lines()[n..]
            .iter()
            .any(|c| c.contains("connection down") || c.contains("connection up")),
        "{:?}",
        &f.lines()[n..]
    );
    f.clear_env("SSH_CONNECTION");
    let s = nm::stop(&f, dir.path(), true).unwrap();
    assert!(s.was_active);
    assert_eq!(s.restored.as_deref(), Some("Reconnected 'Home WiFi'."));
    // Start again: the profile is modified, not recreated, no new password.
    f.ok(
        &format!("nmcli -t -f 802-11-wireless.mode connection show uuid {UUID}"),
        "802-11-wireless.mode:ap\n",
    );
    f.ok(&format!("nmcli connection modify uuid {UUID}"), "");
    let n = f.calls().len();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: Some(UUID),
        },
    );
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: None,
            confirmed: true,
        },
    )
    .unwrap();
    let later: Vec<String> = f.lines()[n..].to_vec();
    assert!(later.iter().any(|l| l.contains("connection modify")));
    assert!(
        !later
            .iter()
            .any(|l| l.contains("connection add") || l.contains("connection edit")),
        "{later:#?}"
    );
}

#[test]
fn password_is_read_from_networkmanager_and_unescaped() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap();
    f.ok(
        &format!("nmcli -s -g 802-11-wireless-security.psk connection show uuid {UUID}"),
        "a\\:b\\\\c-1234567890\n",
    );
    assert_eq!(nm::password(&f, dir.path()).unwrap(), "a:b\\c-1234567890");
}

#[test]
fn forget_is_refused_while_running_and_deletes_after() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap();
    assert!(matches!(nm::forget(&f, dir.path()), Err(Error::Refused(_))));
    f.ok(
        "nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active",
        &format!("Home WiFi:{HOME}:802-11-wireless:wlan0\n"),
    );
    f.ok(
        &format!("nmcli -t -f 802-11-wireless.mode connection show uuid {UUID}"),
        "802-11-wireless.mode:ap\n",
    );
    f.ok(&format!("nmcli connection delete uuid {UUID}"), "deleted\n");
    assert!(nm::forget(&f, dir.path()).unwrap());
    assert_eq!(state::load(dir.path()).unwrap(), None);
}

#[test]
fn status_reports_out_of_sync_when_stopped_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    let f = working_host();
    let facts = gather(&f);
    let pf = preflight::check(
        &facts,
        &req(),
        &Context {
            sites: &[],
            equipment: &[],
            own_profile: None,
        },
    );
    hotspot_active(&f);
    nm::start(
        &f,
        dir.path(),
        &facts,
        &pf,
        &nm::StartOptions {
            psk: Some("Correct-Horse_42!"),
            confirmed: true,
        },
    )
    .unwrap();
    f.ok(
        "ip -4 neigh show dev wlan0",
        "10.77.0.23 lladdr 02:00:00:00:a0:31 REACHABLE\n",
    );
    let s = nm::status(&f, dir.path()).unwrap();
    assert!(s.active && !s.out_of_sync);
    assert_eq!(s.clients.len(), 1);
    let json = serde_json::to_string(&s).unwrap();
    assert!(!json.contains("Correct-Horse"));
    assert!(s.uplinks.is_empty(), "{:?}", s.uplinks);
    // A cable is plugged in while it runs: shared mode NATs clients onto
    // it, and status says so.
    f.ok(
        "ip -4 -o route show table all",
        "default via 10.1.1.254 dev eno1 proto dhcp metric 100\n10.77.0.0/24 dev wlan0 proto kernel scope link src 10.77.0.1\n",
    );
    let s = nm::status(&f, dir.path()).unwrap();
    assert_eq!(s.uplinks, vec!["eno1"]);
    assert!(
        s.routed.is_empty(),
        "the hotspot's own subnet is not elsewhere: {:?}",
        s.routed
    );
    // A VPN comes up while it runs, routes only (no default), in its own
    // table: forwarding reaches it too, and status says so.
    f.ok(
        "ip -4 -o route show table all",
        "100.64.0.0/10 dev tailscale0 table 52\n10.77.0.0/24 dev wlan0 proto kernel scope link src 10.77.0.1\nlocal 10.77.0.1 dev wlan0 table local proto kernel scope host src 10.77.0.1\n",
    );
    let s = nm::status(&f, dir.path()).unwrap();
    assert!(s.uplinks.is_empty());
    assert_eq!(s.routed, vec!["100.64.0.0/10 (tailscale0)"]);
    // Someone stopped it from the desktop's network menu.
    f.ok(
        "nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active",
        "",
    );
    let s = nm::status(&f, dir.path()).unwrap();
    assert!(!s.active && s.out_of_sync && s.clients.is_empty());
}

#[test]
fn field_site_is_added_once_and_updated_in_place() {
    let mut cfg = lablink_core::Config::default();
    let net: ipnet::Ipv4Net = "10.77.0.0/24".parse().unwrap();
    assert!(crate::field_site(&mut cfg, &net, Some("wlan0"), Some("LabLink-TEST")).unwrap());
    assert!(!crate::field_site(&mut cfg, &net, Some("wlan0"), Some("LabLink-TEST")).unwrap());
    let s = cfg
        .sites
        .iter()
        .find(|s| s.id == crate::FIELD_SITE_ID)
        .unwrap();
    assert!(s.roaming);
    assert_eq!(s.networks[0].gateway.as_deref(), Some("10.77.0.1"));
    assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
    let net2: ipnet::Ipv4Net = "10.77.1.0/24".parse().unwrap();
    assert!(crate::field_site(&mut cfg, &net2, Some("wlan0"), None).unwrap());
    assert_eq!(cfg.sites.iter().filter(|s| s.roaming).count(), 1);

    let mut cfg = lablink_core::Config::default();
    cfg.sites.push(lablink_core::config::SiteConfig::new(
        "field-network",
        "Mine",
    ));
    assert!(crate::field_site(&mut cfg, &net, None, None).is_err());
}

#[test]
fn macos_capabilities_are_guided_not_claimed() {
    let mut f = FakeSystem::new();
    f.os_family = Some(crate::system::Os::Macos);
    f.ok(
        "networksetup -listallhardwareports",
        "Hardware Port: Wi-Fi\nDevice: en0\n",
    );
    let c = crate::capabilities(&f);
    assert!(!c.can_host);
    assert_eq!(c.backend, "macos-guided");
    assert!(c.macos.is_some());
}

#[test]
fn linux_capabilities_on_a_single_adapter_host() {
    let f = FakeSystem::new();
    script_host(&f);
    let c = crate::capabilities(&f);
    assert!(c.can_host && c.single_adapter_in_use && !c.checkpoint_rollback);
    assert_eq!(c.backend, "networkmanager");
    assert!(c.notes.iter().any(|n| n.contains("WPA3")));
}
