//! `lablink hotspot` and `lablink feature` end to end, against fake
//! `nmcli` and `ip` programs. `$PATH` holds only the fakes' directory, so
//! no test can reach the real NetworkManager whatever the code does.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const UUID: &str = "114930b6-edee-418c-bac6-3400a8517a6c";
const PSK: &str = "correct:horse-battery_staple";

const NMCLI: &str = r#"#!/bin/bash
D="$(cd "${0%/*}" && pwd)"
echo "nmcli $*" >> "$D/argv.log"
up() { [ -e "$D/up" ]; }
case "$*" in
"-t -f RUNNING,VERSION general") echo "running:1.46.0" ;;
"-t general permissions")
  echo "org.freedesktop.NetworkManager.checkpoint-rollback:auth"
  echo "org.freedesktop.NetworkManager.network-control:yes"
  echo "org.freedesktop.NetworkManager.settings.modify.own:yes"
  echo "org.freedesktop.NetworkManager.settings.modify.system:yes"
  echo "org.freedesktop.NetworkManager.wifi.share.protected:yes" ;;
"-t -f DEVICE,TYPE,STATE,CONNECTION device")
  if up; then echo "wlan1:wifi:connected:LabLink Field Network"; else echo "wlan1:wifi:disconnected:"; fi
  echo "lo:loopback:unmanaged:" ;;
"-t -f GENERAL.DEVICE,GENERAL.DRIVER,GENERAL.STATE,GENERAL.CONNECTION,WIFI-PROPERTIES device show wlan1")
  printf 'GENERAL.DEVICE:wlan1\nGENERAL.DRIVER:fakewifi\nGENERAL.STATE:30 (disconnected)\nGENERAL.CONNECTION:\n'
  printf 'WIFI-PROPERTIES.WPA2:yes\nWIFI-PROPERTIES.CCMP:yes\nWIFI-PROPERTIES.AP:yes\nWIFI-PROPERTIES.2GHZ:yes\nWIFI-PROPERTIES.5GHZ:no\n' ;;
"-t -f NAME,UUID,TYPE,DEVICE connection show --active")
  if up; then echo "LabLink Field Network:@UUID@:802-11-wireless:wlan1"; fi ;;
"connection add save yes type wifi con-name LabLink Field Network "*)
  : > "$D/profile"; echo "Connection 'LabLink Field Network' (@UUID@) successfully added." ;;
"connection modify uuid @UUID@ "*) ;;
"connection edit uuid @UUID@")
  while IFS= read -r line; do
    echo "nmcli> $line"
    case "$line" in "set 802-11-wireless-security.psk "*) printf '%s' "${line#set 802-11-wireless-security.psk }" > "$D/psk" ;; esac
  done ;;
"-t -f 802-11-wireless.mode connection show uuid @UUID@")
  [ -e "$D/profile" ] || exit 10; echo "802-11-wireless.mode:ap" ;;
"-t -f connection.interface-name,"*" connection show uuid @UUID@")
  printf 'connection.interface-name:wlan1\nconnection.permissions:user:%s\nconnection.autoconnect:no\n802-11-wireless.ssid:LL Test\n802-11-wireless.mode:ap\n' "$(/usr/bin/id -un)"
  printf '802-11-wireless-security.key-mgmt:wpa-psk\n802-11-wireless-security.proto:rsn\n802-11-wireless-security.pairwise:ccmp\n'
  printf '802-11-wireless-security.group:ccmp\nipv4.method:shared\nipv4.addresses:10.77.0.1/24\n'
  printf 'ipv4.routing-rules:priority 0 from 0.0.0.0/0 iif wlan1 type prohibit\nipv6.method:disabled\n'
  printf 'ipv6.routing-rules:priority 0 from \\:\\:/0 iif wlan1 type prohibit\n802-11-wireless-security.psk-flags:0\n' ;;
"--wait 45 connection up uuid @UUID@ ifname wlan1") : > "$D/up"; echo "Connection successfully activated" ;;
"--wait "*" connection down uuid @UUID@") /bin/rm -f "$D/up" ;;
"-s -g 802-11-wireless-security.psk connection show uuid @UUID@")
  p="$(< "$D/psk")"; echo "${p//:/\\:}" ;;
"connection delete uuid @UUID@") /bin/rm -f "$D/profile" ;;
*) echo "fake nmcli: unexpected: $*" >&2; exit 2 ;;
esac
"#;

const IP: &str = r#"#!/bin/bash
D="$(cd "${0%/*}" && pwd)"
echo "ip $*" >> "$D/argv.log"
WLAN='5: wlan1    inet 10.77.0.1/24 brd 10.77.0.255 scope global noprefixroute wlan1\       valid_lft forever preferred_lft forever'
case "$*" in
"-4 -o addr show")
  echo '1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever'
  [ -e "$D/up" ] && echo "$WLAN" ;;
"-4 -o addr show dev wlan1") [ -e "$D/up" ] && echo "$WLAN" ;;
"-4 -o route show table all")
  [ -e "$D/up" ] && echo "10.77.0.0/24 dev wlan1 proto kernel scope link src 10.77.0.1 metric 600"
  echo "local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1" ;;
"-4 neigh show dev wlan1") echo "10.77.0.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE" ;;
"-4 rule show"|"-6 rule show")
  # NetworkManager installs the profile's isolation rules while it is up.
  printf '0:\tfrom all lookup local\n'
  [ -e "$D/up" ] && [ ! -e "$D/no-rule" ] && printf '0:\tfrom all iif wlan1 prohibit\n'
  printf '32766:\tfrom all lookup main\n' ;;
"-o -d link show")
  echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00'
  echo '5: wlan1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT\    link/ether 02:00:00:00:00:05 brd ff:ff:ff:ff:ff:ff' ;;
*) echo "fake ip: unexpected: $*" >&2; exit 2 ;;
esac
exit 0
"#;

const TC: &str = r#"#!/bin/bash
D="$(cd "${0%/*}" && pwd)"
echo "tc $*" >> "$D/argv.log"
case "$*" in
"qdisc show") echo "qdisc noqueue 0: dev lo root refcnt 2"; echo "qdisc noqueue 0: dev wlan1 root refcnt 2" ;;
"qdisc show dev wlan1") echo "qdisc noqueue 0: dev wlan1 root refcnt 2" ;;
*) echo "fake tc: unexpected: $*" >&2; exit 2 ;;
esac
"#;

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let bin = root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        for (name, body) in [("nmcli", NMCLI), ("ip", IP), ("tc", TC)] {
            let p = bin.join(name);
            std::fs::write(&p, body.replace("@UUID@", UUID)).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The drop-in that keeps the hotspot's DNS server from forwarding.
        let dnsd = root.join("etc/NetworkManager/dnsmasq-shared.d");
        std::fs::create_dir_all(&dnsd).unwrap();
        std::fs::write(dnsd.join("lablink-no-upstream.conf"), "no-resolv\n").unwrap();
        Env { _dir: dir, root }
    }

    fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn config(&self) -> PathBuf {
        self.root.join("cfg/lablink/config.yaml")
    }

    fn state(&self) -> PathBuf {
        self.root.join("state/lablink")
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_lablink"));
        c.args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("PATH", self.bin())
            .env("XDG_CONFIG_HOME", self.root.join("cfg"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("LABLINK_SOCKET", self.root.join("run/none.sock"))
            // An empty /proc: this machine's own connections stay out.
            .env("LABLINK_TEST_PROC_ROOT", self.root.join("proc"))
            .env("LABLINK_TEST_ETC_ROOT", self.root.join("etc"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        {
            use std::io::Write;
            let mut si = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                si.write_all(s.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    }

    fn argv_log(&self) -> String {
        std::fs::read_to_string(self.bin().join("argv.log")).unwrap_or_default()
    }

    fn up(&self) -> bool {
        self.bin().join("up").exists()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}{}", out(o), err(o)))
}

fn enable(e: &Env) {
    let o = e.run(&["feature", "enable", "field-network"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

#[test]
fn the_feature_is_off_by_default_and_gates_every_change() {
    let e = Env::new();
    // status and stop are not gated: see
    // turning_the_feature_off_never_strands_a_running_network.
    for args in [
        &["hotspot", "preflight"][..],
        &["hotspot", "start", "--yes"],
        &["hotspot", "clients"],
        &["hotspot", "restart"],
        &["hotspot", "password"],
        &["hotspot", "forget", "--yes"],
    ] {
        let o = e.run(args, None);
        assert_eq!(o.status.code(), Some(7), "{args:?}: {}", err(&o));
        assert!(
            err(&o).contains("lablink feature enable field-network"),
            "{args:?}"
        );
    }
    let o = e.run(&["hotspot", "start", "--yes", "--json"], None);
    assert_eq!(json(&o)["error"]["code"], "feature_disabled");
    assert!(e.argv_log().is_empty(), "nothing ran: {}", e.argv_log());
    assert!(!e.config().exists(), "a refused command writes no config");
}

#[test]
fn feature_list_enable_disable() {
    let e = Env::new();
    let o = e.run(&["feature", "list", "--json"], None);
    assert_eq!(json(&o)["features"]["field-network"], false);
    enable(&e);
    assert!(read(&e.config()).contains("field_network: true"));
    let o = e.run(&["feature", "enable", "field-network"], None);
    assert!(out(&o).contains("(unchanged)"));
    let o = e.run(&["feature", "list"], None);
    assert!(out(&o).contains("field-network  on"), "{}", out(&o));
    assert!(out(&o).contains("robotics       off"), "{}", out(&o));
    let o = e.run(&["feature", "disable", "field-network"], None);
    assert_eq!(o.status.code(), Some(0));
    let o = e.run(&["feature", "enable", "teleport"], None);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("unknown feature"));
}

#[test]
fn capabilities_is_read_only_and_ungated() {
    let e = Env::new();
    let o = e.run(&["hotspot", "capabilities", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let c = &json(&o)["capabilities"];
    assert_eq!(c["can_host"], true);
    assert_eq!(c["backend"], "networkmanager");
    assert_eq!(c["adapters"][0]["interface"], "wlan1");
    assert_eq!(c["checkpoint_rollback"], false, "auth is not yes");
    assert!(!e.argv_log().contains("connection add"));
    assert!(!e.argv_log().contains(" up "));
}

#[test]
fn insecure_or_invalid_requests_are_usage_errors_before_anything_runs() {
    let e = Env::new();
    enable(&e);
    for (args, why) in [
        (
            &["hotspot", "start", "--yes", "--security", "wep"][..],
            "insecure",
        ),
        (
            &["hotspot", "start", "--yes", "--security", "open"],
            "insecure",
        ),
        (
            &["hotspot", "preflight", "--subnet", "10.77.0.0"],
            "IPv4 CIDR",
        ),
        (
            &["hotspot", "preflight", "--interface", "wl;rm"],
            "interface name",
        ),
    ] {
        let o = e.run(args, None);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", err(&o));
        assert!(err(&o).contains(why), "{args:?}: {}", err(&o));
    }
    // A short password is refused before NetworkManager is asked anything.
    let o = e.run(
        &["hotspot", "start", "--yes", "--password-stdin"],
        Some("short\n"),
    );
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(e.argv_log().is_empty(), "{}", e.argv_log());
}

#[test]
fn preflight_refusals_exit_7_and_change_nothing() {
    let e = Env::new();
    enable(&e);
    // A public range and a /30 are blockers.
    for subnet in ["8.8.8.0/24", "10.77.0.0/30"] {
        let o = e.run(
            &["hotspot", "preflight", "--subnet", subnet, "--json"],
            None,
        );
        assert_eq!(o.status.code(), Some(7), "{subnet}: {}", err(&o));
        assert_eq!(json(&o)["may_start"], false);
        let o = e.run(&["hotspot", "start", "--yes", "--subnet", subnet], None);
        assert_eq!(o.status.code(), Some(7), "{subnet}");
    }
    // Warnings (lablinkd is not running here) need --yes without a terminal.
    let o = e.run(&["hotspot", "start", "--ssid", "LL Test"], None);
    assert_eq!(o.status.code(), Some(7), "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("confirm"), "{}", err(&o));
    let log = e.argv_log();
    assert!(
        !log.contains("connection add") && !log.contains("connection up"),
        "{log}"
    );
    assert!(!e.state().join("fieldnet.json").exists());
}

#[test]
fn start_takes_the_hotspot_down_when_isolation_cannot_be_verified() {
    let e = Env::new();
    enable(&e);
    // NetworkManager activates the profile but its rules never appear.
    std::fs::write(e.bin().join("no-rule"), "").unwrap();
    let o = e.run(
        &[
            "hotspot",
            "start",
            "--yes",
            "--ssid",
            "LL Test",
            "--password-stdin",
        ],
        Some(&format!("{PSK}\n")),
    );
    assert_ne!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    assert!(
        err(&o).contains("isolation could not be verified")
            && err(&o).contains("IPv4 isolation rule")
            && err(&o).contains("The hotspot was stopped"),
        "{}",
        err(&o)
    );
    assert!(!e.up(), "the hotspot must not stay up");
    let log = e.argv_log();
    let up = log.find("connection up").unwrap();
    assert!(log[up..].contains("connection down uuid"), "{log}");
    let o = e.run(&["hotspot", "status", "--json"], None);
    assert_eq!(json(&o)["status"]["active"], false);
}

#[test]
fn isolated_start_is_refused_without_the_dns_drop_in() {
    let e = Env::new();
    enable(&e);
    std::fs::remove_file(
        e.root
            .join("etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf"),
    )
    .unwrap();
    let o = e.run(&["hotspot", "start", "--yes", "--ssid", "LL Test"], None);
    assert_eq!(o.status.code(), Some(7), "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("--allow-dns-relay"), "{}", err(&o));
    assert!(!e.argv_log().contains("connection up"));
    // Accepting it explicitly starts, isolated.
    let o = e.run(
        &[
            "hotspot",
            "start",
            "--yes",
            "--ssid",
            "LL Test",
            "--allow-dns-relay",
            "--password-stdin",
            "--json",
        ],
        Some(&format!("{PSK}\n")),
    );
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    assert_eq!(json(&o)["started"]["isolated"], true);
    assert_eq!(json(&o)["started"]["dns_relay"]["state"], "forwarded");
}

#[test]
fn start_clients_password_stop_forget_end_to_end() {
    let e = Env::new();
    enable(&e);

    // No lablinkd here: the warning says isolation goes unwatched.
    let o = e.run(&["hotspot", "preflight", "--json"], None);
    let j = json(&o);
    let warn = j["preflight"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "equipment")
        .unwrap_or_else(|| panic!("no equipment warning: {j}"));
    let msg = warn["message"].as_str().unwrap();
    assert!(msg.contains("re-check isolation"), "{msg}");

    let o = e.run(
        &[
            "hotspot",
            "start",
            "--yes",
            "--ssid",
            "LL Test",
            "--password-stdin",
            "--json",
        ],
        Some(&format!("{PSK}\n")),
    );
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    let j = json(&o);
    assert_eq!(j["started"]["interface"], "wlan1");
    assert_eq!(j["started"]["subnet"], "10.77.0.0/24");
    assert_eq!(j["started"]["gateway"], "10.77.0.1");
    assert_eq!(j["started"]["profile_created"], true);
    assert!(e.up());

    // The password went through the editor's stdin: never into a process
    // argument, LabLink's output, its state file or its config.
    assert_eq!(read(&e.bin().join("psk")), PSK);
    let log = e.argv_log();
    assert!(!log.contains("horse"), "PSK in argv: {log}");
    assert!(!out(&o).contains("horse") && !err(&o).contains("horse"));
    let state = read(&e.state().join("fieldnet.json"));
    assert!(state.contains(UUID) && !state.contains("horse"), "{state}");
    let mode = std::fs::metadata(e.state().join("fieldnet.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "state file is private");
    // The profile is a WPA2-PSK/CCMP access point with shared IPv4, never autoconnecting.
    let add = log.lines().find(|l| l.contains("connection add")).unwrap();
    for want in [
        "802-11-wireless.mode ap",
        "802-11-wireless-security.key-mgmt wpa-psk",
        "802-11-wireless-security.proto rsn",
        "802-11-wireless-security.pairwise ccmp",
        "connection.autoconnect no",
        "ipv4.method shared",
        "ipv4.addresses 10.77.0.1/24",
        "ipv6.method disabled",
        "ipv4.routing-rules priority 0 iif wlan1 prohibit",
        "ipv6.routing-rules priority 0 iif wlan1 prohibit",
    ] {
        assert!(add.contains(want), "{want}: {add}");
    }
    assert_eq!(j["started"]["isolated"], true);
    assert_eq!(j["started"]["isolation"]["verified"], true);
    assert_eq!(j["started"]["dns_relay"]["state"], "off");
    assert!(!log.contains("busctl"), "no checkpoint without permission");

    // The roaming field-network site was added.
    let cfg = read(&e.config());
    assert!(
        cfg.contains("id: field-network") && cfg.contains("roaming: true"),
        "{cfg}"
    );
    assert!(cfg.contains("cidr: 10.77.0.0/24"), "{cfg}");

    // Status and clients.
    let o = e.run(&["hotspot", "status", "--json"], None);
    let s = &json(&o)["status"];
    assert_eq!(s["active"], true);
    assert_eq!(s["out_of_sync"], false);
    assert_eq!(s["isolation"]["verified"], true);
    assert!(!out(&o).contains("horse"));
    let o = e.run(&["hotspot", "clients", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let c = &json(&o)["clients"][0];
    assert_eq!(c["ip"], "10.77.0.23");
    assert_eq!(
        c["state"], "discovered-untrusted",
        "unknown clients are never trusted"
    );
    let o = e.run(&["hotspot", "clients"], None);
    assert!(
        out(&o).contains("never trusted automatically"),
        "{}",
        out(&o)
    );

    // The password only on explicit request, unescaped.
    let o = e.run(&["hotspot", "password"], None);
    assert_eq!(out(&o).trim_end(), PSK);

    // Starting again re-applies the running network (no second profile).
    let o = e.run(&["hotspot", "start", "--yes", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    assert_eq!(json(&o)["started"]["already_running"], true);
    assert_eq!(json(&o)["started"]["profile_created"], false);
    assert_eq!(e.argv_log().matches("connection add").count(), 1);

    // forget is refused while running.
    let o = e.run(&["hotspot", "forget", "--yes"], None);
    assert_eq!(o.status.code(), Some(7), "{}", err(&o));

    let o = e.run(&["hotspot", "stop", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(json(&o)["stopped"]["was_active"], true);
    assert!(!e.up());
    let o = e.run(&["hotspot", "clients"], None);
    assert_eq!(o.status.code(), Some(7));

    let o = e.run(&["hotspot", "forget", "--yes"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!e.bin().join("profile").exists());
    assert!(!e.state().join("fieldnet.json").exists());
    assert!(!e.argv_log().contains("horse"));
}

#[test]
fn turning_the_feature_off_never_strands_a_running_network() {
    let e = Env::new();
    enable(&e);
    let o = e.run(
        &[
            "hotspot",
            "start",
            "--yes",
            "--ssid",
            "LL Test",
            "--password-stdin",
            "--json",
        ],
        Some(&format!("{PSK}\n")),
    );
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    assert!(e.up());
    let o = e.run(&["feature", "disable", "field-network"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let o = e.run(&["hotspot", "status", "--json"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(json(&o)["status"]["active"], true);
    let o = e.run(&["hotspot", "stop"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!e.up());
    let o = e.run(&["hotspot", "restart"], None);
    assert_eq!(o.status.code(), Some(7), "changes stay gated");
}

#[test]
fn stop_is_refused_while_an_ssh_session_rides_on_the_hotspot() {
    let e = Env::new();
    enable(&e);
    let o = e.run(
        &[
            "hotspot",
            "start",
            "--yes",
            "--ssid",
            "LL Test",
            "--password-stdin",
            "--json",
        ],
        Some(&format!("{PSK}\n")),
    );
    assert_eq!(o.status.code(), Some(0), "{}{}", out(&o), err(&o));
    // A client at 10.77.0.23 is logged in over SSH to 10.77.0.1 (wlan1).
    let net = e.root.join("proc/net");
    std::fs::create_dir_all(&net).unwrap();
    std::fs::write(
        net.join("tcp"),
        "  sl  local_address rem_address   st\n   0: 01004D0A:0016 17004D0A:C738 01 0\n",
    )
    .unwrap();
    let o = e.run(&["hotspot", "stop"], None);
    assert_eq!(o.status.code(), Some(7), "{}{}", out(&o), err(&o));
    assert!(err(&o).contains("10.77.0.23 port 51000"), "{}", err(&o));
    assert!(e.up(), "nothing was taken down");
    std::fs::remove_file(net.join("tcp")).unwrap();
    let o = e.run(&["hotspot", "stop"], None);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!e.up());
}

#[test]
fn forget_without_yes_refuses_off_a_terminal() {
    let e = Env::new();
    enable(&e);
    let o = e.run(&["hotspot", "forget"], None);
    assert_eq!(o.status.code(), Some(7));
    assert!(err(&o).contains("--yes"));
}
