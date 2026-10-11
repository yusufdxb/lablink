//! `lablink ros`: feature gating, argument validation and exit codes. No
//! daemon runs and `$PATH` holds only a fake `ssh` that records being
//! called, so no test can reach a real device.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

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
        let ssh = bin.join("ssh");
        std::fs::write(
            &ssh,
            "#!/bin/bash\necho \"ssh $*\" >> \"${0%/*}/ssh.log\"\nexit 255\n",
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        Env { _dir: dir, root }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lablink"))
            .args(args)
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("PATH", self.root.join("bin"))
            .env("XDG_CONFIG_HOME", self.root.join("cfg"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("LABLINK_SOCKET", self.root.join("run/none.sock"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
    fn ssh_called(&self) -> bool {
        self.root.join("bin/ssh.log").exists()
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn robotics_mode_is_off_by_default() {
    let e = Env::new();
    for args in [
        vec!["ros", "inspect", "orin"],
        vec!["ros", "nodes", "orin"],
        vec!["ros", "topics", "orin"],
        vec!["ros", "dds-check", "orin"],
        vec!["ros", "dds-check", "orin", "--peer", "laptop", "--active"],
    ] {
        let o = e.run(&args);
        assert_eq!(code(&o), 7, "{args:?}: {}", text(&o));
        assert!(
            text(&o).contains("lablink feature enable robotics"),
            "{}",
            text(&o)
        );
    }
    let o = e.run(&["ros", "inspect", "orin", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["error"]["code"], "feature_disabled", "{v}");
    assert_eq!(v["exit_code"], 7);
    assert!(!e.ssh_called());
    assert!(
        !e.root.join("cfg/lablink/config.yaml").exists(),
        "a refused command writes no config"
    );
}

#[test]
fn arguments_are_validated_before_anything_runs() {
    let e = Env::new();
    assert_eq!(code(&e.run(&["feature", "enable", "robotics"])), 0);
    for (args, why) in [
        (
            vec!["ros", "dds-check", "orin", "--active"],
            "--active needs --peer",
        ),
        (
            vec!["ros", "dds-check", "orin", "--qos-topic", "cmd_vel"],
            "relative topic",
        ),
        (
            vec!["ros", "dds-check", "orin", "--qos-topic", "/a;reboot"],
            "shell characters",
        ),
        (
            vec!["ros", "dds-check", "orin", "--spin", "0"],
            "spin range",
        ),
        (vec!["ros", "nodes", "orin", "--spin", "60"], "spin range"),
        (
            vec!["ros", "inspect", "orin", "--timeout", "1"],
            "timeout range",
        ),
        (
            vec![
                "ros",
                "dds-check",
                "orin",
                "--peer",
                "b",
                "--active",
                "--no-graph",
            ],
            "active needs the graph",
        ),
        (
            vec![
                "ros",
                "dds-check",
                "orin",
                "--qos-topic",
                "/a",
                "--qos-topic",
                "/b",
                "--qos-topic",
                "/c",
                "--qos-topic",
                "/d",
                "--qos-topic",
                "/e",
                "--qos-topic",
                "/f",
            ],
            "too many topics",
        ),
    ] {
        let o = e.run(&args);
        assert_eq!(code(&o), 2, "{why}: {args:?}: {}", text(&o));
    }
    assert!(!e.ssh_called());
}

#[test]
fn no_daemon_is_exit_3_and_nothing_connects() {
    let e = Env::new();
    assert_eq!(code(&e.run(&["feature", "enable", "robotics"])), 0);
    for args in [
        vec!["ros", "inspect", "orin"],
        vec!["ros", "nodes", "orin"],
        vec!["ros", "dds-check", "orin", "--peer", "laptop", "--active"],
    ] {
        let o = e.run(&args);
        assert_eq!(code(&o), 3, "{args:?}: {}", text(&o));
    }
    assert!(
        !e.ssh_called(),
        "devices are only reached through the daemon's resolve"
    );
}

#[test]
fn help_states_the_level_4_rule() {
    let e = Env::new();
    let o = e.run(&["ros", "dds-check", "--help"]);
    assert_eq!(code(&o), 0);
    let t = text(&o);
    assert!(t.contains("level 4 only from --active"), "{t}");
    assert!(t.contains("never touches existing topics"), "{t}");
}
