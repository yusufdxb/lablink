//! [integration, simulated + localhost] `lablink __complete`, the bash
//! completion script, and `--help` visibility.

use lablink_daemon::testing::{fake_key, fast_config, FakeHost, FakeNet, TestDaemon};
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_lablink");

struct Env {
    _dir: tempfile::TempDir,
    daemon: TestDaemon,
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let net = FakeNet::new(&["10.9.0.2/24"]);
    net.add(
        "10.9.0.31",
        FakeHost::ssh_host(vec![fake_key("jetson-a")], "02:4c:4c:00:00:01"),
    );
    net.add(
        "10.9.0.32",
        FakeHost::ssh_host(vec![fake_key("plain")], "02:4c:4c:00:00:02"),
    );
    let cfg = fast_config(
        "networks:\n  - name: lab\n    cidr: 10.9.0.0/24\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    expected_ips: [10.9.0.31]\n  - name: plain\n    ssh: false\n    expected_ips: [10.9.0.32]\n  - name: never\n    expected_ips: [10.9.0.99]\n",
    );
    let daemon = TestDaemon::start(cfg, net, dir.path().join("state"), true).unwrap();
    let e = Env { _dir: dir, daemon };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let o = run(
            Some(&e),
            &["__complete", "--cword", "2", "--", "lablink", "status", ""],
        );
        let out = String::from_utf8_lossy(&o.stdout).to_string();
        if out.lines().any(|l| l == "jetson-a") && out.lines().any(|l| l == "plain") {
            return e;
        }
        assert!(Instant::now() < deadline, "devices never located: {out}");
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn run(env: Option<&Env>, args: &[&str]) -> Output {
    let mut c = Command::new(BIN);
    c.args(args).env("NO_COLOR", "1");
    match env {
        Some(e) => c.env("LABLINK_SOCKET", &e.daemon.socket),
        None => c.env("LABLINK_SOCKET", "/nonexistent/lablink/test.sock"),
    };
    c.output().unwrap()
}

fn lines(o: &Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn complete_devices_for_ssh_vs_status() {
    let e = setup();
    let ssh = run(
        Some(&e),
        &["__complete", "--cword", "2", "--", "lablink", "ssh", ""],
    );
    assert_eq!(ssh.status.code(), Some(0));
    assert_eq!(lines(&ssh), ["jetson-a"]);
    let st = run(
        Some(&e),
        &["__complete", "--cword", "2", "--", "lablink", "status", ""],
    );
    assert_eq!(lines(&st), ["jetson-a", "plain"]);
    assert!(st.stderr.is_empty());
    let top = run(
        Some(&e),
        &["__complete", "--cword", "1", "--", "lablink", ""],
    );
    assert_eq!(
        lines(&top),
        ["status", "doctor", "devices", "discover", "ssh"]
    );
}

#[test]
fn complete_is_silent_when_daemon_down_or_input_bad() {
    for args in [
        &["__complete", "--cword", "2", "--", "lablink", "ssh", ""][..],
        &["__complete"],
        &["__complete", "--cword", "x"],
        &["__complete", "--bogus", "--cword", "99", "--", "lablink"],
    ] {
        let o = run(None, args);
        assert_eq!(o.status.code(), Some(0), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
        assert!(o.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn script_has_nosort_and_no_default_fallback() {
    let o = run(None, &["completions", "bash"]);
    assert_eq!(o.status.code(), Some(0));
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("complete -o nosort -F _lablink lablink"));
    assert!(!s.contains("-o default") && !s.contains("bashdefault"));
}

#[test]
fn help_lists_commands_but_not_internal() {
    let o = run(None, &["--help"]);
    let h = String::from_utf8_lossy(&o.stdout);
    for c in [
        "exec",
        "trust",
        "adopt",
        "metrics",
        "completions",
        "install-completions",
    ] {
        assert!(
            h.lines().any(|l| l.trim_start().starts_with(c)),
            "{c} missing:\n{h}"
        );
    }
    assert!(!h.contains("__complete"));
}

#[test]
fn install_completions_writes_under_xdg_data_home() {
    let d = tempfile::tempdir().unwrap();
    let o = Command::new(BIN)
        .arg("install-completions")
        .env("XDG_DATA_HOME", d.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let p = d.path().join("bash-completion/completions/lablink");
    assert!(String::from_utf8_lossy(&o.stdout).contains(&format!("wrote {}", p.display())));
    assert!(std::fs::read_to_string(p).unwrap().contains("_lablink()"));
}

fn bash_reply(env: Option<&Env>, cwd: &Path, words: &[&str], cword: usize) -> Option<Vec<String>> {
    let bindir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(BIN, bindir.path().join("lablink")).unwrap();
    let script = bindir.path().join("lablink.bash");
    std::fs::write(&script, lablink_script()).unwrap();
    let quoted: Vec<String> = words.iter().map(|w| format!("'{w}'")).collect();
    let prog = format!(
        "source '{}'; COMP_WORDS=({}); COMP_CWORD={cword}; _lablink; printf '%s\\n' \"${{#COMPREPLY[@]}}\"; printf '%s\\n' \"${{COMPREPLY[@]}}\"",
        script.display(),
        quoted.join(" ")
    );
    let path = format!(
        "{}:{}",
        bindir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut c = Command::new("bash");
    c.args(["--norc", "--noprofile", "-c", &prog])
        .current_dir(cwd)
        .env("PATH", path);
    match env {
        Some(e) => c.env("LABLINK_SOCKET", &e.daemon.socket),
        None => c.env("LABLINK_SOCKET", "/nonexistent/lablink/test.sock"),
    };
    let o = c.output().ok()?;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let mut it = text.lines();
    let n: usize = it.next()?.parse().ok()?;
    Some(it.take(n).map(String::from).collect())
}

fn lablink_script() -> String {
    String::from_utf8(run(None, &["completions", "bash"]).stdout).unwrap()
}

#[test]
fn bash_script_end_to_end() {
    if Command::new("bash").arg("--version").output().is_err() {
        eprintln!("bash missing, skipping");
        return;
    }
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(cwd.path().join("somefile.txt"), "x").unwrap();
    std::fs::write(cwd.path().join("lablink.yaml"), "x").unwrap();
    // daemon down: top level still works, device completion is empty, never files
    assert_eq!(
        bash_reply(None, cwd.path(), &["lablink", ""], 1).unwrap(),
        ["status", "doctor", "devices", "discover", "ssh"]
    );
    assert!(bash_reply(None, cwd.path(), &["lablink", "ssh", ""], 2)
        .unwrap()
        .is_empty());
    assert!(
        bash_reply(None, cwd.path(), &["lablink", "exec", "jetson-a", ""], 3)
            .unwrap()
            .is_empty()
    );
    // files only where designed
    let mut f = bash_reply(None, cwd.path(), &["lablink", "check-config", ""], 2).unwrap();
    f.sort();
    assert_eq!(f, ["lablink.yaml", "somefile.txt"]);
    assert_eq!(
        bash_reply(None, cwd.path(), &["lablink", "--socket", "some"], 2).unwrap(),
        ["somefile.txt"]
    );
    // daemon up
    let e = setup();
    assert_eq!(
        bash_reply(Some(&e), cwd.path(), &["lablink", "ssh", ""], 2).unwrap(),
        ["jetson-a"]
    );
    assert_eq!(
        bash_reply(Some(&e), cwd.path(), &["lablink", "status", "p"], 2).unwrap(),
        ["plain"]
    );
}
