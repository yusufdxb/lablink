//! Bash completion logic for `lablink`. The candidate computation is pure
//! (device fetching is injected) so it can be unit tested without a daemon.
//!
//! `lablink __complete --cword N -- <COMP_WORDS...>` prints one candidate per
//! line and always exits 0 with nothing on stderr, whatever goes wrong.

use clap::CommandFactory;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Top-level commands offered for an empty prefix, in this order.
pub const CURATED: &[&str] = &["status", "doctor", "devices", "discover", "ssh"];
/// Token telling the bash script to fall back to filename completion.
pub const FILES: &str = "__lablink_files__";
const GLOBAL_FLAGS: &[&str] = &["--socket", "--help", "--version"];
const SSH_ONLY: &[&str] = &["ssh", "exec", "copy-id"];
const ALL_DEVICES: &[&str] = &["status", "inspect", "resolve", "trust", "set", "history"];

/// A device the daemon has located.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dev {
    pub name: String,
    pub ssh: bool,
    /// `site/name`.
    pub id: String,
    /// Its site is not AWAY (bare names are offered only for these).
    pub here: bool,
}

impl Dev {
    fn site(&self) -> &str {
        self.id.split_once('/').map_or("", |(s, _)| s)
    }
}

pub fn bash_script() -> &'static str {
    lablink_setup::completions::bash_script()
}

fn socket_from(words: &[String]) -> Option<PathBuf> {
    let mut found = None;
    let mut i = 1;
    while i < words.len() {
        let w = &words[i];
        if let Some(p) = w.strip_prefix("--socket=") {
            found = Some(PathBuf::from(p));
        } else if w == "--socket" {
            let (j, v) = match (words.get(i + 1), words.get(i + 2)) {
                (Some(eq), Some(v)) if eq == "=" => (i + 2, v),
                (Some(v), _) => (i + 1, v),
                _ => break,
            };
            found = Some(PathBuf::from(v));
            i = j;
        }
        i += 1;
    }
    found
}

fn subcommand_visible(c: &clap::Command, name: &str) -> bool {
    name != "help"
        && c.get_subcommands()
            .any(|s| s.get_name() == name && !s.is_hide_set())
}

fn long_flags(sub: &clap::Command) -> (Vec<String>, Vec<String>) {
    let (mut all, mut valued) = (vec![], vec![]);
    for a in sub.get_arguments() {
        if a.is_hide_set() || a.get_id() == "version" {
            continue;
        }
        if let Some(l) = a.get_long() {
            let f = format!("--{l}");
            if a.get_action().takes_values() {
                valued.push(f.clone());
            }
            if !all.contains(&f) {
                all.push(f);
            }
        }
    }
    if !all.iter().any(|f| f == "--help") {
        all.push("--help".into());
    }
    (all, valued)
}

fn starts(list: impl IntoIterator<Item = String>, prefix: &str) -> Vec<String> {
    list.into_iter().filter(|s| s.starts_with(prefix)).collect()
}

/// Compute completion candidates. `fetch` is only called when devices are
/// needed; it receives the socket path to use.
pub fn complete(
    words: &[String],
    cword: usize,
    fetch: impl FnOnce(&Path) -> Vec<Dev>,
) -> Vec<String> {
    let cur = words.get(cword).map(String::as_str).unwrap_or("");
    let before = &words[..cword.min(words.len()).max(1)];
    let root = crate::Cli::command();

    // Walk the words before the cursor: find the subcommand and positionals.
    let mut sub: Option<String> = None;
    let mut positionals: Vec<&str> = vec![];
    let mut prev_valued_flag: Option<String> = None;
    let mut sub_cmd: Option<clap::Command> = None;
    let mut i = 1;
    while i < before.len() {
        let w = before[i].as_str();
        prev_valued_flag = None;
        if w == "--socket" {
            prev_valued_flag = Some(w.to_string());
        } else if w == "=" && i > 1 && before[i - 1] == "--socket" {
            prev_valued_flag = Some("--socket".into());
        } else if w == "--" {
            positionals.extend(before[i + 1..].iter().map(String::as_str));
            break;
        } else if w.starts_with("--") && !w.contains('=') {
            if let Some(sc) = &sub_cmd {
                if long_flags(sc).1.iter().any(|f| f == w) {
                    prev_valued_flag = Some(w.to_string());
                }
            }
        } else if w.starts_with('-') {
            // short flag or --flag=value: ignore
        } else if i > 1 && before[i - 1] == "--socket"
            || (i > 2 && before[i - 1] == "=" && before[i - 2] == "--socket")
        {
            // value of --socket
        } else if let Some(prev) = i.checked_sub(1).and_then(|p| before.get(p)).filter(|p| {
            p.starts_with("--")
                && sub_cmd
                    .as_ref()
                    .is_some_and(|sc| long_flags(sc).1.contains(p))
        }) {
            let _ = prev; // value of a value-taking flag
        } else if sub.is_none() {
            if !subcommand_visible(&root, w) {
                return vec![];
            }
            sub = Some(w.to_string());
            sub_cmd = root.find_subcommand(w).cloned();
        } else {
            positionals.push(w);
        }
        i += 1;
    }

    if matches!(
        prev_valued_flag.as_deref(),
        Some("--socket" | "--config" | "--output" | "--output-dir" | "--identity")
    ) {
        return if cur == "=" {
            vec![]
        } else {
            vec![FILES.into()]
        };
    }
    if prev_valued_flag.as_deref() == Some("--site") && cur != "=" {
        let socket = socket_from(words).unwrap_or_else(lablink_core::paths::default_socket_path);
        let mut sites: Vec<String> = fetch(&socket)
            .iter()
            .map(|d| d.site().to_string())
            .collect();
        sites.sort();
        sites.dedup();
        return starts(sites.into_iter().filter(|s| !s.is_empty()), cur);
    }
    if prev_valued_flag.is_some() || cur == "=" {
        return vec![];
    }

    let Some(sub) = sub else {
        if cur.starts_with('-') {
            return starts(GLOBAL_FLAGS.iter().map(|s| s.to_string()), cur);
        }
        let curated = starts(CURATED.iter().map(|s| s.to_string()), cur);
        if cur.is_empty() || !curated.is_empty() {
            return curated;
        }
        let mut all: Vec<String> = root
            .get_subcommands()
            .filter(|s| !s.is_hide_set() && s.get_name() != "help")
            .map(|s| s.get_name().to_string())
            .collect();
        all.sort();
        return starts(all, cur);
    };

    if cur.starts_with('-') {
        return match &sub_cmd {
            Some(sc) => starts(long_flags(sc).0, cur),
            None => vec![],
        };
    }

    let sub = sub.as_str();
    if sub == "site" {
        return match positionals.as_slice() {
            [] => starts(["add", "rename", "use"].map(String::from), cur),
            ["use"] | ["rename"] => {
                let socket =
                    socket_from(words).unwrap_or_else(lablink_core::paths::default_socket_path);
                let mut sites: Vec<String> = fetch(&socket)
                    .iter()
                    .map(|d| d.site().to_string())
                    .collect();
                if positionals == ["use"] {
                    sites.push("auto".into());
                }
                sites.sort();
                sites.dedup();
                starts(sites.into_iter().filter(|s| !s.is_empty()), cur)
            }
            _ => vec![],
        };
    }
    if sub == "check-config" || sub == "import" {
        return if positionals.is_empty() {
            vec![FILES.into()]
        } else {
            vec![]
        };
    }
    let ssh_only = SSH_ONLY.contains(&sub);
    let single = ssh_only || ALL_DEVICES.contains(&sub);
    if !(single || sub == "doctor") || (single && !positionals.is_empty()) {
        return vec![];
    }
    let socket = socket_from(words).unwrap_or_else(lablink_core::paths::default_socket_path);
    let devs: Vec<Dev> = fetch(&socket)
        .into_iter()
        .filter(|d| !ssh_only || d.ssh)
        .collect();
    let mut names: Vec<String> = if cur.contains('/') {
        // `site/name` for any site.
        devs.iter().map(|d| d.id.clone()).collect()
    } else {
        // Bare names at the sites you are at; a name that exists twice
        // there is offered as site/name.
        let here: Vec<&Dev> = devs.iter().filter(|d| d.here).collect();
        here.iter()
            .map(|d| {
                if here.iter().filter(|o| o.name == d.name).count() > 1 && !d.id.is_empty() {
                    d.id.clone()
                } else {
                    d.name.clone()
                }
            })
            .collect()
    };
    names.retain(|n| !positionals.contains(&n.as_str()));
    names.sort();
    names.dedup();
    starts(names, cur)
}

/// Entry point for `lablink __complete`; never fails, never writes to stderr.
pub fn entry(args: Vec<String>) {
    std::panic::set_hook(Box::new(|_| {}));
    let _ = std::panic::catch_unwind(|| {
        let Some(p) = args.iter().position(|a| a == "--cword") else {
            return;
        };
        let Some(Ok(cword)) = args.get(p + 1).map(|v| v.parse::<usize>()) else {
            return;
        };
        let Some(d) = args.iter().position(|a| a == "--") else {
            return;
        };
        let words = &args[d + 1..];
        if cword >= words.len() {
            return;
        }
        let out = complete(words, cword, fetch_devices);
        let mut s = std::io::stdout().lock();
        for line in out {
            let _ = writeln!(s, "{line}");
        }
    });
}

fn fetch_devices(socket: &Path) -> Vec<Dev> {
    use lablink_core::client::Client;
    use lablink_core::model::{PortState, StatusReport};
    use lablink_core::protocol::Request;
    let client = Client::new(socket).with_timeout(std::time::Duration::from_millis(500));
    match client.call_typed::<StatusReport>(&Request::Status {
        device: None,
        site: None,
        all: true,
    }) {
        Ok(r) => r
            .devices
            .into_iter()
            .filter(|d| d.ip.is_some())
            .map(|d| Dev {
                ssh: d.ssh_port != PortState::Disabled,
                here: d.site_state != lablink_core::site::SiteState::Away,
                id: d.id,
                name: d.name,
            })
            .collect(),
        Err(_) => vec![],
    }
}

pub fn install() -> Result<i32, String> {
    match lablink_setup::completions::install()? {
        lablink_setup::completions::Installed::User(path) => {
            println!("wrote {}", path.display());
            println!("Open a new shell (or `source` that file) to enable lablink tab completion.");
        }
        lablink_setup::completions::Installed::System(path) => {
            println!("already installed for all users at {}", path.display());
        }
    }
    Ok(lablink_core::exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        // trailing space in `s` means the cursor is on a new empty word
        let mut v: Vec<String> = s.split_whitespace().map(String::from).collect();
        if s.ends_with(' ') {
            v.push(String::new());
        }
        v
    }
    fn dev(id: &str, ssh: bool, here: bool) -> Dev {
        Dev {
            name: id.split_once('/').unwrap().1.into(),
            ssh,
            id: id.into(),
            here,
        }
    }
    fn devs() -> Vec<Dev> {
        vec![
            dev("site-alpha/jetson-a", true, true),
            dev("site-alpha/gpu-ws", true, true),
            dev("site-alpha/plain", false, true),
            dev("site-beta/jetson-b", true, false),
        ]
    }
    fn run(line: &str) -> Vec<String> {
        let words = w(line);
        complete(&words, words.len() - 1, |_| devs())
    }
    fn run_none(line: &str) -> Vec<String> {
        let words = w(line);
        complete(&words, words.len() - 1, |_| vec![])
    }

    #[test]
    fn sites_and_qualified_names() {
        // Away devices are not offered by bare name, but by site/name.
        assert!(!run("lablink ssh ").contains(&"jetson-b".to_string()));
        assert_eq!(run("lablink ssh site-beta/"), ["site-beta/jetson-b"]);
        assert_eq!(run("lablink site "), ["add", "rename", "use"]);
        assert_eq!(
            run("lablink site use "),
            ["auto", "site-alpha", "site-beta"]
        );
        assert_eq!(run("lablink status --site "), ["site-alpha", "site-beta"]);
        // The same name at two sites you are at: offered as site/name.
        let words = w("lablink ssh ");
        let both = complete(&words, words.len() - 1, |_| {
            vec![
                dev("site-alpha/jetson", true, true),
                dev("site-beta/jetson", true, true),
            ]
        });
        assert_eq!(both, ["site-alpha/jetson", "site-beta/jetson"]);
    }

    #[test]
    fn curated_exact_and_ordered() {
        assert_eq!(
            run("lablink "),
            ["status", "doctor", "devices", "discover", "ssh"]
        );
    }

    #[test]
    fn prefixes() {
        assert_eq!(run("lablink d"), ["doctor", "devices", "discover"]);
        assert_eq!(run("lablink ex"), ["exec", "export"]);
        assert_eq!(
            run("lablink in"),
            ["init", "inspect", "install-completions", "install-service"]
        );
        assert_eq!(run("lablink copy-id "), ["gpu-ws", "jetson-a"]);
        assert_eq!(run("lablink insp"), ["inspect"]);
        assert!(run("lablink zzz").is_empty());
    }

    #[test]
    fn never_offers_hidden_or_help() {
        for p in ["", "_", "__", "h", "he"] {
            let out = run(&format!("lablink {p}"));
            assert!(
                !out.iter().any(|c| c == "__complete" || c == "help"),
                "{p}: {out:?}"
            );
        }
        assert!(run("lablink help ").is_empty());
    }

    #[test]
    fn global_flags() {
        assert_eq!(run("lablink -"), ["--socket", "--help", "--version"]);
        assert_eq!(run("lablink --s"), ["--socket"]);
    }

    #[test]
    fn ssh_and_exec_only_ssh_capable_located() {
        assert_eq!(run("lablink ssh "), ["gpu-ws", "jetson-a"]);
        assert_eq!(
            run("lablink exec j"),
            ["jetson-a"],
            "away jetson-b is not offered"
        );
        assert!(run_none("lablink ssh ").is_empty());
    }

    #[test]
    fn all_device_commands_include_ssh_disabled() {
        for c in [
            "status", "doctor", "inspect", "resolve", "trust", "set", "history",
        ] {
            assert_eq!(
                run(&format!("lablink {c} ")),
                ["gpu-ws", "jetson-a", "plain"],
                "{c}"
            );
            assert!(run_none(&format!("lablink {c} ")).is_empty(), "{c}");
        }
    }

    #[test]
    fn doctor_excludes_typed_names() {
        assert_eq!(run("lablink doctor jetson-a "), ["gpu-ws", "plain"]);
        assert_eq!(run("lablink doctor --json jetson-a gpu-ws "), ["plain"]);
    }

    #[test]
    fn single_device_commands_stop_after_first_positional() {
        for c in [
            "status", "ssh", "exec", "inspect", "resolve", "trust", "set", "history",
        ] {
            assert!(run(&format!("lablink {c} jetson-a ")).is_empty(), "{c}");
        }
        assert!(run("lablink exec jetson-a uname").is_empty());
    }

    #[test]
    fn files_only_after_socket_and_check_config() {
        assert_eq!(run("lablink --socket "), [FILES]);
        assert_eq!(run("lablink --socket /tm"), [FILES]);
        assert_eq!(run("lablink status --socket "), [FILES]);
        assert_eq!(run("lablink check-config "), [FILES]);
        assert!(run("lablink check-config a.yaml ").is_empty());
        for c in [
            "ssh", "exec", "status", "adopt", "discover", "metrics", "trust",
        ] {
            assert!(
                !run_none(&format!("lablink {c} ")).contains(&FILES.to_string()),
                "{c}"
            );
        }
        assert!(run_none("lablink ssh ").is_empty());
    }

    #[test]
    fn socket_path_is_taken_from_words() {
        let mut seen = vec![];
        for line in [
            "lablink --socket /a/b.sock ssh ",
            "lablink --socket=/a/b.sock ssh ",
            "lablink --socket = /a/b.sock ssh ",
        ] {
            let words = w(line);
            complete(&words, words.len() - 1, |p| {
                seen.push(p.to_path_buf());
                vec![]
            });
        }
        assert!(seen.iter().all(|p| p == Path::new("/a/b.sock")), "{seen:?}");
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn subcommand_flags_via_clap() {
        assert!(run("lablink status --").contains(&"--json".to_string()));
        assert!(run("lablink status --").contains(&"--help".to_string()));
        assert!(run("lablink discover --sc").contains(&"--scan-cidr".to_string()));
        // value of a value-taking flag: nothing, and never files
        assert!(run("lablink discover --scan-cidr ").is_empty());
    }

    #[test]
    fn other_commands_are_empty() {
        for c in [
            "adopt",
            "discover",
            "metrics",
            "ping",
            "devices",
            "discovered",
        ] {
            assert!(run(&format!("lablink {c} ")).is_empty(), "{c}");
        }
    }
}
