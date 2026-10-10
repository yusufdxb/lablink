//! `lablink support-bundle`: a sanitized diagnostic archive.
//!
//! Everything that goes into the archive passes through [`Redactor`]: IPv4
//! and IPv6 addresses, MAC addresses, host-key fingerprints, `.local` names,
//! private-key blocks and `password=`/`token=`-style values are found by
//! shape; usernames, hostnames, labels, device names, site names, network
//! names, Wi-Fi SSIDs and home directories are replaced wherever they appear.
//! The same value always gets the same placeholder (`ip-1`, `site-2`, ...),
//! so the report stays readable. Device notes and service-check commands are
//! removed before redaction, along with device output and journal messages.
//! Nothing is uploaded anywhere.
//!
//! Never collected: private keys, ssh-agent contents, shell history,
//! known_hosts files, credentials, or any file other than LabLink's own
//! config and the daemon's own status and log.

use crate::service;
use lablink_core::client::Client;
use lablink_core::config::Config;
use lablink_core::model::{DeviceDetail, DiscoveredHost, StatusReport};
use lablink_core::protocol::Request;
use lablink_core::site::SitesReport;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::time::Duration;

/// LabLink's own vocabulary: never treated as a sensitive word even when a
/// user picks it as a name (it identifies nobody, and replacing it would
/// make the report unreadable).
const NEVER_SENSITIVE: &[&str] = &[
    "default", "ssh", "site", "device", "network", "ok", "none", "true", "false",
];

/// Replaces sensitive strings with stable placeholders.
#[derive(Debug, Default)]
pub struct Redactor {
    /// Literal (usernames, hostnames, labels, ...), placeholder kind, and
    /// whether to match case-insensitively (hostnames).
    words: Vec<(String, &'static str, bool)>,
    seen: BTreeMap<String, String>,
    counters: BTreeMap<&'static str, usize>,
    home: Option<String>,
}

impl Redactor {
    pub fn new(home: Option<String>) -> Self {
        Self {
            home: home
                .map(|h| h.trim_end_matches('/').to_string())
                .filter(|h| h.len() > 1),
            ..Default::default()
        }
    }

    /// Register a literal to replace wherever it appears as a whole word.
    pub fn add(&mut self, s: &str, kind: &'static str) {
        self.add_with(s, kind, false);
    }

    /// Like [`Redactor::add`], matching any letter case (hostnames).
    pub fn add_ci(&mut self, s: &str, kind: &'static str) {
        self.add_with(s, kind, true);
    }

    fn add_with(&mut self, s: &str, kind: &'static str, ci: bool) {
        let s = s.trim();
        if s.len() < 2 || NEVER_SENSITIVE.iter().any(|w| w.eq_ignore_ascii_case(s)) {
            return;
        }
        if !self.words.iter().any(|(w, _, _)| w == s) {
            self.words.push((s.to_string(), kind, ci));
        }
    }

    fn token(&mut self, original: &str, kind: &'static str) -> String {
        let key = format!("{kind}\u{0}{}", original.to_ascii_lowercase());
        if let Some(t) = self.seen.get(&key) {
            return t.clone();
        }
        let n = self.counters.entry(kind).or_insert(0);
        *n += 1;
        let t = format!("{kind}-{n}");
        self.seen.insert(key, t.clone());
        t
    }

    /// Redact one text.
    pub fn apply(&mut self, text: &str) -> String {
        let mut s = text.to_string();
        if let Some(h) = self.home.clone() {
            s = s.replace(&h, "~");
        }
        s = self.secrets(&s);
        s = self.patterns(&s);
        s = self.home_dirs(&s);
        let mut words = self.words.clone();
        words.sort_by_key(|(w, _, _)| std::cmp::Reverse(w.len()));
        for (w, kind, ci) in words {
            s = self.replace_word(&s, &w, kind, ci);
        }
        s
    }

    fn replace_word(&mut self, s: &str, w: &str, kind: &'static str, ci: bool) -> String {
        let hay = if ci {
            s.to_ascii_lowercase()
        } else {
            s.to_string()
        };
        let needle = if ci {
            w.to_ascii_lowercase()
        } else {
            w.to_string()
        };
        let mut out = String::with_capacity(s.len());
        let mut pos = 0;
        while let Some(rel) = hay[pos..].find(&needle) {
            let i = pos + rel;
            let before = s[..i].chars().next_back();
            let after = s[i + w.len()..].chars().next();
            out.push_str(&s[pos..i]);
            // A '.' on either side is a boundary: names appear inside
            // `lablink.<site>.<name>` aliases and `<host>.local` names.
            let inside = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
            if before.is_some_and(inside) || after.is_some_and(inside) {
                out.push_str(&s[i..i + w.len()]);
            } else {
                let t = self.token(w, kind);
                out.push_str(&t);
            }
            pos = i + w.len();
        }
        out.push_str(&s[pos..]);
        out
    }

    /// `/home/<name>` (any user, e.g. a remote home in command output).
    fn home_dirs(&mut self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("/home/") {
            out.push_str(&rest[..i + 6]);
            let tail = &rest[i + 6..];
            let end = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
                .unwrap_or(tail.len());
            if end > 0 {
                let t = self.token(&tail[..end], "user");
                out.push_str(&t);
            }
            rest = &tail[end..];
        }
        out.push_str(rest);
        out
    }

    /// Private-key blocks, `key=value` secrets, bearer tokens and common
    /// token formats. Defense in depth: LabLink stores no secrets, but
    /// command output and logs might contain some.
    fn secrets(&mut self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut skipping = false;
        for line in s.split_inclusive('\n') {
            if line.contains("PuTTY-User-Key-File-") {
                // PuTTY files contain public and private bodies without PEM delimiters.
                out.push_str("<private key removed>\n");
                break;
            }
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
                skipping = true;
                out.push_str("<private key removed>\n");
                continue;
            }
            if skipping {
                if line.contains("-----END") {
                    skipping = false;
                }
                continue;
            }
            out.push_str(&redact_secret_line(line));
        }
        out
    }

    /// IP and MAC addresses, SHA256 fingerprints and `.local` names, found by shape.
    fn patterns(&mut self, s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < chars.len() {
            let prev_ok = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '.');
            if prev_ok {
                if let Some((len, kind)) = match_at(&chars[i..]) {
                    let original: String = chars[i..i + len].iter().collect();
                    let keep = matches!(original.as_str(), "127.0.0.1" | "0.0.0.0" | "::1" | "::");
                    if keep {
                        out.push_str(&original);
                    } else if kind == "fp" {
                        let t = self.token(&original, "fp");
                        let prefix = if original.starts_with("MD5:") {
                            "MD5"
                        } else {
                            "SHA256"
                        };
                        out.push_str(&format!("{prefix}:<{t}>"));
                    } else {
                        // `name@<address>` (OpenSSH errors): the login name
                        // may be one LabLink never saw (~/.ssh/config).
                        if out.ends_with('@') {
                            let at = out.len() - 1;
                            let start = out[..at]
                                .rfind(|c: char| !(c.is_alphanumeric() || "._-".contains(c)))
                                .map_or(0, |p| p + out[p..].chars().next().unwrap().len_utf8());
                            if start < at && !out[start..at].starts_with("user-") {
                                let user = out[start..at].to_string();
                                let u = self.token(&user, "user");
                                out.replace_range(start..at, &u);
                            }
                        }
                        let t = self.token(&original, kind);
                        out.push_str(&t);
                    }
                    i += len;
                    continue;
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        out
    }
}

/// Replace the value of every `password=...`, `token: ...`-style pair, then
/// bearer tokens and well-known token shapes, in one line.
fn redact_secret_line(line: &str) -> String {
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "x-api-key",
        "access_key",
        "private_key",
        "authorization",
    ];
    let lower = line.to_ascii_lowercase();
    // Byte ranges of values to remove.
    let mut cut: Vec<(usize, usize)> = Vec::new();
    for k in KEYS {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(k) {
            let at = from + rel + k.len();
            from = at;
            let rest = &lower[at..];
            let sep = rest.len() - rest.trim_start_matches([' ', '"', '\'']).len();
            if !rest[sep..].starts_with([':', '=']) {
                continue;
            }
            let start = at + sep + 1;
            let (a, b) = secret_value_range(line, start);
            if a < b {
                // Authorization values are schemes plus credentials. Removing
                // the entire remainder also covers Basic and repeated Bearer.
                cut.push((
                    a,
                    if *k == "authorization" {
                        line.trim_end().len()
                    } else {
                        b
                    },
                ));
            }
        }
    }
    // Password command-line flags may occur in diagnostics or commands.
    for flag in ["--password", "--passwd", "-p"] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(flag) {
            let start = from + rel;
            let end = start + flag.len();
            from = end;
            if start > 0 && !line[..start].chars().next_back().unwrap().is_whitespace() {
                continue;
            }
            if flag != "-p" && !line[end..].starts_with(['=', ' ', '\t']) {
                continue;
            }
            let value = end + usize::from(line[end..].starts_with('='));
            let (a, b) = secret_value_range(line, value);
            if a < b {
                cut.push((a, b));
            }
        }
    }
    cut.sort();
    let mut out = String::with_capacity(line.len());
    let mut pos = 0;
    for (a, b) in cut {
        if a < pos {
            continue;
        }
        out.push_str(&line[pos..a]);
        out.push_str("<removed>");
        pos = b;
    }
    out.push_str(&line[pos..]);
    redact_secret_line_tail(&out)
}

/// Byte boundaries of a quoted or whitespace-delimited secret value.
fn secret_value_range(line: &str, start: usize) -> (usize, usize) {
    let tail = &line[start..];
    let a = start + tail.len() - tail.trim_start().len();
    let v = &line[a..];
    let end = if let Some(quote) = v.chars().next().filter(|c| matches!(c, '\'' | '"')) {
        let mut escaped = false;
        let mut end = v.len();
        for (i, c) in v.char_indices().skip(1) {
            if c == quote && !escaped {
                end = i + c.len_utf8();
                break;
            }
            escaped = c == '\\' && !escaped;
        }
        end
    } else {
        v.find(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .unwrap_or(v.len())
    };
    (a, a + end)
}

/// Bearer tokens and common token prefixes anywhere in a line.
fn redact_secret_line_tail(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for (i, tok) in line.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let t = tok.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';'));
        let looks_like_token = (t.len() >= 20
            && [
                "ghp_",
                "gho_",
                "ghs_",
                "ghu_",
                "github_pat_",
                "glpat-",
                "xox",
                "sk-",
                "AKIA",
            ]
            .iter()
            .any(|p| t.starts_with(p)))
            || (t.starts_with("eyJ") && t.matches('.').count() == 2 && t.len() > 30);
        if looks_like_token {
            out.push_str(&tok.replace(t, "<token removed>"));
        } else {
            out.push_str(tok);
        }
    }
    // Bearer/Basic credentials can also occur without an Authorization key.
    for scheme in ["bearer ", "basic "] {
        let mut from = 0;
        while let Some(rel) = out[from..].to_ascii_lowercase().find(scheme) {
            let start = from + rel + scheme.len();
            let (a, b) = secret_value_range(&out, start);
            if a < b {
                out.replace_range(a..b, "<removed>");
            }
            from = a + if a < b { "<removed>".len() } else { 0 };
        }
    }
    out
}

/// Length and kind of a sensitive token starting at `c[0]`.
fn match_at(c: &[char]) -> Option<(usize, &'static str)> {
    // SHA256:<43 base64>
    let sha: Vec<char> = "SHA256:".chars().collect();
    if c.len() >= sha.len() + 43 && c[..sha.len()] == sha[..] {
        let body = &c[sha.len()..sha.len() + 43];
        if body
            .iter()
            .all(|x| x.is_ascii_alphanumeric() || *x == '+' || *x == '/')
        {
            return Some((sha.len() + 43, "fp"));
        }
    }
    // OpenSSH legacy MD5 fingerprints and Cisco dotted MAC addresses.
    if c.starts_with(&['M', 'D', '5', ':'])
        && c.len() >= 51
        && (0..16).all(|k| c[4 + k * 3].is_ascii_hexdigit() && c[5 + k * 3].is_ascii_hexdigit())
        && (0..15).all(|k| c[6 + k * 3] == ':')
    {
        return Some((51, "fp"));
    }
    if c.len() >= 14
        && c[4] == '.'
        && c[9] == '.'
        && (0..14).all(|k| k == 4 || k == 9 || c[k].is_ascii_hexdigit())
        && c.get(14).is_none_or(|x| !x.is_ascii_hexdigit())
    {
        return Some((14, "mac"));
    }
    if c.len() >= 12
        && c[..12].iter().all(char::is_ascii_hexdigit)
        && c.get(12).is_none_or(|x| !x.is_ascii_hexdigit())
    {
        return Some((12, "mac"));
    }
    // aa:bb:cc:dd:ee:ff (also with '-')
    if c.len() >= 17 {
        let sep = c[2];
        if (sep == ':' || sep == '-')
            && (0..6).all(|k| c[k * 3].is_ascii_hexdigit() && c[k * 3 + 1].is_ascii_hexdigit())
            && (0..5).all(|k| c[k * 3 + 2] == sep)
            && c.get(17)
                .is_none_or(|x| !x.is_ascii_hexdigit() && *x != sep)
        {
            return Some((17, "mac"));
        }
    }
    // IPv6: a run of hex digits, ':' and '.', with at least two ':'.
    let run = c
        .iter()
        .take_while(|x| x.is_ascii_hexdigit() || **x == ':' || **x == '.')
        .count();
    if run >= 2 && c[..run].iter().filter(|x| **x == ':').count() >= 2 {
        let mut n = run;
        while n >= 2 {
            let cand: String = c[..n].iter().collect();
            if cand.parse::<Ipv6Addr>().is_ok() {
                return Some((n, "ip"));
            }
            if !matches!(c[n - 1], ':' | '.') {
                break;
            }
            n -= 1;
        }
    }
    // `.local` names: hostname characters ending in ".local".
    let host = c
        .iter()
        .take_while(|x| x.is_ascii_alphanumeric() || matches!(x, '-' | '_' | '.'))
        .count();
    if host > 6 {
        let h: String = c[..host].iter().collect::<String>().to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        if h.ends_with(".local") && h.len() > 6 && !h.starts_with('.') {
            let len = h.len();
            return Some((len, "host"));
        }
    }
    // dotted quad
    let mut i = 0;
    for part in 0..4 {
        let start = i;
        while i < c.len() && c[i].is_ascii_digit() && i - start < 3 {
            i += 1;
        }
        if i == start {
            return None;
        }
        let n: u32 = c[start..i].iter().collect::<String>().parse().ok()?;
        if n > 255 {
            return None;
        }
        if part < 3 {
            if c.get(i) != Some(&'.') {
                return None;
            }
            i += 1;
        }
    }
    if c.get(i).is_some_and(|x| x.is_ascii_digit()) {
        return None;
    }
    // Numeric octets were checked above, including leading-zero forms.
    Some((i, "ip"))
}

fn run(cmd: &str, args: &[&str]) -> String {
    match lablink_core::program::command(cmd).and_then(|mut c| c.args(args).output()) {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let e = String::from_utf8_lossy(&o.stderr);
            if !e.trim().is_empty() {
                s.push_str("\n[stderr]\n");
                s.push_str(&e);
            }
            s
        }
        Err(e) => format!("could not run {cmd}: {e}\n"),
    }
}

fn os_release() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into())
}

fn uname() -> (String, String) {
    // SAFETY: uname fills a caller-provided struct.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return ("unknown".into(), String::new());
    }
    let field = |f: &[libc::c_char]| {
        // SAFETY: utsname fields are NUL-terminated.
        unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    (
        format!(
            "{} {} {}",
            field(&u.sysname),
            field(&u.release),
            field(&u.machine)
        ),
        field(&u.nodename),
    )
}

pub struct BundleOptions {
    pub config_path: PathBuf,
    pub socket: PathBuf,
    /// Directory the archive is written to.
    pub out_dir: PathBuf,
    /// Run `lablink doctor` (read-only SSH checks) and include the result.
    pub doctor: bool,
}

/// What was produced.
pub struct Bundle {
    pub path: PathBuf,
    pub files: Vec<String>,
}

/// Everything a bundle is made of, before redaction.
#[derive(Debug)]
pub struct Collected {
    pub cfg: Option<Config>,
    /// The config exists but does not load: the error, not the raw file.
    pub cfg_error: Option<String>,
    pub cfg_present: bool,
    pub ping: Result<serde_json::Value, String>,
    pub status: Option<StatusReport>,
    pub details: Vec<DeviceDetail>,
    pub sites: Option<SitesReport>,
    pub discovered: Vec<DiscoveredHost>,
    pub metrics: Option<serde_json::Value>,
    pub doctor: Option<String>,
    pub service: String,
    pub service_state: String,
    pub journal: String,
    /// Identifying facts about this machine and user, for redaction.
    pub user: Option<String>,
    pub hostname: Option<String>,
    pub home: Option<String>,
}

impl Collected {
    /// Nothing collected (no config, no daemon).
    pub fn empty() -> Self {
        Self {
            cfg: None,
            cfg_error: None,
            cfg_present: false,
            ping: Err("not asked".into()),
            status: None,
            details: Vec::new(),
            sites: None,
            discovered: Vec::new(),
            metrics: None,
            doctor: None,
            service: String::new(),
            service_state: String::new(),
            journal: String::new(),
            user: None,
            hostname: None,
            home: None,
        }
    }
}

fn register(r: &mut Redactor, c: &Collected) {
    if let Some(u) = &c.user {
        r.add(u, "user");
    }
    if let Some(h) = &c.hostname {
        r.add_ci(h, "host");
    }
    if let Some(cfg) = &c.cfg {
        for s in &cfg.sites {
            r.add(&s.name, "site");
            r.add(&s.id, "site");
            for n in &s.networks {
                r.add(&n.name, "net");
                if let Some(x) = &n.ssid {
                    r.add(x, "ssid");
                }
            }
            for d in &s.devices {
                r.add(&d.name, "device");
                for a in &d.aliases {
                    r.add(a, "device");
                }
                for u in &d.usernames {
                    r.add(u, "user");
                }
                for h in &d.hostnames {
                    r.add_ci(h, "host");
                    r.add_ci(h.trim_end_matches('.').trim_end_matches(".local"), "host");
                }
                if let Some(l) = &d.label {
                    r.add(l, "label");
                }
                if let Some(h) = &d.ssh_host {
                    r.add_ci(h, "host");
                }
            }
        }
    }
    for d in &c.details {
        r.add(&d.status.name, "device");
        r.add(&d.status.site, "site");
        r.add(&d.status.site_name, "site");
        for a in &d.aliases {
            r.add(a, "device");
        }
        for u in d
            .usernames
            .iter()
            .chain(&d.status.username)
            .chain(&d.active_username)
        {
            r.add(u, "user");
        }
        for h in d
            .hostnames
            .iter()
            .chain(&d.learned_hostnames)
            .chain(&d.mdns_names)
            .chain(std::iter::once(&d.ssh_host))
        {
            r.add_ci(h, "host");
            r.add_ci(h.trim_end_matches('.').trim_end_matches(".local"), "host");
        }
        if let Some(l) = &d.status.label {
            r.add(l, "label");
        }
        if let Some(n) = &d.status.network_name {
            r.add(n, "net");
        }
    }
    if let Some(s) = &c.sites {
        for x in &s.sites {
            r.add(&x.name, "site");
            r.add(&x.id, "site");
            for n in &x.networks {
                r.add(&n.name, "net");
            }
        }
        for ssid in &s.signals.ssids {
            // Rendered as `"<ssid>" on <iface>`.
            if let Some(v) = ssid.strip_prefix('"').and_then(|t| t.rsplit_once("\" on ")) {
                r.add(v.0, "ssid");
            }
        }
    }
    for h in &c.discovered {
        if let Some(n) = &h.hostname {
            r.add_ci(n, "host");
            r.add_ci(n.trim_end_matches('.').trim_end_matches(".local"), "host");
        }
    }
}

/// The config as LabLink understands it, without notes and without the
/// shell commands of service checks (they may contain anything).
fn config_for_bundle(cfg: &Config) -> String {
    let mut c = cfg.clone();
    // Option values can be key paths or user names: keep only the names.
    for v in c.ssh.options.values_mut() {
        *v = "<value removed>".into();
    }
    for s in &mut c.sites {
        for d in &mut s.devices {
            d.notes = None;
            for svc in &mut d.services {
                svc.command = "<command removed>".into();
            }
        }
    }
    c.to_yaml()
}

/// Device output is arbitrary text, so shape matching cannot make it safe.
/// Keep state classes and timing, but discard all output-bearing fields.
fn remove_device_output(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            for (key, value) in m {
                if matches!(
                    key.as_str(),
                    "detail" | "last_error" | "reasons" | "message"
                ) {
                    *value = match value {
                        serde_json::Value::Array(_) => {
                            serde_json::json!(["<device output removed>"])
                        }
                        serde_json::Value::Null => serde_json::Value::Null,
                        _ => serde_json::json!("<device output removed>"),
                    };
                } else {
                    remove_device_output(value);
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(remove_device_output),
        _ => {}
    }
}

/// Build the (redacted) files of a bundle from what was collected.
pub fn assemble(c: &Collected) -> Vec<(String, String)> {
    let mut r = Redactor::new(c.home.clone());
    register(&mut r, c);
    let (kernel, _) = uname();
    let mut files: Vec<(String, String)> = Vec::new();
    files.push((
        "summary.txt".into(),
        format!(
            "LabLink support bundle\n\nlablink version: {}\ngit commit: {}\nOS: {}\nkernel: {}\ndaemon: {}\nservice: {}\nconfig: {}\nsites: {}\ndevices tracked: {}\n",
            lablink_core::VERSION,
            lablink_core::GIT_SHA.unwrap_or("unknown"),
            os_release(),
            kernel,
            match &c.ping {
                Ok(v) => format!(
                    "running, version {}, up {} s",
                    v["version"].as_str().unwrap_or("?"),
                    v["uptime_s"]
                ),
                Err(e) => format!("not reachable ({e})"),
            },
            c.service_state,
            match (&c.cfg, &c.cfg_error, c.cfg_present) {
                (Some(cfg), _, _) => format!(
                    "valid, {} sites, {} networks, {} devices",
                    cfg.sites.len(),
                    cfg.network_count(),
                    cfg.device_count()
                ),
                (None, Some(e), _) => format!("present but INVALID: {e}"),
                (None, None, true) => "present but unreadable".into(),
                (None, None, false) => "missing (first run not completed)".into(),
            },
            c.sites
                .as_ref()
                .map(|s| {
                    s.sites
                        .iter()
                        .map(|x| format!("{} {}", x.name, x.state.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "?".into()),
            c.status.as_ref().map_or(0, |s| s.devices.len()),
        ),
    ));
    if let Some(cfg) = &c.cfg {
        files.push(("config.redacted.yaml".into(), config_for_bundle(cfg)));
    }
    if let Some(s) = &c.status {
        files.push(("status.json".into(), {
            let mut value = serde_json::to_value(s).unwrap_or_default();
            remove_device_output(&mut value);
            serde_json::to_string_pretty(&value).unwrap_or_default()
        }));
    }
    if let Some(s) = &c.sites {
        files.push((
            "sites.json".into(),
            serde_json::to_string_pretty(s).unwrap_or_default(),
        ));
    }
    if !c.details.is_empty() {
        let mut v = serde_json::to_value(&c.details).unwrap_or_default();
        remove_device_output(&mut v);
        if let Some(a) = v.as_array_mut() {
            for d in a {
                d["notes"] = serde_json::Value::Null;
                d["overrides"]["label"] = serde_json::Value::Null;
            }
        }
        files.push((
            "devices.json".into(),
            serde_json::to_string_pretty(&v).unwrap_or_default(),
        ));
    }
    if let Some(m) = &c.metrics {
        files.push((
            "metrics.json".into(),
            serde_json::to_string_pretty(m).unwrap_or_default(),
        ));
    }
    if let Some(d) = &c.doctor {
        let safe = serde_json::from_str::<serde_json::Value>(d)
            .map(|mut v| {
                remove_device_output(&mut v);
                serde_json::to_string_pretty(&v).unwrap_or_default()
            })
            .unwrap_or_else(|_| "<doctor output removed>".into());
        files.push(("doctor.json".into(), safe));
    }
    files.push(("service.txt".into(), c.service.clone()));
    // Journal messages interleave local diagnostics with arbitrary device
    // output and have no trustworthy field boundaries. Do not share them.
    files.push((
        "daemon.log".into(),
        "<journal omitted: may contain device output>\n".into(),
    ));
    let mut out: Vec<(String, String)> = files
        .into_iter()
        .map(|(n, t)| {
            let red = r.apply(&t);
            (n, red)
        })
        .collect();
    out.push((
        "README.txt".into(),
        "This archive was created by `lablink support-bundle` for troubleshooting.\n\n\
IPv4/IPv6 and MAC addresses, host-key fingerprints, usernames, hostnames,\n\
.local names, labels, device names, site names, network names, Wi-Fi network\n\
names and home directories were replaced with placeholders such as ip-1,\n\
mac-2, user-1, device-3, site-1. The same value always gets the same\n\
placeholder. Device notes, service-check commands, device output, doctor\n\
details and daemon journal messages were removed. LabLink\n\
stores no passwords or private keys; it never collects ssh-agent contents,\n\
shell history, known_hosts files or any other file of yours.\n\n\
Review the files before sharing them.\n"
            .into(),
    ));
    out
}

/// Ask the daemon and the system for everything a bundle may contain.
pub fn collect(opts: &BundleOptions) -> Collected {
    let client = Client::new(&opts.socket).with_timeout(Duration::from_secs(5));
    let (cfg, cfg_error) = match Config::load(&opts.config_path) {
        Ok(c) => (Some(c), None),
        Err(lablink_core::config::ConfigError::Io { .. }) => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    let ping = client.call(&Request::Ping).map_err(|e| e.to_string());
    let status: Option<StatusReport> = client
        .call_typed(&Request::Status {
            device: None,
            site: None,
            all: true,
        })
        .ok();
    let details: Vec<DeviceDetail> = client
        .call(&Request::Devices {
            site: None,
            all: true,
        })
        .ok()
        .and_then(|v| serde_json::from_value(v["devices"].clone()).ok())
        .unwrap_or_default();
    let sites: Option<SitesReport> = client.call_typed(&Request::Sites).ok();
    let discovered: Vec<DiscoveredHost> = client
        .call(&Request::Discovered)
        .ok()
        .and_then(|v| serde_json::from_value(v["discovered"].clone()).ok())
        .unwrap_or_default();
    let metrics = client.call(&Request::Metrics).ok();
    let doctor = (opts.doctor && ping.is_ok()).then(|| {
        let checks = cfg.as_ref().map(|c| c.checks_by_id()).unwrap_or_default();
        let o = lablink_doctor::Options {
            devices: vec![],
            timeout: Duration::from_secs(15),
            site: None,
            all: true,
        };
        match lablink_doctor::run(&client, &checks, &o) {
            Ok(rep) => serde_json::to_string_pretty(&rep).unwrap_or_default(),
            Err(e) => format!("doctor did not run: {e:?}"),
        }
    });
    let svc = service::status();
    let (_, nodename) = uname();
    let hostname = std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or(Some(nodename).filter(|n| !n.is_empty()));
    Collected {
        cfg_present: opts.config_path.exists(),
        cfg,
        cfg_error,
        ping,
        status,
        details,
        sites,
        discovered,
        metrics,
        doctor,
        // `show` with fixed properties, not `status`: status lists the
        // service's processes with their command lines (ssh arguments,
        // service-check commands), which may contain anything.
        service: run(
            "systemctl",
            &[
                "--user",
                "show",
                "--no-pager",
                "-p",
                "LoadState,ActiveState,SubState,UnitFileState,FragmentPath,ExecMainStartTimestamp,NRestarts,Result",
                service::UNIT_NAME,
            ],
        ),
        service_state: svc.describe(),
        journal: run(
            "journalctl",
            &[
                "--user",
                "-u",
                service::UNIT_NAME,
                "-n",
                "400",
                "--no-pager",
                "-o",
                "short-iso",
            ],
        ),
        user: std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("LOGNAME").ok()),
        hostname,
        home: std::env::var("HOME").ok(),
    }
}

/// Collect diagnostics, redact them and write `lablink-support-<time>.tar.gz`
/// (mode 0600). The working directory is private (random name, 0700) and the
/// archive never replaces an existing file.
pub fn create(opts: &BundleOptions) -> Result<Bundle, String> {
    let stamp = crate::configfile::utc_stamp(lablink_core::time::now_ms());
    let name = format!("lablink-support-{stamp}");
    let files = assemble(&collect(opts));
    let tmp = tempfile::Builder::new()
        .prefix(".lablink-support-")
        .tempdir_in(&opts.out_dir)
        .map_err(|e| {
            format!(
                "cannot create a work directory in {}: {e}",
                opts.out_dir.display()
            )
        })?;
    let root = tmp.path().join(&name);
    std::fs::create_dir(&root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    let mut listed = Vec::new();
    for (fname, text) in &files {
        std::fs::write(root.join(fname), text).map_err(|e| format!("cannot write {fname}: {e}"))?;
        listed.push(fname.clone());
    }
    let staged = tmp.path().join("bundle.tar.gz");
    let st = lablink_core::program::command("tar")
        .map_err(|e| format!("cannot run tar: {e}"))?
        .args(["--owner=0", "--group=0", "--numeric-owner"])
        .arg("-czf")
        .arg(&staged)
        .arg("-C")
        .arg(tmp.path())
        .arg(&name)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !st.success() {
        return Err(format!("tar failed ({st})"));
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let mut out = opts.out_dir.join(format!("{name}.tar.gz"));
    let mut n = 2;
    while out.symlink_metadata().is_ok() {
        out = opts.out_dir.join(format!("{name}-{n}.tar.gz"));
        n += 1;
    }
    // rename(2) never follows a symlink at the destination; a no-clobber
    // hard link would be stricter but fails across filesystems.
    std::fs::rename(&staged, &out).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(Bundle {
        path: out,
        files: listed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_login_names_never_panic_or_leak() {
        for input in ["Lab jörg@10.0.0.5", "ö@10.0.0.5", "€user@fe80::2"] {
            let out = Redactor::new(None).apply(input);
            assert!(out.contains("user-1@ip-1"), "{out}");
            assert!(!out.contains("jörg") && !out.contains("ö@"), "{out}");
        }
    }

    #[test]
    fn redacts_common_contexts_and_secret_formats() {
        let cases = [
            (
                "ip:192.168.50.7 host-192.168.50.7 dev_192.168.50.7",
                "192.168.50.7",
            ),
            ("addr:fe80::abcd", "fe80::abcd"),
            ("inet addr:192.168.050.007", "192.168.050.007"),
            ("mac 024c.4c01.0203 and 024c4c010203", "024c"),
            (
                "MD5:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
                "00:11",
            ),
            ("password = \"correct horse battery\"", "horse battery"),
            (
                "sshpass -p hunter2 and --password 'correct horse'",
                "hunter2",
            ),
            ("sshpass -pS3cret --password=AnotherSecret", "S3cret"),
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            ("Bearer FirstSecret Bearer SecondSecret", "SecondSecret"),
            (
                "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nSecretKeyBody\n",
                "SecretKeyBody",
            ),
            (
                "/home/SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
                "47DEQpj8",
            ),
        ];
        for (input, secret) in cases {
            let out = Redactor::new(None).apply(input);
            assert!(!out.contains(secret), "{input:?} leaked in {out:?}");
        }
        let out = Redactor::new(None).apply("password='correct horse' --password 'another secret'");
        assert!(!out.contains("horse") && !out.contains("another"), "{out}");
    }

    #[test]
    fn arbitrary_device_output_is_omitted_from_all_bundle_files() {
        let mut c = adversarial();
        // Use actual model serialization so this exercises both status copies.
        let status = serde_json::json!({
            "schema_version": 1,
            "daemon": {"version":"test", "pid":1, "uptime_s":1},
            "devices": [{"name":"test-device", "site":"default", "site_name":"default",
                "label":null, "ip":null, "color":"gray", "discovery":"never_seen", "network":"unknown",
                "ssh_port":"unknown", "ssh_auth":"unknown", "identity":"unverified",
                "latency_ms":null, "last_seen_ms":null, "username":null,
                "interface":null, "network_name":null, "monitoring":true,
                "reasons":["RemoteSecretInReasons"],
                "services":[{"name":"check", "state":"failed", "detail":"X-Api-Key S3cretValue123"}]}]
        });
        c.status = Some(serde_json::from_value(status).unwrap());
        c.details = vec![serde_json::from_value(serde_json::json!({
            "schema_version":1, "status":c.status.as_ref().unwrap().devices[0],
            "configured":true, "aliases":[], "usernames":[], "active_username":null,
            "ssh_host":"test-device", "ssh_port":22, "hostnames":[],
            "learned_hostnames":[], "mdns_names":[], "macs":[], "pinned_keys":[],
            "observed_keys":[], "expected_ips":[], "addresses":[], "identity_signal":null,
            "consecutive_failures":1, "last_error":"RemoteErrorSecret", "notes":null,
            "recent_events":[{"ts_ms":1,"device":"test-device","kind":"service",
                "message":"RemoteEventSecret"}]
        }))
        .unwrap()];
        c.doctor =
            Some("{\"checks\":[{\"status\":\"failed\",\"detail\":\"RemoteDoctorSecret\"}]}".into());
        c.journal = "RemoteJournalSecret".into();
        let all = assemble(&c).into_iter().map(|(_, t)| t).collect::<String>();
        for secret in [
            "S3cretValue123",
            "RemoteSecretInReasons",
            "RemoteDoctorSecret",
            "RemoteJournalSecret",
            "RemoteErrorSecret",
            "RemoteEventSecret",
        ] {
            assert!(!all.contains(secret), "{secret} leaked: {all}");
        }
        assert!(all.contains("failed"), "state class was lost: {all}");
    }

    #[test]
    fn redacts_addresses_fingerprints_and_registered_words() {
        let mut r = Redactor::new(Some("/home/alice".into()));
        r.add("alice", "user");
        r.add("ops", "user");
        r.add_ci("lab-pc", "host");
        let t = "alice@LAB-PC 192.168.1.20 -> 192.168.1.20, 10.0.0.300 mac aa:BB:cc:dd:ee:ff \
SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU /home/alice/.ssh ops-jetson 127.0.0.1 v0.3.0";
        let out = r.apply(t);
        assert!(out.starts_with("user-1@host-1 ip-1 -> ip-1,"), "{out}");
        assert!(out.contains("10.0.0.300"), "not an address: {out}");
        assert!(out.contains("mac mac-1"), "{out}");
        assert!(out.contains("SHA256:<fp-1>"), "{out}");
        assert!(out.contains("~/.ssh"), "{out}");
        // Whole words only: a hostname that merely contains a username stays.
        assert!(out.contains("ops-jetson"), "{out}");
        assert!(out.contains("127.0.0.1") && out.contains("v0.3.0"), "{out}");
        for leak in [
            "alice",
            "192.168.1.20",
            "aa:BB",
            "47DEQ",
            "lab-pc",
            "LAB-PC",
        ] {
            assert!(!out.contains(leak), "{leak} leaked: {out}");
        }
        // Stable across calls.
        assert_eq!(r.apply("192.168.1.20"), "ip-1");
        assert_eq!(r.apply("10.1.1.1/24"), "ip-2/24");
    }

    #[test]
    fn redacts_ipv6_local_names_secrets_and_other_homes() {
        let mut r = Redactor::new(None);
        let t = "addr fe80::1ff:fe23:4567:890a%wlan0 and [2001:db8::42]:22, 2001:db8:0:0:1:0:0:1 \
loopback ::1 time 13:18:22 path lablink_core::model jetson-b.local. reached\n\
password=hunter2 token: abc123 Authorization: Bearer eyJabc.def.ghi more\n\
ghp_0123456789abcdefghijklmnopqrstuvwxyz0 /home/bob/cyclonedds.xml\n\
-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\nafter\n";
        let out = r.apply(t);
        for leak in [
            "fe80::1ff",
            "2001:db8",
            "jetson-b",
            "hunter2",
            "abc123",
            "eyJabc",
            "ghp_0123",
            "bob",
            "b3BlbnNz",
            "PRIVATE KEY",
        ] {
            assert!(!out.contains(leak), "{leak} leaked:\n{out}");
        }
        for kept in [
            "::1",
            "13:18:22",
            "lablink_core::model",
            "%wlan0",
            "after",
            "<private key removed>",
        ] {
            assert!(out.contains(kept), "{kept} missing:\n{out}");
        }
    }

    fn adversarial() -> Collected {
        let yaml = "sites:\n  - id: site-alpha\n    name: Alpha Robotics Lab\n    networks:\n      - name: alpha_lan\n        cidr: 10.77.0.0/24\n        gateway: 10.77.0.1\n        gateway_mac: 02:aa:bb:cc:dd:01\n        ssid: Alpha Guest WiFi\n    devices:\n      - name: rover-7\n        label: Rover Seven\n        usernames: [carol]\n        hostnames: [rover7-host.local]\n        host_key_fingerprints: [\"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\"]\n        notes: door code 4711\n        services:\n          - name: probe\n            command: \"curl -H 'X-Api-Key: SUPERSECRET' http://10.77.0.9\"\n  - id: site-beta\n    name: Beta Workshop\n    devices:\n      - name: bench-pc\n        expected_ips: [\"fd12:3456:789a::5\"]\n";
        let yaml = format!("ssh:\n  options:\n    IdentityFile: /opt/fleet-keys/erin_lab\n{yaml}");
        let cfg = Config::parse(&yaml, "t").unwrap();
        let mut c = Collected::empty();
        c.cfg = Some(cfg);
        c.cfg_present = true;
        c.user = Some("dave".into());
        c.hostname = Some("daves-laptop".into());
        c.home = Some("/home/dave".into());
        c.journal = "2026-10-09T10:00:00 daves-laptop lablinkd[42]: rover-7: located at 10.77.0.42 (matched by fingerprint via keyscan)\n\
2026-10-09T10:00:01 daves-laptop lablinkd[42]: SSH fingerprint verified at 10.77.0.42 (SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU)\n\
learned MAC 02:aa:bb:cc:dd:42; bench-pc at fd12:3456:789a::5; site 'Alpha Robotics Lab' is ACTIVE; \"Alpha Guest WiFi\" on wlan0\n\
ssh: carol@rover7-host.local: Permission denied; /home/dave/.ssh/id_ed25519 and /home/carol/ws\n\
ssh: erin@10.77.0.42: Permission denied (publickey)\n".into();
        c.doctor = Some("{\"detail\": \"GPU OK on rover-7 (Rover Seven), user carol, /home/carol/ws, 10.77.0.42\"}".into());
        c
    }

    #[test]
    fn adversarial_bundle_leaks_nothing() {
        let files = assemble(&adversarial());
        let all: String = files
            .iter()
            .filter(|(n, _)| n != "README.txt")
            .map(|(n, t)| format!("== {n}\n{t}\n"))
            .collect();
        for leak in [
            "10.77.0",
            "02:aa:bb",
            "fd12:3456",
            "47DEQpj8",
            "carol",
            "dave",
            "daves-laptop",
            "rover-7",
            "Rover Seven",
            "rover7-host",
            "Alpha Robotics Lab",
            "Beta Workshop",
            "site-alpha",
            "site-beta",
            "alpha_lan",
            "Alpha Guest WiFi",
            "door code",
            "SUPERSECRET",
            "bench-pc",
            "4711",
            "erin",
            "fleet-keys",
        ] {
            assert!(!all.contains(leak), "{leak} leaked:\n{all}");
        }
        assert!(all.contains("<command removed>"), "{all}");
        assert!(all.contains("device-1"), "{all}");
        assert!(all.contains("site-1"), "{all}");
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        for f in [
            "summary.txt",
            "config.redacted.yaml",
            "daemon.log",
            "doctor.json",
            "README.txt",
        ] {
            assert!(names.contains(&f), "{f} missing: {names:?}");
        }
        for never in ["known_hosts", "history", "id_ed25519", "agent"] {
            assert!(
                !names.iter().any(|n| n.contains(never)),
                "{never}: {names:?}"
            );
        }
    }

    #[test]
    fn names_inside_dotted_aliases_are_redacted() {
        let mut c = adversarial();
        c.service = "ssh -o HostKeyAlias=lablink.site-alpha.rover-7 -l carol -- rover-7 hostname\nrover7-host.local. and rover7-host.lab.example\n".into();
        let files = assemble(&c);
        let svc = &files.iter().find(|(n, _)| n == "service.txt").unwrap().1;
        for leak in ["site-alpha", "rover-7", "carol", "rover7-host"] {
            assert!(!svc.contains(leak), "{leak} leaked: {svc}");
        }
        assert!(svc.contains("HostKeyAlias=lablink.site-"), "{svc}");
        assert!(svc.contains(".device-"), "{svc}");
    }

    #[test]
    fn invalid_config_contributes_its_error_not_its_text() {
        let mut c = Collected::empty();
        c.cfg_present = true;
        c.cfg_error = Some("t: invalid configuration".into());
        let files = assemble(&c);
        assert!(!files.iter().any(|(n, _)| n == "config.redacted.yaml"));
        let s = &files.iter().find(|(n, _)| n == "summary.txt").unwrap().1;
        assert!(s.contains("INVALID"), "{s}");
    }

    #[test]
    fn bundle_without_daemon_is_private_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.yaml");
        std::fs::write(
            &cfg,
            "networks:\n  - name: secret_lab\n    cidr: 192.168.9.0/24\ndevices:\n  - name: jetson-a\n    usernames: [ops]\n    notes: my door code is 1234\n",
        )
        .unwrap();
        let opts = BundleOptions {
            config_path: cfg,
            socket: dir.path().join("none.sock"),
            out_dir: dir.path().to_path_buf(),
            doctor: true,
        };
        let b = create(&opts).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&b.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A second bundle in the same second does not replace the first, and
        // a symlink planted at the next name is left alone.
        let target = dir.path().join("victim");
        std::fs::write(&target, "keep").unwrap();
        let stem = b
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .replace(".tar.gz", "");
        let _ = std::os::unix::fs::symlink(&target, dir.path().join(format!("{stem}-2.tar.gz")));
        let b2 = create(&opts).unwrap();
        assert_ne!(b.path, b2.path);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let headers = std::process::Command::new("tar")
            .args(["-tvzf"])
            .arg(&b.path)
            .output()
            .unwrap();
        assert!(headers.status.success());
        let headers = String::from_utf8(headers.stdout).unwrap();
        for row in headers.lines() {
            assert_eq!(row.split_whitespace().nth(1), Some("0/0"), "{row}");
        }
        let x = dir.path().join("x");
        std::fs::create_dir(&x).unwrap();
        assert!(std::process::Command::new("tar")
            .arg("-xzf")
            .arg(&b.path)
            .arg("-C")
            .arg(&x)
            .status()
            .unwrap()
            .success());
        let inner = std::fs::read_dir(&x)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let c = std::fs::read_to_string(inner.join("config.redacted.yaml")).unwrap();
        for leak in ["secret_lab", "192.168.9.0", "ops", "door code", "jetson-a"] {
            assert!(!c.contains(leak), "{leak} leaked:\n{c}");
        }
        let s = std::fs::read_to_string(inner.join("summary.txt")).unwrap();
        assert!(s.contains("not reachable"), "{s}");
        // No work directories are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".lablink-support-")
            })
            .collect();
        assert!(leftovers.is_empty());
    }
}
