//! Human-readable rendering. Stable column order; colors only on a terminal
//! and never when NO_COLOR is set. Machine consumers should use `--json`.

use lablink_core::model::*;
use lablink_core::site::{SiteState, SiteStatus, SitesReport};
use lablink_core::time::format_age;
use std::io::IsTerminal;

pub fn use_color() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

pub fn paint(color: Color, text: &str) -> String {
    if !use_color() {
        return text.to_string();
    }
    let code = match color {
        Color::Green => "32",
        Color::Yellow => "33",
        Color::Red => "31",
        Color::Gray => "90",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

pub fn net_word(s: NetworkState) -> &'static str {
    match s {
        NetworkState::Online => "ONLINE",
        NetworkState::Degraded => "DEGRADED",
        NetworkState::Offline => "OFFLINE",
        NetworkState::Unknown => "UNKNOWN",
    }
}

/// One-word SSH summary combining port and login state.
pub fn ssh_word(d: &DeviceStatus) -> &'static str {
    match d.ssh_port {
        PortState::Disabled => "-",
        PortState::Open => match d.ssh_auth {
            AuthState::Ok => "OK",
            AuthState::Failed => "AUTH_FAIL",
            AuthState::Disabled => "OPEN",
            AuthState::Unavailable | AuthState::Unknown => "OPEN",
        },
        PortState::Closed => "CLOSED",
        PortState::Filtered => "FILTERED",
        PortState::Unknown => "UNKNOWN",
    }
}

pub fn identity_word(s: IdentityState) -> &'static str {
    match s {
        IdentityState::Verified => "VERIFIED",
        IdentityState::Unverified => "UNPINNED",
        IdentityState::Mismatch => "MISMATCH",
        IdentityState::Unknown => "UNKNOWN",
    }
}

/// Render rows as an aligned table (two-space gutters). The last column is
/// not padded. ANSI sequences in a cell do not count toward its width.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let visible = |s: &str| {
        let mut n = 0;
        let mut in_esc = false;
        for c in s.chars() {
            if c == '\x1b' {
                in_esc = true;
            } else if in_esc && c == 'm' {
                in_esc = false;
            } else if !in_esc {
                n += 1;
            }
        }
        n
    };
    let mut w: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(visible(c));
        }
    }
    let mut out = String::new();
    let mut line = |cells: Vec<String>| {
        let n = cells.len();
        let mut l = String::new();
        for (i, c) in cells.into_iter().enumerate() {
            l.push_str(&c);
            if i + 1 < n {
                l.push_str(&" ".repeat(w[i] - visible(&c) + 2));
            }
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(header.iter().map(|s| s.to_string()).collect());
    for r in rows {
        line(r.clone());
    }
    out
}

/// The name to show: `site/name` when the list holds devices of that name
/// at several sites.
fn shown_name(d: &DeviceStatus, all: &[DeviceStatus]) -> String {
    let dup = all.iter().filter(|o| o.name == d.name).count() > 1;
    if dup && !d.id.is_empty() {
        d.id.clone()
    } else {
        d.name.clone()
    }
}

/// `GREEN`, `YELLOW`, ... or `AWAY` for a device whose site is away.
fn state_word(d: &DeviceStatus) -> String {
    if d.site_state == lablink_core::site::SiteState::Away && d.color == Color::Gray {
        paint(Color::Gray, "AWAY")
    } else {
        paint(d.color, d.color.as_str())
    }
}

pub fn status_table(devices: &[DeviceStatus]) -> String {
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|d| {
            vec![
                shown_name(d, devices),
                state_word(d),
                d.ip.clone().unwrap_or_else(|| "--".into()),
                net_word(d.network).into(),
                ssh_word(d).into(),
                if d.ssh_port == PortState::Disabled {
                    "-".into()
                } else {
                    identity_word(d.identity).into()
                },
                d.latency_ms
                    .map(output_latency)
                    .unwrap_or_else(|| "--".into()),
                d.last_seen_ms
                    .map(format_age)
                    .unwrap_or_else(|| "never".into()),
            ]
        })
        .collect();
    table(
        &[
            "DEVICE",
            "STATE",
            "IP",
            "NETWORK",
            "SSH",
            "IDENTITY",
            "LATENCY",
            "LAST SEEN",
        ],
        &rows,
    )
}

pub fn device_detail(d: &DeviceDetail) -> String {
    let s = &d.status;
    let mut o = String::new();
    let mut kv = |k: &str, v: String| o.push_str(&format!("{k:<18} {v}\n"));
    kv(
        "device",
        format!(
            "{}{}",
            s.name,
            s.label
                .as_ref()
                .map(|l| format!(" ({l})"))
                .unwrap_or_default()
        ),
    );
    if !s.site.is_empty() {
        kv(
            "site",
            format!("{} ({}), {}", s.site_name, s.id, s.site_state.as_str()),
        );
    }
    kv(
        "state",
        format!(
            "{} {}",
            paint(s.color, s.color.as_str()),
            if s.reasons.is_empty() {
                String::new()
            } else {
                format!("- {}", s.reasons.join("; "))
            }
        ),
    );
    kv("ip", s.ip.clone().unwrap_or_else(|| "--".into()));
    kv(
        "network",
        format!(
            "{} (discovery: {:?}, failures in a row: {})",
            net_word(s.network),
            s.discovery,
            d.consecutive_failures
        )
        .to_lowercase(),
    );
    kv(
        "interface",
        s.interface.clone().unwrap_or_else(|| "--".into()),
    );
    kv(
        "network name",
        s.network_name
            .clone()
            .unwrap_or_else(|| "(not in allowlist)".into()),
    );
    kv(
        "latency",
        s.latency_ms
            .map(output_latency)
            .unwrap_or_else(|| "--".into()),
    );
    kv(
        "last seen",
        s.last_seen_ms
            .map(|m| format!("{} ago", format_age(m)))
            .unwrap_or_else(|| "never".into()),
    );
    kv(
        "ssh",
        format!(
            "port {} {:?}, login {:?}, host {}",
            d.ssh_port, s.ssh_port, s.ssh_auth, d.ssh_host
        )
        .to_lowercase(),
    );
    kv(
        "username",
        s.username
            .clone()
            .unwrap_or_else(|| "(from ~/.ssh/config)".into()),
    );
    kv(
        "identity",
        format!(
            "{}{}",
            identity_word(s.identity),
            d.identity_signal
                .as_ref()
                .map(|x| format!(" (by {x})"))
                .unwrap_or_default()
        ),
    );
    for k in &d.pinned_keys {
        kv(
            "  pinned key",
            format!(
                "{} {} [{}]",
                k.key_type,
                k.fingerprint,
                k.source.clone().unwrap_or_default()
            ),
        );
    }
    for k in &d.observed_keys {
        kv(
            "  observed key",
            format!("{} {}", k.key_type, k.fingerprint),
        );
    }
    if !d.hostnames.is_empty() {
        kv("hostnames", d.hostnames.join(", "));
    }
    if !d.learned_hostnames.is_empty() {
        kv("learned hostnames", d.learned_hostnames.join(", "));
    }
    if !d.mdns_names.is_empty() {
        kv("mdns names", d.mdns_names.join(", "));
    }
    if !d.macs.is_empty() {
        kv("macs", d.macs.join(", "));
    }
    if !d.aliases.is_empty() {
        kv("aliases", d.aliases.join(", "));
    }
    if !d.expected_ips.is_empty() {
        kv("expected ips", d.expected_ips.join(", "));
    }
    for a in &d.addresses {
        kv(
            if a.current {
                "  address (cur)"
            } else {
                "  address"
            },
            format!(
                "{} via {} net={} if={} mac={} last seen {} ago",
                a.ip,
                a.source,
                a.network_name.clone().unwrap_or_else(|| "-".into()),
                a.interface.clone().unwrap_or_else(|| "-".into()),
                a.mac.clone().unwrap_or_else(|| "-".into()),
                format_age(a.last_seen_ms_ago)
            ),
        );
    }
    if let Some(e) = &d.last_error {
        kv("last error", e.clone());
    }
    if let Some(n) = &d.notes {
        kv("notes", n.clone());
    }
    kv(
        "monitoring",
        if s.monitoring {
            "on".into()
        } else {
            "off".into()
        },
    );
    if !d.recent_events.is_empty() {
        o.push_str("recent events:\n");
        o.push_str(&history_lines(&d.recent_events, false));
    }
    o
}

pub fn history_lines(events: &[HistoryEvent], show_device: bool) -> String {
    let mut o = String::new();
    for e in events {
        let t = format_ts(e.ts_ms);
        if show_device {
            o.push_str(&format!(
                "{t}  {:<10} {}\n",
                e.device.clone().unwrap_or_else(|| "-".into()),
                e.message
            ));
        } else {
            o.push_str(&format!("  {t}  {}\n", e.message));
        }
    }
    o
}

/// Local wall-clock time, `YYYY-MM-DD HH:MM:SS`.
pub fn format_ts(ms: u64) -> String {
    let secs = (ms / 1000) as libc::time_t;
    // SAFETY: localtime_r writes into the provided tm; both pointers are valid.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn discovered_table(hosts: &[DiscoveredHost]) -> String {
    let rows: Vec<Vec<String>> = hosts
        .iter()
        .map(|h| {
            vec![
                h.ip.clone(),
                h.mac.clone().unwrap_or_else(|| "--".into()),
                h.hostname.clone().unwrap_or_else(|| "--".into()),
                format!("{:?}", h.ssh_port).to_uppercase(),
                h.network_name.clone().unwrap_or_else(|| "-".into()),
                h.sources.join(","),
                format_age(h.last_seen_ms_ago),
                h.note.clone().unwrap_or_default(),
            ]
        })
        .collect();
    table(
        &[
            "IP",
            "MAC",
            "HOSTNAME",
            "SSH",
            "NETWORK",
            "SOURCES",
            "LAST SEEN",
            "NOTE",
        ],
        &rows,
    )
}

/// `<1 ms` for sub-millisecond round trips (e.g. through a gateway on a LAN).
fn output_latency(ms: u64) -> String {
    if ms == 0 {
        "<1 ms".into()
    } else {
        format!("{ms} ms")
    }
}

fn site_word(s: &SiteStatus) -> String {
    let (c, w) = match s.state {
        SiteState::Active => (Color::Green, "ACTIVE"),
        SiteState::Away => (Color::Gray, "AWAY"),
        SiteState::Unknown => (Color::Yellow, "UNKNOWN"),
    };
    paint(c, w)
}

fn confidence_word(s: &SiteStatus) -> String {
    match (s.state, s.selected_by) {
        (SiteState::Away, _) => "-".into(),
        (_, lablink_core::site::SelectedBy::Manual) => "manual".into(),
        (_, lablink_core::site::SelectedBy::OnlySite) => "only site".into(),
        _ => s.confidence.as_str().into(),
    }
}

fn counts(s: &SiteStatus) -> String {
    let c = s.devices;
    if c.total == 0 {
        return "0".into();
    }
    if s.state == SiteState::Away {
        return format!("{} (not checked)", c.total);
    }
    let mut parts = Vec::new();
    for (n, w) in [
        (c.green, "green"),
        (c.yellow, "yellow"),
        (c.red, "red"),
        (c.gray, "gray"),
    ] {
        if n > 0 {
            parts.push(format!("{n} {w}"));
        }
    }
    format!("{} ({})", c.total, parts.join(", "))
}

/// `lablink sites`.
pub fn sites_table(r: &SitesReport) -> String {
    if r.sites.is_empty() {
        return "no sites yet: run `lablink init` where your devices are\n".into();
    }
    let rows: Vec<Vec<String>> = r
        .sites
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                site_word(s),
                confidence_word(s),
                counts(s),
                s.id.clone(),
            ]
        })
        .collect();
    let mut o = table(&["SITE", "STATE", "CONFIDENCE", "DEVICES", "ID"], &rows);
    o.push_str(&format!(
        "\nmode: {}{}\n",
        r.mode.describe(),
        match r.mode {
            lablink_core::site::SiteMode::Auto => {
                "   (choose one by hand with `lablink site use <id>`)".to_string()
            }
            lablink_core::site::SiteMode::Manual(_) => {
                "   (back to automatic detection: `lablink site use auto`)".to_string()
            }
        }
    ));
    o
}

/// `lablink site`: the current site and why.
pub fn site_detail(r: &SitesReport) -> String {
    let mut o = String::new();
    let here: Vec<&SiteStatus> = r
        .sites
        .iter()
        .filter(|s| s.state != SiteState::Away)
        .collect();
    if r.sites.is_empty() {
        return "no sites yet: run `lablink init` where your devices are\n".into();
    }
    if here.is_empty() {
        o.push_str(&format!(
            "No active site: LabLink does not recognize this place (mode: {}).\n",
            r.mode.describe()
        ));
        o.push_str("If you are at one of your sites, choose it: `lablink site use <id>`.\n");
    }
    for s in &here {
        o.push_str(&format!(
            "{}  {}  (confidence: {}, {})\n",
            s.name,
            site_word(s),
            confidence_word(s),
            r.mode.describe()
        ));
        o.push_str(&format!("  id        {}\n", s.id));
        o.push_str(&format!("  devices   {}\n", counts(s)));
        if s.contested {
            o.push_str("  note      another site matches this network equally well\n");
        }
        o.push_str(&format!(
            "  scanning  {}\n",
            s.scan
                .clone()
                .unwrap_or_else(|| "allowed on its attached active-scan networks".into())
        ));
        if !s.evidence.is_empty() {
            o.push_str("  evidence\n");
            for e in &s.evidence {
                o.push_str(&format!(
                    "    {:<8} {}\n",
                    format!("{:?}", e.strength).to_lowercase(),
                    e.detail
                ));
            }
        }
        for n in &s.networks {
            o.push_str(&format!(
                "  network   {:<14} {:<18} {}{}\n",
                n.name,
                n.cidr,
                if n.attached {
                    "attached"
                } else {
                    "not attached"
                },
                if n.active_scan { ", active scan" } else { "" }
            ));
        }
    }
    let away: Vec<String> = r
        .sites
        .iter()
        .filter(|s| s.state == SiteState::Away)
        .map(|s| format!("{} ({})", s.name, s.id))
        .collect();
    if !away.is_empty() {
        o.push_str(&format!("\nAway: {}\n", away.join(", ")));
    }
    o.push_str("\nThis machine sees:\n");
    let sig = &r.signals;
    for a in &sig.attached {
        o.push_str(&format!("  network   {a}\n"));
    }
    for g in &sig.gateways {
        o.push_str(&format!("  gateway   {g}\n"));
    }
    for w in &sig.ssids {
        o.push_str(&format!("  Wi-Fi     {w}\n"));
    }
    o
}

/// Line above `lablink status` naming the scope (only with several sites).
pub fn scope_header(r: &StatusReport, site: Option<&str>, all: bool) -> String {
    if r.sites.len() <= 1 && site.is_none() && !all {
        // One site: say so only when it is away (nothing is checked then).
        return match r.sites.first() {
            Some(s) if s.state == SiteState::Away => format!(
                "{} is AWAY: LabLink does not recognize this place, so its {} device(s) are not checked.\n`lablink status --all` lists them; `lablink site use {}` if you are there.\n",
                s.name, s.devices.total, s.id
            ),
            _ => String::new(),
        };
    }
    if all {
        return "All sites\n\n".into();
    }
    if let Some(id) = site {
        return match r.sites.iter().find(|s| s.id.eq_ignore_ascii_case(id)) {
            Some(s) => format!("{}  {}\n\n", s.name, site_word(s)),
            None => String::new(),
        };
    }
    let here: Vec<&SiteStatus> = r
        .sites
        .iter()
        .filter(|s| s.state != SiteState::Away)
        .collect();
    if here.is_empty() {
        return "No active site: LabLink does not recognize this place, so no device is checked.\n`lablink sites` shows every site; `lablink site use <id>` if you are at one.\n".into();
    }
    let mut o = String::new();
    for s in here {
        let ready = match (s.devices.red, s.devices.yellow, s.devices.gray) {
            _ if s.state == SiteState::Unknown => "NOT CONFIRMED".to_string(),
            (0, 0, 0) => paint(Color::Green, "READY"),
            (0, 0, _) | (0, _, _) => paint(Color::Yellow, "DEGRADED"),
            _ => paint(Color::Red, "NOT READY"),
        };
        o.push_str(&format!(
            "{}  {}  {}  (confidence: {})\n",
            s.name,
            site_word(s),
            ready,
            confidence_word(s)
        ));
    }
    o.push('\n');
    o
}

/// Footer of `lablink status` listing the other sites.
pub fn other_sites(r: &StatusReport) -> String {
    let away: Vec<String> = r
        .sites
        .iter()
        .filter(|s| s.state == SiteState::Away)
        .map(|s| format!("  {:<20} {}  {}", s.name, site_word(s), counts(s)))
        .collect();
    if away.is_empty() {
        String::new()
    } else {
        format!("\nOther sites\n{}\n", away.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_alignment_ignores_ansi() {
        let t = table(
            &["A", "B"],
            &[
                vec!["\x1b[32mGREEN\x1b[0m".into(), "x".into()],
                vec!["RED".into(), "y".into()],
            ],
        );
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "A      B");
        assert_eq!(lines[2], "RED    y");
    }
}
