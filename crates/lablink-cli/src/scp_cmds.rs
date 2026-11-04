//! `lablink scp`: copy files to or from one device with the system scp,
//! through the same address and pinned host key as `lablink ssh`.

use crate::{resolve_target, shown, Fail, R};
use lablink_core::client::Client;
use lablink_core::exit;
use lablink_ssh::{scp_args, ScpPath};

/// scp's own options, from `lablink scp` flags (never user text). `quiet`
/// only hides LabLink's line: scp's -q would also hide ssh's host-key errors.
#[derive(Debug, Default, Clone)]
pub struct Flags {
    pub recursive: bool,
    pub preserve: bool,
    pub compress: bool,
    pub legacy: bool,
    pub quiet: bool,
    pub limit: Option<u32>,
}

impl Flags {
    fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            (self.recursive, "-r"),
            (self.preserve, "-p"),
            (self.compress, "-C"),
            (self.legacy, "-O"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, f)| f.to_string())
        .collect();
        if let Some(l) = self.limit {
            a.push("-l".into());
            a.push(l.to_string());
        }
        a
    }
}

/// A command-line operand: `[user@]device:path` names the device (`device`
/// may be `site/name` or the app's name for it); anything else is a local
/// path. As with scp, write a local file whose name has a colon as `./a:b`.
#[derive(Debug, PartialEq, Eq)]
struct Operand {
    remote: Option<(Option<String>, String)>,
    path: ScpPath,
}

fn parse(s: &str) -> Result<Operand, Fail> {
    let local = || Operand {
        remote: None,
        path: ScpPath::Local(s.into()),
    };
    let Some((before, path)) = s.split_once(':') else {
        return Ok(local());
    };
    if before.is_empty() || before.starts_with(['/', '.', '~']) || before.matches('/').count() > 1 {
        return Ok(local());
    }
    let (user, device) = match before.split_once('@') {
        Some((u, d)) => {
            if !lablink_core::config::valid_username(u) {
                return Err(Fail::new(
                    exit::USAGE,
                    "bad_request",
                    format!("invalid username '{u}' in '{s}'"),
                ));
            }
            (Some(u.to_string()), d)
        }
        None => (None, before),
    };
    if device.is_empty() || device.starts_with('-') {
        return Err(Fail::new(
            exit::USAGE,
            "bad_request",
            format!("no device name in '{s}'"),
        ));
    }
    Ok(Operand {
        remote: Some((user, device.to_string())),
        path: ScpPath::Remote(path.into()),
    })
}

/// The one device (and login name) the operands name.
fn one_device(ops: &[Operand], user: Option<String>) -> Result<(String, Option<String>), Fail> {
    let usage = |m: String| Fail::new(exit::USAGE, "bad_request", m);
    let mut device: Option<&str> = None;
    let mut login = user;
    for (u, d) in ops.iter().filter_map(|o| o.remote.as_ref()) {
        match device {
            Some(seen) if seen != d => {
                return Err(usage(format!(
                    "one device per copy: '{seen}' and '{d}' are both named; copy through this machine in two steps"
                )))
            }
            _ => device = Some(d),
        }
        match (&login, u) {
            (Some(a), Some(b)) if a != b => {
                return Err(usage(format!("two login names given: '{a}' and '{b}'")))
            }
            (None, Some(b)) => login = Some(b.clone()),
            _ => {}
        }
    }
    let device = device.ok_or_else(|| {
        usage("no device named: write the remote side as device:path (e.g. jetson:~/data/); a local file with a colon is ./a:b".into())
    })?;
    Ok((device.to_string(), login))
}

pub fn cmd_scp(
    client: &Client,
    paths: &[String],
    user: Option<String>,
    flags: &Flags,
    force: bool,
) -> R {
    use std::os::unix::process::CommandExt;
    let usage = |m: &str| Fail::new(exit::USAGE, "bad_request", m.to_string());
    let Some((last, firsts)) = paths.split_last().filter(|(_, f)| !f.is_empty()) else {
        return Err(usage("give at least one source and a destination"));
    };
    let sources = firsts
        .iter()
        .map(|s| parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    let target = parse(last)?;
    let upload = target.remote.is_some();
    if sources.iter().any(|s| s.remote.is_some() == upload) {
        return Err(usage(if upload {
            "the destination is on a device, so every source must be a local path (device-to-device copies are not supported)"
        } else {
            "the destination is local, so every source must be device:path"
        }));
    }
    let all: Vec<Operand> = sources.into_iter().chain(std::iter::once(target)).collect();
    let (device, login) = one_device(&all, user)?;
    // Never `--unpinned`: a copy goes only to the machine whose key is pinned.
    let (r, mut t) = resolve_target(client, &device, login, (force, false), false).map_err(|mut f| {
        if f.code == exit::DEVICE_NOT_FOUND {
            f.message += &format!(" ('{device}:' was read as a device; write a local file with a colon as ./name)");
        }
        f
    })?;
    // scp starts this very ssh, by absolute path.
    t.binary = lablink_core::program::find(&t.binary)
        .map_err(|e| {
            Fail::new(
                exit::FAILURE,
                "exec",
                format!("cannot run {}: {e}", t.binary),
            )
        })?
        .display()
        .to_string();
    let (srcs, dst) = all.split_at(all.len() - 1);
    let srcs: Vec<ScpPath> = srcs.iter().map(|o| o.path.clone()).collect();
    let args = scp_args(&t, &flags.args(), &srcs, &dst[0].path)
        .map_err(|e| Fail::new(exit::REFUSED, "refused", format!("'{}': {e}", shown(&r))))?;
    if !flags.quiet {
        let who = t
            .username
            .as_deref()
            .map(|u| format!("{u}@"))
            .unwrap_or_default();
        eprintln!(
            "lablink: scp {} {who}{}:{} (host key pinned by LabLink)",
            if upload { "->" } else { "<-" },
            r.ip,
            r.port,
        );
    }
    let err = match lablink_core::program::command("scp") {
        Ok(mut c) => c.args(&args).exec(),
        Err(e) => e,
    };
    Err(Fail::new(
        exit::FAILURE,
        "exec",
        format!("cannot run scp: {err}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(u: Option<&str>, d: &str, p: &str) -> Operand {
        Operand {
            remote: Some((u.map(String::from), d.into())),
            path: ScpPath::Remote(p.into()),
        }
    }
    fn local(p: &str) -> Operand {
        Operand {
            remote: None,
            path: ScpPath::Local(p.into()),
        }
    }

    #[test]
    fn operands_name_a_device_only_before_the_first_colon() {
        assert_eq!(
            parse("jetson:~/data/").map_err(|f| f.message).unwrap(),
            remote(None, "jetson", "~/data/")
        );
        assert_eq!(
            parse("jetson:").map_err(|f| f.message).unwrap(),
            remote(None, "jetson", "")
        );
        assert_eq!(
            parse("nvidia@jetson:/a:b").map_err(|f| f.message).unwrap(),
            remote(Some("nvidia"), "jetson", "/a:b")
        );
        assert_eq!(
            parse("lab/jetson:x").map_err(|f| f.message).unwrap(),
            remote(None, "lab/jetson", "x")
        );
        assert_eq!(
            parse("Lab PC:x").map_err(|f| f.message).unwrap(),
            remote(None, "Lab PC", "x")
        );
        for l in [
            "file", "./a:b", "/abs/a:b", "~/a:b", ":x", "a/b/c:d", "../x:y", "-f",
        ] {
            assert_eq!(parse(l).map_err(|f| f.message).unwrap(), local(l), "{l}");
        }
        for bad in ["-bad@jetson:x", "@jetson:x", "nvidia@:x", "nvidia@-o:x"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_copy_names_exactly_one_device_and_one_login() {
        let ops = [local("a"), remote(Some("u"), "j", "x")];
        assert_eq!(
            one_device(&ops, None).map_err(|f| f.message).unwrap(),
            ("j".into(), Some("u".into()))
        );
        assert_eq!(
            one_device(&ops, Some("u".into()))
                .map_err(|f| f.message)
                .unwrap(),
            ("j".into(), Some("u".into()))
        );
        assert!(one_device(&ops, Some("v".into())).is_err());
        let ops = [remote(None, "j", "a"), remote(None, "k", "b"), local("c")];
        assert!(one_device(&ops, None).is_err());
        let ops = [
            remote(Some("u"), "j", "a"),
            remote(Some("v"), "j", "b"),
            local("c"),
        ];
        assert!(one_device(&ops, None).is_err());
        assert!(one_device(&[local("a"), local("b")], None).is_err());
    }

    #[test]
    fn flags_become_scp_options_only() {
        let f = Flags {
            recursive: true,
            preserve: true,
            compress: true,
            legacy: true,
            quiet: true,
            limit: Some(800),
        };
        assert_eq!(f.args(), ["-r", "-p", "-C", "-O", "-l", "800"]);
        assert!(Flags::default().args().is_empty());
    }
}
