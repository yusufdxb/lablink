//! Health-check specifications for `lablink doctor` (config key `checks`).
//!
//! A check is a fixed, read-only probe chosen from a closed catalog; the
//! configuration only supplies strictly validated parameters, never commands.
//! Each entry is either a bare name (`- disk`) or a single-key map
//! (`- ros2: { distro: humble }`).

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiskCheck {
    pub path: String,
    pub warn_pct: u32,
    pub fail_pct: u32,
}
impl Default for DiskCheck {
    fn default() -> Self {
        Self {
            path: "/".into(),
            warn_pct: 85,
            fail_pct: 95,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NvidiaGpuCheck {
    /// Substring (case-insensitive) that must appear in a GPU name.
    pub expect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ThermalCheck {
    pub warn_c: u32,
    pub fail_c: u32,
}
impl Default for ThermalCheck {
    fn default() -> Self {
        Self {
            warn_c: 85,
            fail_c: 95,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ros2Check {
    pub distro: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdsCheck {
    pub interface: String,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default = "default_rmw")]
    pub rmw: String,
}
fn default_rmw() -> String {
    "cyclonedds".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ReachCheck {
    /// Device to ping from the checked device. Without a target, a device
    /// reached `via` a gateway is pinged from that gateway.
    pub target: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// One catalog entry with its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckSpec {
    Disk(DiskCheck),
    NvidiaGpu(NvidiaGpuCheck),
    JetsonGpu,
    Thermal(ThermalCheck),
    Ros2(Ros2Check),
    Dds(DdsCheck),
    Reach(ReachCheck),
}

impl CheckSpec {
    /// Stable kind name (the YAML key and the JSON `kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            CheckSpec::Disk(_) => "disk",
            CheckSpec::NvidiaGpu(_) => "nvidia_gpu",
            CheckSpec::JetsonGpu => "jetson_gpu",
            CheckSpec::Thermal(_) => "thermal",
            CheckSpec::Ros2(_) => "ros2",
            CheckSpec::Dds(_) => "dds",
            CheckSpec::Reach(_) => "reach",
        }
    }

    /// Validate parameters. Everything that ends up in a remote script passes
    /// through here (and again when the script is generated).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CheckSpec::Disk(d) => {
                if !valid_abs_path(&d.path) {
                    return Err(format!(
                        "disk.path '{}' must be an absolute path of [A-Za-z0-9_./-] without '..'",
                        d.path
                    ));
                }
                if !(1..=100).contains(&d.warn_pct)
                    || !(1..=100).contains(&d.fail_pct)
                    || d.warn_pct > d.fail_pct
                {
                    return Err("disk needs 1 <= warn_pct <= fail_pct <= 100".into());
                }
            }
            CheckSpec::NvidiaGpu(g) => {
                if let Some(e) = &g.expect {
                    if !valid_expect(e) {
                        return Err(format!(
                            "nvidia_gpu.expect '{e}' must match [A-Za-z0-9 _.-]{{1,64}}"
                        ));
                    }
                }
            }
            CheckSpec::JetsonGpu => {}
            CheckSpec::Thermal(t) => {
                if t.warn_c == 0 || t.fail_c > 200 || t.warn_c > t.fail_c {
                    return Err("thermal needs 1 <= warn_c <= fail_c <= 200".into());
                }
            }
            CheckSpec::Ros2(r) => {
                if let Some(d) = &r.distro {
                    if !valid_distro(d) {
                        return Err(format!("ros2.distro '{d}' must match [a-z]{{1,32}}"));
                    }
                }
            }
            CheckSpec::Dds(d) => {
                if !valid_interface(&d.interface) {
                    return Err(format!(
                        "dds.interface '{}' must match [A-Za-z0-9_.:-]{{1,15}} and not start with '-'",
                        d.interface
                    ));
                }
                if let Some(c) = &d.config {
                    if !valid_abs_path(c) {
                        return Err(format!(
                            "dds.config '{c}' must be an absolute path of [A-Za-z0-9_./-] without '..'"
                        ));
                    }
                }
                if d.rmw != "cyclonedds" {
                    return Err(format!("dds.rmw '{}' is not supported (cyclonedds)", d.rmw));
                }
            }
            CheckSpec::Reach(r) => {
                if let Some(t) = &r.target {
                    if !crate::config::valid_name(t) {
                        return Err(format!(
                            "reach.target '{t}' must be a device name ([A-Za-z0-9_.-]+)"
                        ));
                    }
                }
                if let Some(l) = &r.label {
                    if !valid_label(l) {
                        return Err(format!(
                            "reach.label '{l}' must match [A-Za-z0-9 _.-]{{1,32}}"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn valid_abs_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 255
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'))
        && !p.split('/').any(|s| s == "..")
}
pub fn valid_interface(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}
pub fn valid_distro(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.chars().all(|c| c.is_ascii_lowercase())
}
pub fn valid_expect(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-'))
}
fn valid_label(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-'))
}

impl Serialize for CheckSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if matches!(self, CheckSpec::JetsonGpu) {
            return s.serialize_str("jetson_gpu");
        }
        let mut m = s.serialize_map(Some(1))?;
        match self {
            CheckSpec::Disk(p) => m.serialize_entry("disk", p)?,
            CheckSpec::NvidiaGpu(p) => m.serialize_entry("nvidia_gpu", p)?,
            CheckSpec::JetsonGpu => {}
            CheckSpec::Thermal(p) => m.serialize_entry("thermal", p)?,
            CheckSpec::Ros2(p) => m.serialize_entry("ros2", p)?,
            CheckSpec::Dds(p) => m.serialize_entry("dds", p)?,
            CheckSpec::Reach(p) => m.serialize_entry("reach", p)?,
        }
        m.end()
    }
}

struct SpecVisitor;

impl<'de> Visitor<'de> for SpecVisitor {
    type Value = CheckSpec;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a check name (`disk`) or a single-key map (`ros2: { distro: humble }`)")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<CheckSpec, E> {
        Ok(match v {
            "disk" => CheckSpec::Disk(DiskCheck::default()),
            "nvidia_gpu" => CheckSpec::NvidiaGpu(NvidiaGpuCheck::default()),
            "jetson_gpu" => CheckSpec::JetsonGpu,
            "thermal" => CheckSpec::Thermal(ThermalCheck::default()),
            "ros2" => CheckSpec::Ros2(Ros2Check::default()),
            "reach" => CheckSpec::Reach(ReachCheck::default()),
            "dds" => return Err(E::custom("check 'dds' needs an `interface`")),
            other => return Err(unknown_kind(other)),
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<CheckSpec, A::Error> {
        let key: String = m
            .next_key()?
            .ok_or_else(|| de::Error::custom("empty check entry"))?;
        // `- disk:` with no value (null) means defaults.
        let spec = match key.as_str() {
            "disk" => CheckSpec::Disk(m.next_value::<Option<_>>()?.unwrap_or_default()),
            "nvidia_gpu" => CheckSpec::NvidiaGpu(m.next_value::<Option<_>>()?.unwrap_or_default()),
            "jetson_gpu" => {
                m.next_value::<Option<Empty>>()?;
                CheckSpec::JetsonGpu
            }
            "thermal" => CheckSpec::Thermal(m.next_value::<Option<_>>()?.unwrap_or_default()),
            "ros2" => CheckSpec::Ros2(m.next_value::<Option<_>>()?.unwrap_or_default()),
            "reach" => CheckSpec::Reach(m.next_value::<Option<_>>()?.unwrap_or_default()),
            "dds" => CheckSpec::Dds(m.next_value()?),
            other => return Err(unknown_kind(other)),
        };
        if m.next_key::<String>()?.is_some() {
            return Err(de::Error::custom(
                "a check entry has exactly one key (indent its parameters under it)",
            ));
        }
        Ok(spec)
    }
}

fn unknown_kind<E: de::Error>(k: &str) -> E {
    E::custom(format!(
        "unknown check '{k}' (expected disk, nvidia_gpu, jetson_gpu, thermal, ros2, dds or reach)"
    ))
}

impl<'de> Deserialize<'de> for CheckSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(SpecVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn parse(y: &str) -> Result<Config, crate::config::ConfigError> {
        Config::parse(y, "t")
    }

    #[test]
    fn accepts_string_and_map_forms() {
        let c = parse(
            "checks:\n  jetson-a:\n    - disk\n    - jetson_gpu\n    - thermal\n    - ros2: { distro: humble }\n    - dds: { interface: eth1, config: /home/ops/cyclonedds.xml }\n    - reach: { target: robot-a, label: \"robot link\" }\n  \"gpu-ws\":\n    - disk: { path: /home, warn_pct: 70 }\n    - nvidia_gpu: { expect: \"RTX A4000\" }\n    - reach\n    - ros2:\n",
        )
        .unwrap();
        let o = &c.sites[0].checks["jetson-a"];
        assert_eq!(o[0], CheckSpec::Disk(DiskCheck::default()));
        assert_eq!(o[1], CheckSpec::JetsonGpu);
        assert_eq!(o[2], CheckSpec::Thermal(ThermalCheck::default()));
        assert_eq!(
            o[3],
            CheckSpec::Ros2(Ros2Check {
                distro: Some("humble".into())
            })
        );
        match &o[4] {
            CheckSpec::Dds(d) => {
                assert_eq!(d.interface, "eth1");
                assert_eq!(d.rmw, "cyclonedds");
            }
            x => panic!("{x:?}"),
        }
        let f = &c.sites[0].checks["gpu-ws"];
        assert_eq!(
            f[0],
            CheckSpec::Disk(DiskCheck {
                path: "/home".into(),
                warn_pct: 70,
                fail_pct: 95
            })
        );
        assert_eq!(f[2], CheckSpec::Reach(ReachCheck::default()));
        assert_eq!(f[3], CheckSpec::Ros2(Ros2Check::default()));
        // Serialization round-trips through the same parser.
        let again = parse(&yaml_serde::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, again);
    }

    #[test]
    fn rejects_invalid_params() {
        for (entry, needle) in [
            ("disk: { path: relative }", "disk.path"),
            ("disk: { path: /a/../etc }", "disk.path"),
            ("disk: { path: \"/a b\" }", "disk.path"),
            ("disk: { path: \"/x;rm\" }", "disk.path"),
            ("disk: { warn_pct: 99, fail_pct: 90 }", "warn_pct"),
            ("disk: { fail_pct: 101 }", "warn_pct"),
            ("thermal: { warn_c: 90, fail_c: 80 }", "warn_c"),
            ("nvidia_gpu: { expect: \"a;b\" }", "expect"),
            ("ros2: { distro: Humble }", "distro"),
            ("ros2: { distro: \"humble;x\" }", "distro"),
            ("dds: { interface: \"eth0;id\" }", "interface"),
            ("dds: { interface: \"-h\" }", "interface"),
            ("dds: { interface: abcdefghijklmnop }", "interface"),
            ("dds: { interface: eth0, config: \"/a/../b\" }", "config"),
            ("dds: { interface: eth0, rmw: fastdds }", "rmw"),
            ("reach: { target: \"a b\" }", "target"),
        ] {
            let y = format!("checks:\n  jetson-a:\n    - {entry}\n");
            let e = parse(&y).expect_err(entry).to_string();
            assert!(e.contains(needle), "{entry}: {e}");
        }
        let e = parse("checks:\n  \"bad name\":\n    - disk\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("checks.bad name"), "{e}");
    }

    #[test]
    fn strictness_is_preserved() {
        for y in [
            "checks:\n  jetson-a:\n    - frobnicate\n",
            "checks:\n  jetson-a:\n    - dds\n",
            "checks:\n  jetson-a:\n    - disk: { pth: / }\n",
            "checks:\n  jetson-a:\n    - disk: { path: / }\n      ros2: {}\n",
            "checks:\n  jetson-a:\n    - command: ls\n",
            "check:\n  jetson-a:\n    - disk\n",
            "checks:\n  jetson-a:\n    - jetson_gpu: { x: 1 }\n",
        ] {
            assert!(parse(y).is_err(), "should reject: {y}");
        }
    }
}
