//! Service-check extension point.
//!
//! A [`ServiceCheck`] answers "is this thing on the device healthy?" (ROS 2,
//! CycloneDDS, a topic, Nav2, GPU state, disk, temperature, ...). Checks run
//! inside the device's monitor only after the host key is verified and SSH
//! login works, at their own interval, and their results are reported per
//! service without changing the device's network/SSH color.
//!
//! The one built-in implementation, [`CommandCheck`], runs a configured
//! command over OpenSSH (BatchMode) and maps the exit status. Robot-specific
//! checks are therefore configuration, not code:
//!
//! ```yaml
//! services:
//!   - name: ros2
//!     command: "timeout 5 ros2 node list | grep -q ."
//!   - name: disk
//!     command: "test $(df --output=pcent / | tail -1 | tr -dc 0-9) -lt 90"
//! ```
//!
//! New native checks implement the trait and are added in [`from_config`].

use crate::probe::{BoxFut, Prober};
use lablink_core::config::DeviceConfig;
use lablink_core::model::ServiceState;
use lablink_ssh::Target;
use std::sync::Arc;
use std::time::Duration;

/// Result of one service check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceResult {
    pub state: ServiceState,
    pub detail: Option<String>,
}

/// A pluggable per-device health check.
pub trait ServiceCheck: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn interval(&self) -> Duration;
    /// Run the check against a verified, authenticated device.
    fn run<'a>(&'a self, prober: &'a dyn Prober, target: Target) -> BoxFut<'a, ServiceResult>;
}

/// Runs a command on the device; exit 0 = ok, 1 = degraded, else failed.
pub struct CommandCheck {
    pub name: String,
    pub command: String,
    pub interval: Duration,
    pub timeout: Duration,
}

impl ServiceCheck for CommandCheck {
    fn name(&self) -> &str {
        &self.name
    }
    fn interval(&self) -> Duration {
        self.interval
    }
    fn run<'a>(&'a self, prober: &'a dyn Prober, target: Target) -> BoxFut<'a, ServiceResult> {
        Box::pin(async move {
            let out = prober
                .exec(target, self.command.clone(), self.timeout)
                .await;
            // Device output is untrusted: one line, no control characters
            // (it is stored, shown in `lablink status` and in the GUI).
            let first_line = |s: &str| {
                s.lines().find(|l| !l.trim().is_empty()).map(|l| {
                    l.chars()
                        .filter(|c| !c.is_control())
                        .take(200)
                        .collect::<String>()
                })
            };
            if out.timed_out {
                return ServiceResult {
                    state: ServiceState::Failed,
                    detail: Some(format!("timed out after {:?}", self.timeout)),
                };
            }
            match out.exit_code {
                Some(0) => ServiceResult {
                    state: ServiceState::Ok,
                    detail: first_line(&out.stdout),
                },
                Some(1) => ServiceResult {
                    state: ServiceState::Degraded,
                    detail: first_line(&out.stdout).or_else(|| first_line(&out.stderr)),
                },
                Some(255) => ServiceResult {
                    state: ServiceState::Unknown,
                    detail: Some(format!(
                        "ssh failed: {}",
                        first_line(&out.stderr).unwrap_or_default()
                    )),
                },
                Some(c) => ServiceResult {
                    state: ServiceState::Failed,
                    detail: Some(format!(
                        "exit {c}: {}",
                        first_line(&out.stderr)
                            .or_else(|| first_line(&out.stdout))
                            .unwrap_or_default()
                    )),
                },
                None => ServiceResult {
                    state: ServiceState::Failed,
                    detail: Some("killed by signal".into()),
                },
            }
        })
    }
}

/// Checks configured for a device.
pub fn from_config(dev: &DeviceConfig) -> Vec<Arc<dyn ServiceCheck>> {
    dev.services
        .iter()
        .map(|s| {
            Arc::new(CommandCheck {
                name: s.name.clone(),
                command: s.command.clone(),
                interval: Duration::from_secs(s.interval_s),
                timeout: Duration::from_secs(s.timeout_s),
            }) as Arc<dyn ServiceCheck>
        })
        .collect()
}
