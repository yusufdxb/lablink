//! LabLink robotics mode: read-only ROS 2 and DDS inspection of registered
//! devices over the same pinned-key SSH path as the doctor. Nothing here
//! needs ROS on this machine, installs an agent, or changes a device: the
//! remote scripts are fixed templates, and the few parameters they take
//! are validated and shell-quoted. Only `active` (an explicit,
//! user-initiated test) publishes anything, and only on a unique topic of
//! its own.

pub mod active;
pub mod check;
pub mod dds;
pub mod diagnose;
pub mod env;
pub mod inspect;
pub mod script;

pub use lablink_doctor::RemoteError;

use lablink_core::client::Client;
use std::time::Duration;

/// Runs a script on a device and returns its stdout. The production
/// implementation is [`SshRemote`]; tests use fakes.
pub trait Remote: Sync {
    fn run(&self, device: &str, script: &str, timeout: Duration) -> Result<String, RemoteError>;
}

/// Runs scripts through the daemon-resolved, pinned-key SSH path.
pub struct SshRemote<'a> {
    pub client: &'a Client,
}

impl Remote for SshRemote<'_> {
    fn run(&self, device: &str, script: &str, timeout: Duration) -> Result<String, RemoteError> {
        lablink_doctor::run_pinned_script(self.client, device, script, timeout)
    }
}
