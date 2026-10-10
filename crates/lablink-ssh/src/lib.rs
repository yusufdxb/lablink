//! LabLink's interface to the system OpenSSH client.
//!
//! LabLink never implements the SSH protocol. It builds argument vectors for
//! `ssh`, `ssh-keyscan` and `ssh-keygen`, runs them with timeouts, and parses
//! their output. Everything here is synchronous so that the CLI and GUI do not
//! need an async runtime; the daemon calls it from blocking worker threads.
//!
//! Security properties (see `docs/THREAT_MODEL.md`):
//! - Host-key options chosen by LabLink are placed *first* on the command line.
//!   OpenSSH uses the first value it sees for an option, so neither the config
//!   file's `ssh.options` nor extra user arguments can weaken them.
//! - Verified devices are connected with `HostKeyAlias` + a LabLink-managed
//!   known_hosts file + `StrictHostKeyChecking=yes`: the connection succeeds only
//!   if the server presents the pinned key, at whatever IP it currently has.
//! - Unverified devices get no host-key options at all, so the user's own
//!   OpenSSH policy (`~/.ssh/config`, `~/.ssh/known_hosts`) applies unchanged.
//! - Passwords are never handled: non-interactive calls use `BatchMode=yes`.

pub mod command;
pub mod fingerprint;
pub mod keys;
pub mod run;

pub use command::{
    automated_session_args, build_args, copy_id_args, proxy_command_through, shell_quote, Mode,
    Target, AUTOMATED_SESSION_OPTIONS,
};
pub use fingerprint::fingerprint_of_blob;
pub use keys::{parse_keyscan_output, parse_known_hosts_lines, write_known_hosts, KnownHostsEntry};
pub use run::{classify_ssh_failure, run_captured, ExecOutput, OutputMode, SshFailure};
