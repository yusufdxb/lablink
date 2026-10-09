//! Process exit-code contract shared by the CLI and documented in
//! `docs/AUTOMATION.md`. These values are part of the public
//! interface: do not renumber them.

/// Command succeeded (for `status <device>`: the device is GREEN).
pub const OK: i32 = 0;
/// Unexpected internal failure.
pub const FAILURE: i32 = 1;
/// Invalid command-line usage or invalid configuration.
pub const USAGE: i32 = 2;
/// The daemon is not running or its socket is unreachable.
pub const DAEMON_UNAVAILABLE: i32 = 3;
/// The named device is not known to LabLink.
pub const DEVICE_NOT_FOUND: i32 = 4;
/// The device has no usable current address or is offline.
pub const DEVICE_UNREACHABLE: i32 = 5;
/// The device's SSH host key does not match the pinned identity.
pub const IDENTITY_MISMATCH: i32 = 6;
/// The request was refused by policy (e.g. scan outside the allowlist).
pub const REFUSED: i32 = 7;
/// A bare device name matches devices at several sites; use `site/name`.
pub const AMBIGUOUS: i32 = 8;
/// `status <device>`: device is YELLOW (located but degraded/incomplete).
pub const STATUS_YELLOW: i32 = 10;
/// `status <device>`: device is RED (expected but unavailable, or security error).
pub const STATUS_RED: i32 = 11;
/// `status <device>`: device is GRAY (never located, monitoring disabled, or
/// its site is AWAY / not confirmed: not evaluated, not failed).
pub const STATUS_GRAY: i32 = 12;
/// `exec`: the remote command exceeded `--timeout` (same value as coreutils `timeout`).
pub const EXEC_TIMEOUT: i32 = 124;
/// `exec`: the OpenSSH client itself failed (connection/auth/host key), like `ssh`.
pub const SSH_ERROR: i32 = 255;
