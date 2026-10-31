//! LabLink setup and maintenance actions shared by the CLI and the GUI:
//! first-run setup, the systemd user service, shell completion, local network
//! detection, safe config writes, export/import and support bundles.
//!
//! Nothing here probes the network: discovery stays in the daemon.

pub mod bundle;
pub mod completions;
pub mod configfile;
pub mod export;
pub mod ifaces;
pub mod init;
pub mod onboarding;
pub mod remove;
pub mod service;
