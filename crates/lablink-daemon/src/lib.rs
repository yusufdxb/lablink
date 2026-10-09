//! `lablinkd`: the LabLink daemon library (the binary is a thin wrapper so
//! integration tests can run complete daemons in-process with fake probes).

pub mod daemon;
pub mod discovery;
pub mod ipc;
pub mod metrics;
pub mod monitor;
pub mod probe;
pub mod registry;
pub mod services;
pub mod state;
pub mod store;
pub mod testing;

pub use daemon::{run, RunOptions};
