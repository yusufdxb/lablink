//! [systemd] The service actions the desktop app's Start button runs
//! (`service::run_verified`), against a real systemd user manager and the
//! installed `lablinkd.service`. Skipped unless `LABLINK_LIVE_SYSTEMD=1`:
//! it starts and stops the user's real service. Run it in a throwaway
//! container or account (see docs/TESTING.md, "Daemon startup").
//!
//! `LABLINK_LIVE_EXPECT=ok` expects the daemon to start and answer;
//! `LABLINK_LIVE_EXPECT=fail:<text>` expects a failed start whose message
//! contains `<text>` (the daemon's own reason), reported before the timeout.

use lablink_setup::service;
use std::time::Instant;

#[test]
fn start_button_reports_what_the_daemon_did() {
    if std::env::var("LABLINK_LIVE_SYSTEMD").as_deref() != Ok("1") {
        eprintln!("skipped: set LABLINK_LIVE_SYSTEMD=1 to drive the real user service");
        return;
    }
    let expect = std::env::var("LABLINK_LIVE_EXPECT").unwrap_or_else(|_| "ok".into());
    let socket = lablink_core::paths::default_socket_path();
    for action in ["start", "restart"] {
        let t0 = Instant::now();
        let r = service::run_verified(action, &socket);
        println!("{action}: {:?} after {:?}", r, t0.elapsed());
        match expect.strip_prefix("fail:") {
            None => {
                let m = r.expect("the daemon must start and answer");
                assert!(m.contains("answers on"), "{m}");
            }
            Some(text) => {
                let e = r.expect_err("a daemon that exits must not read as started");
                assert!(e.contains(text), "{e}");
                assert!(
                    t0.elapsed() < service::READY_TIMEOUT,
                    "the exit was seen before the timeout: {:?}",
                    t0.elapsed()
                );
            }
        }
    }
    let st = service::status();
    println!("status: {st:?}");
    if expect.starts_with("fail:") {
        assert!(st.last_message.is_some(), "the GUI shows why: {st:?}");
    }
}
