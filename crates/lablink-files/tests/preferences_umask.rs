//! The desktop app saves Files preferences in lablinkd's state directory.
//! LabLink 0.4.2 created that directory with the umask's mode (0775 under
//! Ubuntu's usual umask of 002); lablinkd then refused it on every start.
//! Its own test binary: the umask is per process.

use lablink_files::preferences::Preferences;
use std::os::unix::fs::PermissionsExt;

#[test]
fn preferences_create_a_private_state_directory_whatever_the_umask() {
    // SAFETY: umask has no preconditions; this binary runs only this test.
    let old = unsafe { libc::umask(0o002) };
    let t = tempfile::tempdir().unwrap();
    let state = t.path().join("state").join("lablink");
    let path = state.join("files-preferences.json");
    let r = Preferences::default().save(&path);
    unsafe { libc::umask(old) };
    r.unwrap();
    for d in [t.path().join("state"), state.clone()] {
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", d.display());
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
