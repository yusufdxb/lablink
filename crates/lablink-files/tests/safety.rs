use lablink_files::{fs, preferences::Preferences, validate_name, Kind};
use russh_sftp::protocol::FileAttributes;
use std::{os::unix::fs::symlink, path::Path};

#[test]
fn untrusted_names_paths_and_type_bits_are_validated() {
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "/etc/passwd",
        "a/b",
        "a\0b",
        "a\nb",
        "a\rb",
        "spoof\u{1b}[31m",
    ] {
        assert!(validate_name(name).is_err(), "{name:?}");
    }
    for name in [
        "空间 café",
        "a b",
        "$(touch sentinel);'",
        "-flag",
        "back\\slash",
    ] {
        validate_name(name).unwrap();
    }
    for (mode, kind) in [
        (0o040755, Kind::Directory),
        (0o100600, Kind::File),
        (0o120777, Kind::Symlink),
        (0o020666, Kind::Other),
    ] {
        assert_eq!(
            fs::remote_kind(&FileAttributes {
                permissions: Some(mode),
                ..FileAttributes::empty()
            }),
            kind
        );
    }
    assert_eq!(fs::normalize_remote("/a/../b//./c").unwrap(), "/b/c");
    assert!(fs::normalize_remote("relative").is_err());
    assert_eq!(lablink_files::remote_parent("/file"), "/");
    assert_eq!(lablink_files::remote_parent("/folder/file"), "/folder");
    assert!(validate_name("spoof\u{202e}txt").is_err());
    let parent = format!("/{}", "a".repeat(4093));
    assert_eq!(
        lablink_files::remote_join(&parent, "b").unwrap().len(),
        4096
    );
    assert!(lablink_files::remote_join(&parent, "bc").is_err());
}
#[test]
fn local_capabilities_refuse_ancestor_symlinks_and_traversal() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();
    let (dir, _) = fs::local_root(root.path()).unwrap();
    assert!(fs::local_child_dir(&dir, Path::new("escape")).is_err());
    assert!(fs::local_child_dir(&dir, Path::new("../outside")).is_err());
    assert!(fs::local_open(&dir, "../file", true).is_err());
    fs::local_mkdir(root.path(), "new").unwrap();
    fs::local_rename(root.path(), "new", "renamed 空间").unwrap();
    assert!(root.path().join("renamed 空间").is_dir());
}
#[test]
fn private_atomic_preferences_roundtrip_and_invalid_data() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private/locations.json");
    let mut preferences = Preferences::default();
    preferences
        .devices
        .entry("site-a-device".into())
        .or_default()
        .remote = Some("/home/test/空间".into());
    preferences
        .devices
        .entry("site-b-device".into())
        .or_default()
        .remote_favorites = vec!["/srv/data".into()];
    preferences.save(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let read = Preferences::load(&path).unwrap();
    assert_eq!(
        read.devices["site-a-device"].remote.as_deref(),
        Some("/home/test/空间")
    );
    assert_eq!(
        read.devices["site-b-device"].remote_favorites,
        vec!["/srv/data"]
    );
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
        1
    );
    std::fs::write(&path, "{truncated").unwrap();
    assert!(Preferences::load(&path).is_err());
}

#[test]
fn staging_cleanup_preserves_substituted_payload_and_directory() {
    use lablink_files::staging::LocalStage;
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = fs::local_root(root.path()).unwrap();
    let mut stage = LocalStage::create(&dir).unwrap();
    stage.file.write_all(b"ours").unwrap();
    let path = root.path().join(stage.name());
    std::fs::rename(path.join("payload"), path.join("ours-moved")).unwrap();
    std::fs::write(path.join("payload"), b"foreign payload").unwrap();
    assert!(stage.verify().is_err());
    drop(stage);
    assert_eq!(
        std::fs::read(path.join("payload")).unwrap(),
        b"foreign payload"
    );
    let mut stage = LocalStage::create(&dir).unwrap();
    stage.file.write_all(b"ours").unwrap();
    let path = root.path().join(stage.name());
    let moved = root.path().join("owned-directory-moved");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("payload"), b"foreign directory").unwrap();
    assert!(stage.verify().is_err());
    drop(stage);
    assert_eq!(
        std::fs::read(path.join("payload")).unwrap(),
        b"foreign directory"
    );
    assert!(!moved.join("payload").exists()); // pinned capability removed only our inode
}
#[test]
fn failed_exclusive_creation_and_publication_preserve_existing_files() {
    use lablink_files::staging::LocalStage;
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = fs::local_root(root.path()).unwrap();
    let name = format!(".lablink-transfer-{}", uuid::Uuid::new_v4());
    std::fs::write(root.path().join(&name), b"foreign").unwrap();
    assert!(LocalStage::create_named(&dir, name.clone()).is_err());
    assert_eq!(std::fs::read(root.path().join(name)).unwrap(), b"foreign");
    let mut stage = LocalStage::create(&dir).unwrap();
    stage.file.write_all(b"complete").unwrap();
    stage.file.sync_all().unwrap();
    std::fs::write(root.path().join("destination"), b"existing").unwrap();
    assert!(stage.publish(&dir, "destination").is_err());
    drop(stage);
    assert_eq!(
        std::fs::read(root.path().join("destination")).unwrap(),
        b"existing"
    );
}
#[test]
fn directory_leases_conflict_in_process_and_across_processes() {
    use lablink_files::staging::LocalLease;
    use std::process::Command;
    let root = tempfile::tempdir().unwrap();
    let (dir, _) = fs::local_root(root.path()).unwrap();
    let lease = LocalLease::acquire(&dir).unwrap();
    assert!(LocalLease::acquire(&dir).is_err());
    let script="import os,sys,fcntl; fd=os.open(sys.argv[1],os.O_RDONLY);\ntry:\n fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('acquired')\nexcept BlockingIOError:\n print('busy')\n";
    let child = || {
        Command::new("python3")
            .args(["-c", script])
            .arg(root.path())
            .output()
            .unwrap()
    };
    let result = child();
    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "busy");
    drop(lease);
    let result = child();
    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "acquired");
}
#[test]
fn capabilities_do_not_follow_a_substituted_parent_into_a_decoy() {
    use lablink_files::staging::LocalStage;
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("chosen")).unwrap();
    let (dir, _) = fs::local_root(&root.path().join("chosen")).unwrap();
    std::fs::rename(
        root.path().join("chosen"),
        root.path().join("original-object"),
    )
    .unwrap();
    symlink(outside.path(), root.path().join("chosen")).unwrap();
    let mut stage = LocalStage::create(&dir).unwrap();
    stage.file.write_all(b"complete").unwrap();
    stage.file.sync_all().unwrap();
    stage.publish(&dir, "file").unwrap();
    drop(stage);
    assert_eq!(
        std::fs::read(root.path().join("original-object/file")).unwrap(),
        b"complete"
    );
    assert!(!outside.path().join("file").exists());
}
