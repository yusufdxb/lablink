fn main() {
    // `lablink version` reports the commit when the release build sets it.
    println!("cargo:rerun-if-env-changed=LABLINK_GIT_SHA");
}
