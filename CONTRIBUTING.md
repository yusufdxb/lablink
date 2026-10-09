# Contributing to LabLink

Thank you for helping. Bug reports, documentation fixes and code are all
welcome.

## Before you start

- Security problems: follow [SECURITY.md](SECURITY.md), not a public issue.
- For a larger change, open an issue first to agree on the approach.
- By contributing you agree that your contribution is licensed under the
  Apache License 2.0 (see [LICENSE](LICENSE)).

## Build and test

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on
first use.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check            # licenses, sources, bans, advisories
cargo audit                 # RustSec advisories
```

The GUI needs the usual X11/Wayland/OpenGL runtime libraries to start, but
building and testing need no extra system packages. The OpenSSH
cross-check tests use `ssh-keygen` when it is installed.

### What the tests may and may not touch

- Tests run complete daemons in-process on a simulated network
  (`lablink_daemon::testing::FakeNet`). They must never touch a real
  network, a real device, your `~/.config/lablink`, or your systemd user
  manager. CLI tests point `HOME` and every `XDG_*` directory at a temporary
  directory; LabLink refuses to drive a systemd user manager whose home
  differs from the caller's.
- **Never commit real data.** Use the fake names and documentation-safe
  addresses the tests already use (`jetson-a`, `robot-a`,
  `gpu-workstation`, `site-alpha`, `site-beta`, `10.9.0.0/24`,
  `192.0.2.0/24`, `02:00:00:..` MAC addresses, `fake_key("...")` host keys).
  No real hostnames, usernames, IP or MAC addresses, fingerprints, logs or
  cache databases.

### Clean-room and release builds

```bash
scripts/release.sh                         # .deb + tarball of HEAD, built in Ubuntu 20.04
BASE=ubuntu:22.04 scripts/cleanroom.sh     # fresh-user install test (Docker, privileged)
```

`scripts/release.sh` refuses a dirty tree and builds a clean `git archive`
of the commit, so artifacts always match one commit.

## Code style

- Keep the daemon small and predictable: no polling where an event exists,
  bounded memory, no I/O while holding the registry lock.
- Security-relevant behavior needs a test that fails without it.
- Public JSON and the exit codes are a contract: add fields and enum
  variants at the end, never rename or renumber.
- Platform-specific code belongs in `lablink-platform`, `lablink-discovery`
  or `lablink-setup` (see [docs/PORTABILITY.md](docs/PORTABILITY.md)).

## Pull requests

- One logical change per pull request, with tests.
- `cargo fmt`, clippy with `-D warnings` and the full test suite must pass;
  CI runs them, plus the clean-room tests on Ubuntu 20.04, 22.04 and 24.04.
- Update the docs and `CHANGELOG.md` (under "Unreleased") when behavior
  changes.
