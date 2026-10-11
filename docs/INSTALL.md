# Installing LabLink

LabLink runs on **Ubuntu 20.04, 22.04 and 24.04 LTS** (x86_64). The release
binaries are built on Ubuntu 20.04 and need glibc 2.31 or newer, so other
current x86_64 distributions generally work too, but only these three are
tested on every release (see [TESTING.md](TESTING.md)). No Rust toolchain is
needed.

## Verify the download

Each release has `lablink_<version>_amd64.deb`,
`lablink-<version>-x86_64-linux.tar.gz`, `BUILDINFO` (commit, compiler,
build image, minimum glibc, build timestamp), a CycloneDX SBOM
`lablink-<version>.cdx.json` and `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify lablink_<version>_amd64.deb --repo yusufdxb/lablink
```

The attestation shows the file was built by the project's CI from the tagged
commit; builds are reproducible (see [RELEASING.md](RELEASING.md)).

`lablink version` prints the version and the commit it was built from;
they match the release's Git tag and `BUILDINFO`.

## Debian package

```bash
sudo apt install ./lablink_0.3.1_amd64.deb
```

Installs:

| Path | What |
|---|---|
| `/usr/bin/lablink`, `lablinkd`, `lablink-gui` | CLI, daemon, desktop app |
| `/usr/lib/systemd/user/lablinkd.service` | systemd *user* unit (each user starts their own daemon) |
| `/usr/share/bash-completion/completions/lablink` | bash completion |
| `/usr/share/applications/lablink-gui.desktop`, `/usr/share/icons/hicolor/scalable/apps/lablink.svg` | menu entry and icon |
| `/usr/share/doc/lablink/` | README, LICENSE, NOTICE, third-party licenses, changelog, example config |

It depends on the OpenSSH client and the usual X11/Wayland/OpenGL client
libraries for the app. Nothing starts at install time: each user runs
`lablink init` (or opens LabLink) to name their site, choose networks and
start their own `lablinkd`.

### Remove

```bash
sudo apt remove lablink        # or: sudo apt purge lablink
```

Removing stops running `lablinkd` processes and deletes the program files.
Each user's configuration and state stay in their home directory, also on
`purge` (packages never delete files in home directories). To delete yours:

```bash
systemctl --user disable --now lablinkd 2>/dev/null
rm -rf ~/.config/lablink ~/.local/state/lablink
```

## Tarball (no root)

```bash
tar xzf lablink-0.3.1-x86_64-linux.tar.gz
cd lablink-0.3.1-x86_64-linux
./install.sh                 # or: ./install.sh /opt/lablink  (any prefix you can write)
```

`install.sh` copies the three binaries to `~/.local/bin`, and the menu entry,
icon and bash completion to `~/.local/share`. `lablink init` then writes a
systemd user unit pointing at `~/.local/bin/lablinkd`. If the `.deb` is also
installed on the machine, `lablink init` uses the packaged unit
(`/usr/bin/lablinkd`) instead, so removing the package stops your daemon too;
run `lablink init` again afterwards to switch to the tarball daemon.

Remove with `./uninstall.sh` (keeps configuration and state) or
`./uninstall.sh --purge` (also deletes `~/.config/lablink` and
`~/.local/state/lablink`).

## Files LabLink uses

| Path | Contents |
|---|---|
| `~/.config/lablink/config.yaml` | sites, networks, devices, checks, preferences (mode 0600) |
| `~/.local/state/lablink/` (0700) | `cache.db` (device records, history, site mode), `known_hosts` (pinned keys) |
| `$XDG_RUNTIME_DIR/lablink/lablinkd.sock` | the daemon's socket (0600 in a 0700 directory) |

`LABLINK_CONFIG`, `LABLINK_STATE_DIR` and `LABLINK_SOCKET` override these.

## Upgrading

Install the new package or tarball over the old one, then
`systemctl --user restart lablinkd`. Configuration and state carry over;
single-site configurations from earlier builds are read as site `default`
and their cache is migrated on first start.

## Building from source

```bash
git clone <repository> && cd lablink
cargo build --release --workspace --locked     # binaries in target/release/
```

Release artifacts are built with `scripts/release.sh`: it takes a clean
`git archive` of the committed HEAD, builds it in the pinned Ubuntu 20.04
container (`packaging/build.Dockerfile`) with the toolchain from
`rust-toolchain.toml`, refuses binaries that need a glibc newer than 2.31,
and writes `dist/`. `LABLINK_MAINTAINER` and `LABLINK_HOMEPAGE` override the
Debian package's Maintainer and Homepage fields.
