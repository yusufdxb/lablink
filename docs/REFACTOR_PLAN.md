# Refactor plan: splitting the four largest files

Four files are too large to review safely:

| File | Lines | What it is |
|---|---|---|
| `crates/lablink-daemon/src/registry.rs` | 4,698 | the daemon's device, identity, trust and site state |
| `crates/lablink-gui/src/app.rs` | 2,903 | the desktop app's main window |
| `crates/lablink-core/src/config.rs` | 2,102 | configuration types, parsing and validation |
| `crates/lablink-cli/src/main.rs` | 1,942 | the CLI's clap definitions and command dispatch |

This plan proposes module splits with **no behaviour change**. It is a plan
only: no code has moved. Line numbers refer to `main` at the time of
writing and will drift.

## Rules for every step

1. **Moves only.** A step moves items between files and adjusts `use`,
   `mod` and visibility. It changes no function body, no type, no clap
   attribute, no serde attribute, no error text. A reviewer checks it with
   `git diff --color-moved=dimmed-zebra --color-moved-ws=allow-indentation-change`:
   everything except imports and module headers must show as moved.
2. **One file, one pull request, one step at a time.** Never combine a move
   with a fix. If a bug is found during a move, note it, finish the move,
   fix it in its own pull request.
3. **Paths stay valid.** Every item reachable today (`lablink_core::config::X`,
   `crate::registry::X`) stays reachable at the same path through `pub use`
   in the new `mod.rs`. Visibility is widened only to `pub(super)` or
   `pub(crate)`, never to `pub`.
4. **Guardrails first.** Each file below lists the characterization tests to
   add *before* the first move (in a separate pull request), so the move is
   checked by tests that already passed on the old layout.
5. The usual gates: `cargo fmt --all --check`, `cargo clippy --workspace
   --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`,
   plus the CI clean-room and upgrade jobs.

A child module can use its parent's private items, so most `impl` blocks can
move into child modules of the file they leave without any visibility change
on the struct's fields. This is what keeps the splits below mechanical.

## Order, lowest risk first

### 1. `lablink-cli/src/main.rs` (lowest risk)

A binary crate with no library API. All behaviour is reached through the
binary, and `tests/cli.rs`, `tests/sites.rs`, `tests/setup.rs` and
`tests/complete.rs` run it end to end. Sibling modules already use
`crate::{Fail, R, print_json, resolve_target, shown}`.

| Lines (approx.) | Content | Proposed module |
|---|---|---|
| 27-519 | `Cli`, `Cmd` (about 430 lines of clap definitions), `Shell`, `SiteAction`, value parsers | `cli_def.rs` |
| 537-604 | `Fail`, `R`, `print_json`, `color_exit` | `fail.rs` (re-exported at the crate root, so `crate::Fail` keeps working) |
| 605-780 | `main`, `launch_gui`, `adopt_hostname_hint`, `command_name` | stays in `main.rs` |
| 781-1475 | `run`: one match dispatching every command | stays in `main.rs`, shrinking as arms move to command modules |
| 1476-1557 | `resolve_target`, `shown`, `describe_identity` | `target.rs` |
| 1558-1767 | `cmd_ssh`, `cmd_exec` | `remote_cmds.rs` (next to `scp_cmds.rs`) |
| 1768-1943 | `cmd_forget`, `cmd_remove`, `cmd_trust` | `trust_cmds.rs` |

**Guardrails before moving:** a test that snapshots `lablink --help` and
`lablink <cmd> --help` for every subcommand, and the bash completion script,
so a moved clap attribute cannot change the interface unnoticed. The JSON
and exit-code behaviour is already covered by the CLI tests.

**Risk:** `cmd_trust`, `cmd_ssh`, `cmd_exec` and `describe_identity` show
the identity state before a connection, and `cmd_exec` handles stdin and
signals. Move them whole, in their own step, after the clap move.

### 2. `lablink-gui/src/app.rs`

Only `App` and `App::new` are public (used by `main.rs`). Almost everything
is `impl App` using `&mut self`, so it splits into `app/*.rs` child modules
holding further `impl App` blocks, with no field visibility change. Check
for names that clash with the existing sibling modules (`files`, `flow`,
`health`, `onboarding`, `scan`, `settings`, `term`, `theme`, `view`,
`wizard`, `worker`).

| Lines (approx.) | Content | Proposed module |
|---|---|---|
| 30-119 | UI state types: `Tab`, `SiteView`, `AdoptDialog`, `RemoveDialog`, `TrustPanel`, `RunPanel`, `TestSsh`, `removal_consequences` | `app/state.rs` |
| 120-600 | `App` struct, `new`, actions, `drain_events`, `handle` | `app/mod.rs` |
| 601-1170 | top-level panels: `top_bar`, `sidebar`, `daemon_down`, `device_list`, `site_selector`, `site_header`, `all_sites_view`, `getting_started`, `details` | `app/panels.rs` |
| 1173-1826 | device detail sections: `details_body`, `explanation`, `test_ssh_section`, `history_section`, `edit_section`, `run_section` | `app/details.rs` |
| (same range) | `trust_section`, `remove_window`, `scan_window` | `app/dialogs.rs` |
| 1827-2251 | `discovered_view`, `adopt_window`, `discover_window`, `sites_tab`, `settings_tab`, `settings_actions` | `app/tabs.rs` |
| 2253-2407 | `impl eframe::App` | `app/mod.rs` |
| 2408-2820 | free rendering helpers (`card`, `dot`, `info_grid`, `event_list`, `service_banner`, `files_device_*`, ...) | `app/widgets.rs` (`pub(super)`) |

**Guardrails before moving:** the four inline tests (start result, removal
dialog, Files selector and Files actions) move with the code they test.
Add a headless render smoke test that runs one frame of `App` for each
`Tab` and each dialog open, against a fixture snapshot, so a missed call
shows up as a panic or a missing widget rather than only by eye. Re-run the
capture scripts (`scripts/capture-*-gui.py`) and compare against the
previous screenshots.

**Risk:** low for security (the daemon enforces trust; the GUI only asks).
`files_device_ready` / `files_device_refs`, which gate the Files actions on
a verified identity, move together with their test.

### 3. `lablink-core/src/config.rs`

About 60 public items used across crates
(`Config`, `ConfigError`, `SiteConfig`, `NetworkConfig`, `valid_*`,
`site_id_from_name`, `device_id`, ...). `config.rs` becomes `config/mod.rs`
with explicit `pub use` of every item that is public today (no glob, so the
list is reviewed).

| Lines (approx.) | Content | Proposed module |
|---|---|---|
| 21-445 | data types: `Config`, `RawConfig` + `TryFrom`, `SiteConfig`, `Preferences`, `DaemonConfig`, `SshConfig`, `NetworkConfig`, `DeviceConfig`, `Availability`, `ServiceCheckConfig` | `config/types.rs` |
| 446-617 | `ConfigError`, `ssh_option_problem`, `check_yaml_nesting` | `config/error.rs` and `config/limits.rs` |
| 618-1043 | `load`, `parse`, `validate`, `allowlist`, `to_yaml`, `prune`, text helpers, accessors | `config/io.rs` |
| 1044-1297 | `validate_site` | `config/validate.rs` |
| 1298-1553 | `device_id`, `split_ref`, `DeviceConfig` helpers, the `valid_*` / `normalize_*` field validators, `valid_ssh_option`, `valid_ssh_host_alias` | `config/fields.rs` (pure functions, the cleanest split) |
| 1527-2102 | about 40 inline tests | split by the module they exercise |

**Guardrails before moving:** every rule here is a security control:
`ssh_option_problem` and `valid_ssh_option` (host-key bypass, code loading,
forwarding, environment and weakening options), `valid_ssh_host_alias`,
`valid_ssh_identity_path`, the YAML nesting and file-size limits in `load`,
`valid_notes` (terminal escapes), `valid_program`. They are well covered by
inline tests (`host_key_bypass_options_rejected`,
`code_loading_forwarding_and_env_options_rejected`,
`weakening_ssh_options_rejected`, `ssh_binaries_and_options_cannot_inject`,
`deeply_nested_yaml_is_refused_quickly`, `oversized_config_is_refused`,
`notes_with_terminal_escapes_are_refused`). Before moving, add one
table-driven test in `tests/` (the public API only) that feeds a corpus of
rejected configurations and asserts each is still rejected with the same
`ConfigError`; it must pass unchanged before and after every step.

**Risk:** medium. A moved validator that stops being called would silently
drop a rule; the external corpus test is what catches that. Move
`fields.rs` first (pure, no callers change), `validate_site` last.

### 4. `lablink-daemon/src/registry.rs` (highest risk)

One `Registry` struct (lines 515-560) with methods in about six `impl`
blocks, holding host-key pinning, identity verification, trust, adoption,
gateway routing and site decisions. There is no lock inside it (the
`Mutex<Registry>` is in `state.rs`), so moving code does not change locking.
External users: `monitor.rs` (`CheckPlan`, `ProbeReport`, `UserKnown`,
`usable_address`), `daemon.rs` (`Registry`, `EVENT_RING`), `state.rs`,
`discovery.rs` (`usable_address`), `tests/identity_attacks.rs`
(`ProbeReport`, `Registry`, `UserKnown`), `tests/sites.rs` (`DeviceRecord`,
`PinnedKey`). All stay reachable through `registry/mod.rs`.

| Lines (approx.) | Content | Proposed module |
|---|---|---|
| 57-158, 160-480 | persisted records (`PinnedKey`, `AddressRecord`, `Overrides`, `DeviceRecord`, `DiscoveredRecord`, `ServiceSlot`) and the runtime `Device` | `registry/model.rs` |
| 481-514 | `CheckPlan`, `ProbeReport`, `FollowUp` | `registry/probe_types.rs` |
| 515-1100 | `Registry` struct, `new`, `restore`, lookups, events, snapshot | `registry/mod.rs` |
| 1108-1500 | probe scheduling and application (`plan`, `apply_probe`, `follow_up`, `learn_mac`, `release_ip`) | `registry/probing.rs` |
| 1502-1940 | identity, keys and auth (`apply_keys`, `trust_from_user_known_hosts`, `key_proof_*`, `apply_key_proof`, `apply_auth`, `address_shared_with`) | `registry/identity.rs` |
| 1941-2264 | `observe`, `attach` | stays in `mod.rs` (it writes devices, discovered and sites together; the least separable part) |
| 2265-2705 | discovered table, scan memos, read views (`status`, `inspect`, `history`) | `registry/views.rs` |
| 2706-3180 | resolve and trust (`resolve_inner`, `known_hosts_entries`, `trust`, `trust_target`, `forget`) | `registry/trust.rs` |
| 3181-3530 | mutation and adoption (`set`, `apply_changes`, `adopt`, `validate_changes`, dirty tracking) | `registry/adopt.rs` |
| 3534-3780 | free helpers (`usable_address`, `private_address`, `key_views`, `touch_address`, `host_key_alias`), services, gateway routing, `UserKnown` | `registry/util.rs`, `registry/gateway.rs` |
| 3781-4234 | sites (`restore_sites`, `local_signals`, `refresh_sites*`, `decision`, `sites_report`) | `registry/sites.rs` |
| 4230-4698 | 7 inline tests (sites, scan memos) | with `sites.rs` / `views.rs` |

**Guardrails before moving:** the trust and adoption paths have no inline
unit tests and are covered only through the daemon and CLI integration
tests and `tests/identity_attacks.rs`. Before the first move, add
characterization tests at the `Registry` API level for: trust of a new
device (preview, confirm), refusal when a pinned key changes (mismatch is
RED and never resolves), `forget`, adoption into a site, `resolve` refusing
an unverified address, a gateway route through an unreachable gateway, and
`restore` of a persisted registry. Each must pass on the current layout.

**Risk:** high. Order the moves from least to most security-relevant:
`model.rs` and `probe_types.rs` (types only), `util.rs`, `views.rs`,
`sites.rs`, `gateway.rs`, `probing.rs`, `adopt.rs`, then `identity.rs` and
`trust.rs` last, each in its own pull request with a second reviewer. Never
move `identity.rs` and `trust.rs` in the same pull request.

## What this plan does not do

- No behaviour, naming, API or performance changes, and no new
  abstractions: those come later, one at a time, once each piece is small
  enough to review.
- No change to the CLI contract: JSON, exit codes, flags ([AUTOMATION.md](AUTOMATION.md)).
- No splitting of other files; `lablink-gui/src/files.rs` (about 1,700
  lines) is the next candidate once these are done.
