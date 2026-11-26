# Compatibility policy

Scripts, runbooks, preflights and AI agents call `lablink` unattended. This
page says what they may rely on, what a release may change, and how the
version number tells them.

## The CLI contract

These are the contract. A change to any of them that can make an existing,
documented invocation behave differently or fail is a **breaking change**.

| Area | What is covered |
|---|---|
| Commands and flags | Command and subcommand names, flag names and short forms, what each flag means, its default, and which flags conflict. |
| Argument placement | Which positionals a command takes and in what order; where options may appear; what `--` means (for `ssh` and `exec`: everything after it is the remote command, placed after the destination). |
| stdin, stdout, stderr | Whether a command reads stdin and when (`exec` forwards piped stdin; `ssh -n` and terminal rules), what goes to stdout and what to stderr, and that `--json` puts exactly one JSON document on stdout. |
| JSON output | `schema_version`, every documented field: its name, type and meaning, and the `status` / `error.code` strings ([AUTOMATION.md](AUTOMATION.md#json-shapes-schema_version-1)). |
| Exit codes | Every code in [AUTOMATION.md](AUTOMATION.md#exit-code-contract) and `lablink_core::exit`, including pass-through of remote exit codes by `exec` and `ssh`. |
| Configuration | Every key that loads today keeps loading with the same meaning. |
| Environment variables | `LABLINK_CONFIG`, `LABLINK_STATE_DIR`, `LABLINK_SOCKET` and the XDG fallbacks. |
| State on disk | The state dir layout callers may touch: `known_hosts`, `update-hold`. |
| Installer | `scripts/install-linux.sh` options, exit codes, and that it never downgrades. |

**Not** part of the contract: human-readable text, colors and table layout,
log messages, timings, the desktop app's layout, the daemon socket protocol
between matching CLI/daemon builds (it carries its own `PROTOCOL_VERSION`),
and anything marked hidden or "testing" in `--help`.

## What may change in which release

LabLink uses `MAJOR.MINOR.PATCH`.

- **Before 1.0** (now): a breaking change bumps the **minor** version
  (`0.4.x` to `0.5.0`). A patch release (`0.4.x` to `0.4.y`) contains only
  bug fixes that change no contracted behaviour, and additions.
- **From 1.0 on**: a breaking change bumps the major version.

Always allowed, in any release, because they are additive:

- a new command, a new flag, a new optional configuration key;
- a new JSON field (callers must ignore fields they do not know);
- a new `error.code` string or a new exit code for a condition that used to
  be a generic failure (1), documented in AUTOMATION.md.

Never allowed without a breaking-version bump: renaming or removing any of
the above, renumbering an exit code, changing a field's type, changing a
default, or changing what is read from stdin or where an argument goes.
**JSON fields and exit codes are added, never renamed.**

A bug fix is breaking when a caller could have written a working invocation
that the fix changes. Fixing behaviour to match the documentation does not
make it non-breaking if the old behaviour was observable and useful. When in
doubt, treat it as breaking.

**Security fixes.** If a security fix cannot be made without a behaviour
change, it may ship in a patch release, but it is listed under
`### Behaviour changes` in the CHANGELOG with the safe way to keep working,
and the release follows the checklist in
[RELEASING.md](RELEASING.md#before-every-release). Prefer making the new
behaviour opt-in for one minor release when that is safe.

**Deprecation.** Prefer adding the new form and keeping the old one working
(with a warning on stderr) for at least one minor release before removing it.

## How it is enforced

- Every breaking change gets a `### Behaviour changes` section in the
  CHANGELOG entry, written for the caller: what changed, what breaks, what to
  use instead.
- `scripts/check-compat.py` (run in CI) fails when a released CHANGELOG
  section has `### Behaviour changes` but the version only bumps the patch.
- Before any release with a `### Behaviour changes` section, known callers
  are searched and the affected ones listed in the release pull request
  ([RELEASING.md](RELEASING.md#before-every-release)).

**Known exception.** 0.4.4 shipped two behaviour changes in a patch release,
before this policy: `ssh DEVICE -- ...` placement and `exec` forwarding piped
stdin. Under this policy it would have been 0.5.0. It stays as released and
is listed as the only exception in `scripts/check-compat.py`.

## Protecting a caller

A caller that depends on one version's behaviour should not rely on nobody
upgrading the machine:

- Check the version first: `lablink version --require '>=0.4.3,<0.4.4'` exits
  0 in range and 7 outside (builds without `--require` exit 2, so stop on any
  non-zero exit).
- Hold the machine: `lablink update --hold --reason TEXT` makes
  `lablink update` and the official installer refuse until `--unhold`.

See [AUTOMATION.md](AUTOMATION.md#pinning-a-version-version---require-update---hold).
