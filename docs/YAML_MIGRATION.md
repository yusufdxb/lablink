# YAML parser maintenance migration (issue #13)

This source change replaces `serde_yaml_ng 0.10.0` with `yaml_serde 0.10.7`, the maintained YAML-organization fork with a compatible Serde YAML API.

The transitive parser is now `libyaml-rs 0.3.0`, rather than archived `unsafe-libyaml 0.2.11`. **This is not a safe-Rust parser rewrite:** `libyaml-rs` also contains unsafe Rust translated from C, but it is maintained by the YAML organization. The specific RUSTSEC-2024-0449 *unmaintained dependency* advisory is addressed only when the old crates disappear from the resolved graph; this is not evidence of general memory safety.

Compatibility requirements:
- Preserve released configuration schema and the legacy single-site layout.
- Keep unknown-field rejection, semantic validation, file size and nesting limits.
- Preserve atomic save/import behavior and explicit host-key trust rules.
- Parse, serialize and reparse released examples with semantic equality.
- Keep export/import behavior for escaped strings and security-sensitive fields.
- Reject duplicate mapping keys and multiple YAML documents, not silently discard data.

Regenerate Cargo.lock and THIRD_PARTY_LICENSES.md from the resolved dependency graph; pass full workspace tests, cleanroom checks, cargo deny, cargo audit and CLI/GUI integration tests before merge. No audit exception should remain.

**Release scope:** the public v0.3.1 binary remains unchanged. Source migration does not alter a previously published package. To ship the new parser to users, build and qualify a subsequent release.
