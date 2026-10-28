# Files validation

The automated suite uses disposable loopback OpenSSH/SFTP servers, isolated keys and temporary directories. It does not use production device filesystems. Each server is pinned with a generated fixture key; the tests verify that inherited settings cannot weaken that pin.

This document describes the commands and assertions provided by the source. It does not assert that a particular release qualification campaign passed. Test counts, failures, ignored tests, platform exclusions and rendered GUI evidence belong in that campaign's execution record.

## Build and security gates

Run from the repository root with the recorded Rust toolchain and committed Cargo.lock:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
LABLINK_REQUIRE_SFTP_TESTS=1 cargo test --locked --workspace
cargo build --locked --release --workspace
cargo deny check
cargo audit --deny warnings
```

The `LABLINK_REQUIRE_SFTP_TESTS` setting turns an unavailable sshd into failure. Without it, the SFTP fixture can print SKIP and return early while Rust reports the enclosing test as passed. Record fixture availability and executed assertions. Dependency advisory gate failures must be reported without loosening policy solely to obtain a passing result.

Targeted Files commands:

```sh
LABLINK_REQUIRE_SFTP_TESTS=1 cargo test --locked -p lablink-files --test sftp
cargo test --locked -p lablink-files --test safety
cargo test --locked -p lablink-files --test compatibility
```

Linux syscall fault tests execute in isolated child processes and inject actual write/fsync errors. Other platforms do not establish those Linux results. The Unix mode-permission assertion in `permission_errors_and_conflict_wait_cancellation` is skipped when the test process runs as root; protocol permission-denial tests provide separate evidence.

Repository cleanroom and upgrade scripts exercise container/package deployment scenarios. Run them only in their intended disposable environments. They must not install over or restart an existing primary installation to satisfy a development test.

## Transfer and filesystem evidence

| Case | Named tests | Proof boundary |
|---|---|---|
| Recursive round-trip, Unicode/shell-like names, empty files/folders, symlink skipping | `bidirectional_recursive_bytes_names_empty_files_and_symlinks` | Real fixture SFTP byte equality and planning behavior; no shell manipulation of transfer names. |
| Conflict decisions and no-overwrite | `explicit_collisions_both_directions_and_no_clobber_rename`, `recursive_folder_merge_and_keep_both_are_explicit`, `changed_destination_after_conflict_does_not_overwrite` | Skip/Keep Both preserve existing bytes; file Replace and remote rename refused; explicit directory merge. |
| Independent/concurrent writers | `concurrent_sftp_sessions_publish_one_complete_winner`, `independent_writer_and_symlink_win_without_being_overwritten`, `failed_publication_is_uncertain_and_never_removes_competing_file` | One complete no-overwrite winner or preexisting writer preserved; no deletion of competing files. |
| Local capabilities and leases | `local_capabilities_refuse_ancestor_symlinks_and_traversal`, `capabilities_do_not_follow_a_substituted_parent_into_a_decoy`, `directory_leases_conflict_in_process_and_across_processes` | Pinned directory operations and cooperating-writer locks; no same-UID hostile isolation claim. |
| Local persistent stage substitution | `staging_cleanup_preserves_substituted_payload_and_directory`, `failed_exclusive_creation_and_publication_preserve_existing_files`, `local_staging_content_edit_is_refused_before_publication` | Existing/substituted entries retained or publication refused when changes are visible before checks. |
| Directory replacement | `source_changes_with_restored_mtime_and_directory_substitution_are_refused`, `newly_created_and_existing_local_destination_directory_swaps_are_refused` | Persistent local source/destination directory replacements detected. |
| Remote symlinks and ancestors | `remote_symlink_ancestors_and_destination_links_refused`, `persistent_remote_ancestor_swaps_after_conflict_and_source_open_are_refused`, `noncanonical_download_source_cannot_hide_a_symlink_ancestor` | Persistent path substitutions and noncanonical source spellings refused. |
| Local/remote source edits | `replaced_source_after_planning_is_refused_before_copy`, `source_changes_with_restored_mtime_and_directory_substitution_are_refused`, `growing_and_truncated_sources_in_both_directions_are_refused` | Selected persistent inode/size/content changes detected; no immutable snapshot guarantee. |
| Persistent remote source symlink | `persistent_symlink_substitution_of_remote_source_is_refused` | Visible post-open pathname substitution refused before payload bytes. |
| Remote source race remains | `documented_sftp_open_swap_restore_limit_is_reproduced` | Successful unintended-source transfer is reproduced. Passing means the limitation remains observable. |
| Persistent remote stage edits | `same_metadata_remote_staging_substitution_is_refused` | Pathname hash detects persistent substitutions before final publication checks. |
| Remote publication race remains | `documented_sftp_last_path_swap_limit_is_reproduced` | Successful unintended-byte publication is reproduced. Passing is not mitigation. |
| Remote staging retention | `remote_staging_collision_and_substitution_never_authorize_cleanup`, `server_write_and_fsync_refusals_never_publish_and_retain_staging` | No unsafe deletion of stage candidates/substitutes; failed stages retained. |
| Unsupported extensions/rename | `missing_publication_extensions_are_refused_before_writing`, `unsafe_server_rename_is_reproduced_and_files_refuses_it` | Upload/rename refuse instead of unsafe fallback; direct unsafe-server behavior is distinct from Files behavior. |

## Interruptions, faults and identity evidence

| Case | Named tests | Proof boundary |
|---|---|---|
| Cancel before/after publication | `cancellation_at_commit_boundaries_reports_confirmed_publication`, `download_cancellation_at_publication_boundaries_preserves_confirmed_status`, `cancellation_and_retry_preserve_destination_and_cleanup_staging` | Cancellation states and retained confirmed files; safe retry with explicit conflict handling; remote partial stage retention. |
| Transport interruption | `transport_loss_mid_copy_never_publishes_partial_file`, `disconnection_during_operation_is_an_error` | Before-publication loss produces error without partial destination. No power-loss durability claim. |
| Actual protocol denial | `server_write_and_fsync_refusals_never_publish_and_retain_staging` | Real server write/fsync permission statuses block publication. |
| Local storage faults | `actual_local_write_failure_in_isolated_child_never_publishes`, `kernel_injected_local_enospc_never_publishes`, `kernel_injected_local_fsync_eio_never_publishes` | Actual selected kernel errors prevent publication. |
| Synthetic boundary faults | `scheduled_io_faults_never_publish_partial_files` | Transfer error handling at scheduled checkpoints; distinguish from actual syscall/protocol fault tests. |
| Host-key pin | `unavailable_subsystem_and_pinned_key_mismatch_fail_closed` | SFTP unavailable or incorrect pinned identity refuses connection. |
| Trust/route resolution | `changed_trust_and_daemon_ambiguity_stop_transfers`, `trust_change_during_conflict_wait_prevents_publication`, `trust_revoked_after_copy_starts_preserves_old_destination`, `host_key_file_changes_during_both_directions_stop_before_publication`, `trust_refusal_is_latched_even_after_state_is_restored` | Observed changes refuse and latch, preserving existing destination bytes. |
| Inherited SSH settings | `files_connection_refuses_inherited_local_command`, `spaced_known_hosts_path_cannot_add_an_unpinned_trust_file`, `inherited_known_hosts_command_cannot_bypass_a_wrong_pin` | Selected command and alternate-trust bypasses blocked by actual OpenSSH. |
| Compatibility and monitoring | `old_daemon_refusal_explains_matching_daemon_requirement`, `incompatible_security_build_is_refused_before_resolution`, `slow_valid_identity_checks_do_not_starve_transfer_or_cancellation` | Incompatible daemon refused; slow valid checks do not starve cancellation or useful work. |
| Worker pressure/teardown | `bounded_queue_cancelled_jobs_and_browsing_during_conflict`, `saturated_gui_events_refuse_conflict_without_blocking_active_transport`, `failed_connection_and_drop_reap_the_private_ssh_child` | Bounded queues, browsing independence, conflict fail-closed handling and selected child reaping. |

Daemon registry tests separately cover site-aware Files resolution, duplicate keys and mismatched identity. Existing general SSH/security tests remain required; Files tests do not replace them.

## Remaining coverage requirements

Additional hardening regressions:

| Case | Test | Evidence |
|---|---|---|
| Untrusted browse status text | `browse_status_errors_hide_hostile_server_instructions` | Trusted guidance hides server instructions, control characters and bidi text. |
| OPEN reply lost | `lost_open_reply_reports_candidate_without_claiming_ownership_or_deleting` | Real server creates a stage; a disposable transport wrapper suppresses HANDLE. Worker reports creation-unconfirmed path without claiming ownership or deleting it. |
| Stage lifecycle and cancellation | `staging_lifecycle_distinguishes_cancellation_and_publication_acknowledgement` | Created/Published stages remain diagnosable; before/after publication states preserve confirmed file integrity. |
| Publication refusal | `publication_refusal_has_uncertain_stage_diagnostic_and_preserves_competitor` | Uncertain stage diagnostic; concurrent destination bytes preserved. |
| Hardlink reply lost | `lost_publication_reply_reports_uncertainty_with_complete_destination` | Actual server publication succeeds; suppressed reply causes Uncertain reporting, zero acknowledged completions and retained complete destination. |
| Remote REMOVE denial | `remote_remove_denied_retains_successful_alias_without_cleanup_requests` | Test-only REMOVE probe is denied; LabLink cleanup remains a no-op and preserves both hardlinks. |
| Missing destination | `missing_destination_directories_fail_before_staging_or_publication` | Local/remote missing directories fail without staging or publication. |
| Local cleanup failure | `interrupted_download_reports_failed_local_cleanup_without_deleting_foreign_entry` | Actual nonempty-directory removal failure is reported; foreign evidence survives cancellation. |

Failed remote cleanup is represented as deliberate retention, since safe remote deletion is not implemented. Crash recovery, same-UID last-instruction local races and power-loss namespace persistence require distinct evidence.

## Linux GUI qualification

Use isolated development binaries, daemon socket, state/config directories and disposable transfer locations. Preserve existing production keys, pinned fingerprints, registrations and installation. Confirm the rendered True Black interface, device selection and site switching, Files activation, local/remote browsing, upload/download, recursive transfer, drag-and-drop, cancel/retry, conflict decisions and visible progress. Verify round-trip SHA-256 through independently hashed files. Exercise matching and incompatible daemon behavior.

Backend tests do not prove GUI interaction. Record actual interaction outcomes and screenshots where available, and label static widget tests, startup-only checks and inaccessible desktop sessions accurately. A small authorized remote-machine regression can supplement loopback tests, but it does not prove hostile-filesystem containment or all GUI cases. No updated binary should be deployed as part of development qualification.

## Result interpretation

Report exact command outcomes, executed test counts, failures, ignored tests, fixture skips, platform exclusions and compiler warnings. Keep security limitations separate from mitigation regressions. Record the source commit, Cargo.lock hash, toolchain and features for any clean-checkout build. Binary equality requires matching hashes; a repeatable build with different hashes is source/build reproducibility evidence, not bit-for-bit reproduction.
