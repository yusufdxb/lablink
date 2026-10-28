# Files security review

This document describes the implemented controls and the remaining Files/SFTP limits. A passing exploit-reproduction test proves a boundary failure; it is not evidence that the attack is mitigated. The validation document maps conclusions to named tests.

## Supported threat boundary

The local account, its configuration, pinned keys, programs and environment are trusted. Root and hostile processes running as the same local UID are not isolated by LabLink. Directory capabilities, private modes and advisory leases reduce accidental and persistent substitution risks, but do not provide conditional leaf mutation against that UID.

SSH authenticates the pinned remote endpoint. A compromised authenticated server can lie about attributes and bytes. Strong filesystem-integrity guarantees also require that untrusted processes cannot mutate selected remote source/destination entries or their ancestors during the transfer. This includes untrusted same-UID processes and other users granted parent-directory write authority. A mode-0600 staging file does not prevent an authorized directory writer from renaming its entry.

Within stable remote paths, Files protects existing destinations from intentional replacement, rejects persistent symlinks and unsupported publication servers, verifies copied bytes, and distinguishes incomplete, confirmed and uncertain publication. It does not provide race-free containment, original remote inode identity, immutable snapshots, atomic file replacement or crash-durable destination naming.

## Confirmed vulnerabilities

### Resolved: untrusted remote status messages in browsing errors

The original browsing worker used `to_string()`, allowing an authenticated SFTP server's arbitrary status message to reach the UI. A crafted browse/mkdir failure could display misleading text or bidi/control characters; no execution or SSH bypass was established.

Browsing now uses the same trusted status-based `user_message()` guidance as transfer errors. `browse_status_errors_hide_hostile_server_instructions` verifies that crafted status text, bidi and control characters are not rendered. This resolves the identified status-message path; it does not authenticate a remote filesystem.

## Reproduced design limitations

### Remote source-opening race

The download path checks the selected source with LSTAT, opens it by pathname, validates the path again and compares FSTAT attributes. SFTP v3 attributes do not contain inode/device identity, and OPEN has no no-follow or expected-object flag. A hostile writer can substitute a readable file/symlink around OPEN and restore the path before validation. Matching size, permissions, UID/GID and mtime allow the held substitute to pass checks and both SHA-256 reads.

Impact: unintended bytes can be downloaded and another remote-readable file can be disclosed to the client. The deterministic `documented_sftp_open_swap_restore_limit_is_reproduced` test demonstrates successful exploitation. Persistent symlink substitution is rejected by a separate test; that does not eliminate the swap-and-restore case.

Further pathname checks cannot establish the missing atomic identity condition. Ordinary SFTP cannot enforce the required property through the selected operations. Do not claim this race is fixed without a different trusted protocol/component or a changed filesystem trust boundary.

### Remote final-publication race

Uploads verify the original staging handle, then verify the staging pathname's contents and attributes. Publication uses `hardlink@openssh.com(oldpath, newpath)`. This extension accepts paths rather than a held source handle. A hostile writer can replace the staging pathname after content verification with a same-metadata substitute. A final LSTAT then matches and the wrong file is linked to the destination.

Impact: unintended bytes can be published with a successful transfer result. The deterministic `documented_sftp_last_path_swap_limit_is_reproduced` test demonstrates this behavior. The no-overwrite guarantee is separate: existing destinations remain protected by a compliant hardlink implementation.

Hashing or checking again narrows one window while creating another. Persistent substitutions detected before publication do not prove last-window containment. Retain the restriction against unsafe remote rename and file replacement.

### Retained remote staging

Remote cleanup deliberately issues no REMOVE requests. Success leaves an additional hardlink to the published inode; cancellation and failure can leave partial or complete unpublished data. The extra successful link keeps file blocks alive if the destination name is later deleted. Failed stages consume disk until manually inspected and safely removed by the owner/administrator.

REMOVE takes only a pathname. Checking attributes, a UUID, a prefix or a content hash before REMOVE cannot make deletion conditional on the object that was checked. Automatic cleanup could delete a substituted unrelated entry. No available client-only operation proves safe unlink against hostile writers. Do not automatically delete existing staging evidence or scan reserved names for collection.

Stage diagnostics are bounded and held in memory. Creation candidates are recorded before OPEN, so lost replies retain an explicit creation-unconfirmed diagnostic. Candidates can be absent or unrelated, and are never counted as acknowledged creations. Process termination can still leave unknown stages. Even a known diagnostic path is not deletion authorization. Retention is a deliberate safety limitation, not successful garbage collection.

### Publication and cancellation ambiguity

After a publication request is dispatched, connection loss/cancellation can occur after the server committed but before the client observed the reply. The outcome is Uncertain. After acknowledged publication, cancellation/finalization failure retains the confirmed complete destination. Recursive jobs publish per file and are not rolled back as a transaction. Created folders and confirmed files can remain after later failure.

The UI must expose uncertainty and completed-file counts. A failed/cancelled job must not imply destination absence. Inspect the destination before retrying; never replace it automatically.

## Theoretical risks

| Risk | Prerequisites and impact | Guarantee boundary |
|---|---|---|
| Local check-to-rename/unlink races | A hostile same UID substitutes a leaf after an inode check; unrelated names could be published or deleted. | Local UID trusted; current tests prove persistent substitution handling, not conditional unlink. |
| Remote ancestor substitution | A writer mutates an ancestor between validation and an operation; reads/writes can target a different directory. | Remote directory paths are not pinned capabilities. Stable trusted path components required. |
| Coordinated edits across hash passes | Writer controls timings/content and makes both passes observe the same chosen stream. | Consistency checking is not an immutable snapshot or independently authenticated digest. |
| Crash after file fsync/publication | Local or remote host/storage loses directory updates after an acknowledged operation. | Parent-directory durability is not established by file fsync alone. |
| Revocation after final check | Trust changes after a successful guard check while a request is in flight. | Revocation stops subsequent work when observed, not effects already committed. |

These risks are source-derived gaps, not reproduced exploit claims unless a dedicated test demonstrates them.

## Coverage and observability gaps

- Local staging cleanup now reports inspection/refusal/removal failures through bounded item diagnostics. `interrupted_download_reports_failed_local_cleanup_without_deleting_foreign_entry` exercises an actual nonempty-directory removal failure and preserves the foreign entry. The reporter is attached after successful stage construction; a failure during construction can still retain a directory reported only through the construction error.
- Remote lifecycle diagnostics now distinguish creation-unconfirmed, acknowledged creation, publication-requested, published and publication-uncertain states. `lost_open_reply_reports_candidate_without_claiming_ownership_or_deleting` suppresses an actual HANDLE response after server creation and verifies worker diagnostics without deletion.
- `missing_destination_directories_fail_before_staging_or_publication` covers absent local and remote destinations.
- `lost_publication_reply_reports_uncertainty_with_complete_destination` suppresses the actual hardlink status reply after server commit. It proves Uncertain reporting while the complete destination remains.
- Unexpected process termination and post-crash recovery differ from controlled transport loss and child reaping tests.
- No remote cleanup operation exists. `remote_remove_denied_retains_successful_alias_without_cleanup_requests` proves retention on a server denying REMOVE, with a test-only denial probe. The implementation of cleanup issues no requests. This is deliberate refusal of unsafe cleanup, not successful cleanup or handling of an attempted cleanup failure.
- Actual GUI interactions, remote-storage crash behavior and platform-specific filesystem semantics require separate validation.

## Practical controls to retain

Files requires verified, unambiguous pinned identity and compatible daemon/Files protocol; a fresh SSH connection; periodic and per-boundary latched trust checks; exclusive random staging; regular-file restrictions; bounded chunks/trees/messages; byte and metadata verification; no-overwrite publication; explicit conflict decisions; refusal of file replacement; refusal of remote rename; conservative stage retention; and explicit publication uncertainty.

Narrow fixes can improve diagnostics and input sanitization without changing these restrictions. They do not resolve the demonstrated remote source or publication races. Dependency advisory checks and release qualification remain separate gates; source-level Files review alone is insufficient for public release approval.
