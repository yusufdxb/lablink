# Files architecture

Files is a native Linux workspace for local browsing and SFTP transfers. The GUI owns rendering, selection, drag-and-drop, conflict decisions and queue presentation. The `lablink-files` crate owns filesystem validation, transfer planning, OpenSSH transport and bounded background workers. The daemon owns device resolution and pinned SSH identities.

## Connection and identity

The Files worker requests a compatible daemon build and Files protocol before resolving a device. Resolution must return a verified site-aware identity, a host-key alias and a private known-hosts file. The daemon refuses ambiguous references and host keys shared by multiple device registrations. The worker stores the complete resolved route and a digest of the trust file; observed route/trust changes latch refusal until a new connection is explicitly created.

OpenSSH performs SSH authentication, host-key validation and gateway forwarding. `russh-sftp` parses SFTP v3 packets on the child process's stdin/stdout. No remote shell command manipulates transfer paths. Files uses a fresh noninteractive connection, disables ControlMaster reuse, agent/X11/port forwarding and LocalCommand, and gives the pinned host-key options precedence over inherited settings. The private process group is terminated on transport abort/drop, including a gateway process.

The worker revalidates identity throughout copies and conflict waits. The periodic monitor also runs while SFTP I/O stalls. Revocation stops subsequent work when observed; it does not reverse operations already accepted by a remote server.

## Worker and resource model

Browsing and transfers use separate fixed background threads and current-thread Tokio runtimes. Browsing therefore remains available while a transfer waits for a conflict decision. Transfers are serialized within one worker; independent workers or applications can still run concurrently. Channels have bounded capacities, progress is coalesced in a shared snapshot, and item diagnostics are bounded. Overflow is reported and never silently grants a conflict decision.

Planning limits the complete recursive tree to 50,000 entries and depth 128. Packet sizes and requests are bounded. Transfer data and verification rereads use 32 KiB chunks. Filenames are treated as data, validated as single components, and never interpolated into shell text. Control/bidi characters, traversal components, oversized names and non-UTF-8 local names are refused. Symlinks and special files are skipped in recursive transfers.

## Local filesystem operations

Explicit local roots are canonicalized and opened as directory capabilities after checking object identity. Child directories are opened without following symlinks. Files use no-follow opens and must be regular files. Directory capabilities prevent a later ancestor-path replacement from redirecting operations into another tree.

Downloads stage data in an exclusively created random directory with mode 0700 and a regular `payload` file with mode 0600. Local staging holds both directory and file handles. Identity checks detect persistent replacement of the stage directory or payload. The destination directory uses a nonblocking advisory lease to coordinate cooperating writers.

Local publication uses an atomic no-overwrite rename through the pinned source and destination directories. Linux uses `renameat2(RENAME_NOREPLACE)`; the corresponding source implementation for macOS uses `renameatx_np(RENAME_EXCL)`. These operations preserve an existing destination. The local UID is trusted: advisory locks and private modes do not isolate a hostile process running as that UID, and check-then-rename/unlink does not provide expected-inode compare-and-swap semantics.

## Remote filesystem operations

Remote roots are normalized absolute paths. The worker uses LSTAT on ancestors and REALPATH to detect persistent symlinks or path changes. Download sources must already use normalized absolute spellings so ancestor validation describes the same path later passed to OPEN.

SFTP v3 provides pathname operations and file/directory handles, but the selected protocol has no directory-relative no-follow OPEN, expected-inode publication, conditional unlink or destination compare-and-swap replacement. Remote path checks therefore cannot pin the tree against untrusted concurrent mutations.

Uploads require the negotiated OpenSSH hardlink and fsync extensions. They exclusively create a random mode-0600 staging entry, write through the returned handle, recheck the local source and its hash, fsync the staging handle, then verify staged bytes through both the held handle and the staging pathname. Publication creates a new destination hardlink. No rename fallback is permitted. An existing destination is never intentionally replaced.

The hardlink request takes source and destination pathnames, not a staging handle. Repeated checks detect persistent substitution but cannot eliminate the final pathname race. Downloads similarly cannot establish the original source's inode identity across LSTAT and OPEN. The security review describes demonstrated attacks and the supported stable-path boundary.

## Conflict and publication states

File conflicts offer Skip and Keep Both; replacement is refused because expected-destination compare-and-swap is unavailable. A directory Replace decision means explicit merging into an existing directory of the matching type. Existing child files still receive individual conflict handling. Remote rename remains refused because its source/destination ownership and no-clobber behavior cannot be guaranteed under the required races.

Publication state is separate from job success:

| State | Meaning |
|---|---|
| NotRequested | No publication request for the current staged file has been dispatched. |
| Requested | Publication may execute, but no confirming result has been recorded. |
| Confirmed | Publication was acknowledged; the complete file remains even if later finalization/cancellation fails. |
| Uncertain | Publication was dispatched and its outcome cannot be established from the reply/error. Refresh and inspect the destination before retrying. |

Recursive transfers publish each file independently. They are not transactional: confirmed files and created directories can remain after a later failure. Cancellation before publication prevents the normal copy path from publishing that staged file. Cancellation after confirmed publication reports the completed-file count; it does not remove published data. A lost response after a remote commit is inherently ambiguous.

## Staging lifecycle

Remote staging names are retained deliberately. Successful publication leaves a second hardlink to the same inode. Cancellation, permission errors, connection loss or other prepublication failures can leave partial unpublished data. The session ledger records a creation-unconfirmed candidate before OPEN is sent. A successful reply advances it to Created. Publication dispatch advances it to PublicationRequested, then Published on acknowledgement or PublicationUncertain on error. An interrupted in-flight request remains unconfirmed or uncertain. These states describe observations, not inode ownership. Unexpected process exit loses this in-memory ledger. Diagnostics are evidence for inspection, not authority to delete.

Remote cleanup performs no REMOVE requests. LSTAT, mode, size, UUID-shaped names and content hashes cannot establish conditional unlink ownership against pathname substitution. Prefix scanning and automatic garbage collection are prohibited. A matching reserved name is skipped during recursive planning, never treated as deletion authority.

Local staging attempts nonrecursive cleanup through pinned directory capabilities and persistent inode checks. A replaced payload/directory is retained. The transfer attaches a bounded diagnostic reporter before using the local stage. Failed inspection, unproven identity and removal failures are visible in item diagnostics. Cleanup failure does not replace the original transfer outcome or revoke acknowledged publication. The same-UID check-to-delete window is outside the trusted-local-account boundary.

## Integrity and durability

SHA-256 rereads and metadata checks detect many interrupted, corrupted and persistently modified transfers. They do not authenticate data against a compromised server or provide an immutable source snapshot under a coordinated writer. SSH host authentication authenticates the endpoint, not its filesystem contents.

Payload fsync precedes publication. No parent-directory fsync guarantee is established for the destination name, so success is not a promise of power-loss-durable namespace publication. Platform behavior, remote storage and network filesystems require separate qualification.

GUI preferences are a private bounded JSON document for appearance and remembered locations. They contain no passwords, host keys or network addresses. Saving writes an exclusive mode-0600 temporary file before replacing the preference file. Production device configuration and SSH trust remain separate.
