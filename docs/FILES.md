# Files workspace

Select a verified device on **Devices** and choose **Open Files**, or select a
site-qualified device in **Files**. Local and remote panes retain independent
paths, favorites and selection. Device identity remains `site/device` across
site switching, queued transfers and saved preferences. Onboarding, site
management, SSH setup and health checks use the existing LabLink workflow.

Use **Upload files**, **Upload folder** or **Download to folder** for native
selection dialogs. Selected files and folders can also be dragged between
panes; desktop drops request confirmation before upload. Recursive transfers
include empty files and directories. The queue shows progress, verification,
completion and actionable failures. Cancellation stops future work; retry
starts a new transfer rather than resuming an incomplete file.

Choose **True Black**, **Light** or **System Default** in Settings. The same
palette applies to navigation, device cards, onboarding, site management,
Files and transfer progress. Appearance and per-device browser preferences
are saved in the user state directory.

## Compatibility and trust

The GUI and daemon must be compatible LabLink builds and the daemon must
advertise the Files protocol. Unsupported daemons refuse remote Files access
with a visible error; local browsing remains available. Files uses the released
site-aware resolver and verified OpenSSH host pins, including every gateway.
A key shared by multiple tracked identities is refused for Files.

SFTP uses a fresh noninteractive OpenSSH connection, without forwarding or
reused control sockets. LabLink owns host verification and authentication;
the SFTP parser does not maintain a second SSH trust store. Unknown keys,
mismatches and unavailable authentication must be resolved through the normal
explicit trust and SSH setup workflow. Files never stores passwords or installs
credentials automatically.

## Conflicts, verification and limits

**Skip**, **Keep Both** and cancellation are supported for existing destinations.
File replacement and remote browser rename are refused. Verified bytes are
staged before publication and checked with SHA-256. Upload publication requires
the server's OpenSSH hardlink and fsync extensions; there is no unsafe rename fallback.
Local publication uses capability-based directory access and no-clobber
operations. Recursive transfers are not transactional: completed siblings and
created directories can remain after a later failure.

Remote staging files are retained, including successful hardlink aliases and
interrupted partial uploads. No prefix-based cleanup is attempted. Remove them
only when their ownership and lack of active use are independently established.
Cancellation or trust revocation cannot undo already acknowledged server writes
or publication. Trust is checked periodically and is not an instantaneous lease.

SFTP v3 cannot bind pathname checks atomically to file handles or publication.
A hostile same-UID remote writer can swap a source around OPEN or substitute a
stage after verification and before hardlink publication. Metadata and hash
rereads narrow these windows but do not guarantee snapshot integrity or path
containment against that actor. Local permissions and advisory locks likewise
do not constrain hostile same-UID or root namespace mutation. These limitations
are covered by deterministic reproduction tests and remain unresolved.

Linux validation does not establish native macOS, Wayland, physical storage
exhaustion, power-loss durability or accessibility support. Refer to actual
platform qualification before using those paths for critical data.
