# Device identity and SSH trust

LabLink identifies a device by its SSH host key, not by its address. This
page explains how a key becomes trusted (enrollment), how LabLink checks it
afterwards, what happens when it changes, and which part of the work is done
by OpenSSH.

## Words

- **Pin**: a host-key fingerprint LabLink accepts for one device
  (`site/name`). Pins live in the config (`host_key_fingerprints`) or in
  LabLink's state, and are written to LabLink's own `known_hosts` file under
  the alias `lablink.<site>.<name>`.
- **Verified**: the host at the device's current address presented a pinned
  key *and proved it holds the private key* (see below).
- **Mismatch**: a security stop. Nothing connects to the device until you
  replace the pin yourself.

## Enrolling a device (first contact)

1. Find it: `lablink discover`, or configure its address/hostname.
2. Adopt it (or configure it): `lablink adopt <ip> --name <name>`. This
   never pins a key.
3. Compare the fingerprint **on a channel you trust**, for example the
   device's own console:

   ```bash
   lablink trust <device>            # shows the fingerprints, pins nothing
   # on the device: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   lablink trust <device> --yes      # pin exactly what was shown
   ```

   The confirmation must name exactly the fingerprints of a fresh scan; if
   the device presents something else between the preview and the
   confirmation, nothing is pinned.
4. Optionally install your public key: `lablink copy-id <device>`. It refuses
   devices without a pin and passes LabLink's pinned host-key options to
   `ssh-copy-id`, so the password you type can only reach the verified
   machine. The password goes to OpenSSH, never to LabLink.

Other ways a key gets pinned, all explicit:

- a fingerprint you wrote in the config;
- an entry already in your `~/.ssh/known_hosts` under the device's configured
  hostname, `ssh_host` or name, or under its address when that address is a
  configured `expected_ips` entry or the address where you adopted it (within
  10 minutes). Names and addresses announced by the network (mDNS, DNS,
  learned hostnames, MAC matches) never select a known_hosts entry.

There is no automatic trust on first use. `lablink ssh` / `lablink exec` to a
device without a pin are refused (exit 7) unless you pass `--unpinned`, which
lets OpenSSH ask you as it normally would (the answer is stored in your own
`~/.ssh/known_hosts`, not as a LabLink pin).

## Verification and the possession proof

`ssh-keyscan` returns public keys, which anyone can copy and replay. So a key
that matches a pin at a new address (or right after pinning) only makes the
check due: LabLink then runs

```
ssh -o HostKeyAlias=lablink.<site>.<name> -o UserKnownHostsFile=<LabLink's file>
    -o StrictHostKeyChecking=yes -o ControlPath=none -o BatchMode=yes
    -o PubkeyAuthentication=no -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no
    -o HostbasedAuthentication=no -o IdentityAgent=none -o LogLevel=FATAL
    ... <device> true
```

OpenSSH verifies the server's signature with the pinned key during the key
exchange, before any authentication. Reaching `Permission denied` therefore
proves the server holds the private key, while LabLink offered no key, no
password and no agent. The device becomes *verified*; only then does LabLink
learn its MAC address and run login and service checks.

Text the server can send must never count as that proof: before the key
exchange a server can send a disconnect reason, and OpenSSH before 9.0 prints
it with newlines unescaped, so a fake server could print a line that looks
like the client's own "Permission denied". The proof therefore runs at
`LogLevel=FATAL` (OpenSSH logs disconnect reasons at ERROR level, so they are
not printed) and is refused whenever stderr shows a disconnect or any other
server-originated message.

| Result of the proof | Device |
|---|---|
| OpenSSH reached authentication | verified |
| a different key, or the pinned key could not sign | **mismatch** (security stop) |
| timeout, refused, connection closed | unverified, retried at the next identity check |

Once verified at an address, periodic re-checks compare keys only; a new
address, a changed MAC at the address, or a reconnect of SSH triggers a full
check again.

## When the key changes

A key that contradicts the pin, at an address the device is known by (its
static IP, its MAC, a name that resolved to it), is a **mismatch**: RED,
recorded once, and `ssh`, `exec`, `resolve`, `copy-id` and all background
checks refuse. Losing the address does not clear it; only the pinned key
proven again, or your explicit decision, does.

If the device was really reinstalled or its keys rotated:

```bash
# on the device's console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
lablink trust <device> --replace     # shows old and new, asks
```

Fingerprints written in the config cannot be replaced at runtime; edit the
config.

An unknown key at an address the device merely *used* to have (DHCP gave it
to another machine) is not a mismatch: LabLink releases the address and lists
the newcomer as discovered, without connecting to it.

## Several sites

Pins belong to `site/name`: two sites can each have a device `jetson` with
different keys, and the alias `lablink.<site>.<name>` keeps them apart in one
known_hosts file. A bare name resolves only when it is unique, or when
exactly one site is confidently active; otherwise the command is refused
(exit 8) and lists the `site/name` choices. Devices of an AWAY site are
refused by `ssh`/`exec`/`resolve` unless `--force`.

## What `lablink resolve` gives you

`lablink resolve <device>` prints the device's address only when its identity
is verified at that address (exit 7 otherwise, `--force` to print it anyway).
Tools you give the address to (`scp`, `rsync`, plain `ssh`) do not use
LabLink's pin; prefer `lablink ssh`/`lablink exec`, or pass the same options:

```bash
lablink resolve <device> --json   # host_key_alias and known_hosts_file
```

## What OpenSSH and the OS do, not LabLink

- Key exchange, signature checks and all authentication: OpenSSH.
- Command-line options take precedence over `~/.ssh/config`; LabLink relies
  on this for its host-key options.
- An existing ControlMaster connection you opened is reused by OpenSSH
  without a new key exchange (see `ssh.reuse_control_master` in
  [SECURITY.md](../SECURITY.md#known-limitations)).
- Anyone who can act as your user (or root) can edit LabLink's pins.
