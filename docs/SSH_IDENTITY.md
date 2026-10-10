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
   lablink trust <device> --fingerprint SHA256:...   # pin exactly that key
   ```

   Only the keys you name are pinned, and only if a fresh scan still shows
   them; if the device presents something else by then, nothing is pinned.
   Answering `y` at the interactive prompt pins exactly the keys it showed.
   `--yes` without `--fingerprint` pins whatever the device presents at that
   moment (trust on first use): use it only where nothing can stand in for
   the device between your check and the command. LabLink prints every key
   it pins.
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
  learned hostnames, MAC matches) never select a known_hosts entry. With
  more than one site, `~/.ssh/known_hosts` is not consulted at all for an
  address that another site's networks also contain (or that is outside this
  site's networks): a bare address or name there may belong to the other
  site's machine. Pin those devices with `lablink trust --fingerprint`.

There is no automatic trust on first use. `lablink ssh` / `lablink exec` to a
device without a pin are refused (exit 7) unless you pass `--unpinned`, which
lets OpenSSH ask you as it normally would (the answer is stored in your own
`~/.ssh/known_hosts`, not as a LabLink pin).

## Verification and the possession proof

`ssh-keyscan` returns public keys, which anyone can copy and replay. So a key
that matches a pin at a new address (or right after pinning) only makes the
check due: LabLink then opens a TCP connection to that address itself (or
starts the gateway hop) and runs OpenSSH over it:

```
ssh -F /dev/null                 # no config file: everything the proof needs is below
    -o ProxyCommand=-            # ssh speaks over stdin/stdout, LabLink carries the bytes
    -o HostKeyAlias=lablink.<site>.<name> -o UserKnownHostsFile=<LabLink's file>
    -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes
    -o KnownHostsCommand=none -o VerifyHostKeyDNS=no -o UpdateHostKeys=no
    -o ControlPath=none -o BatchMode=yes -o IdentityAgent=none
    -o PubkeyAuthentication=no -o PasswordAuthentication=no
    -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no
    -o HostbasedAuthentication=no -o GSSAPIKeyExchange=no ... <device> true
```

(`KnownHostsCommand` and `GSSAPIKeyExchange` only where the installed ssh
knows them: an option is left out only when `ssh -F /dev/null -G` answers
"Bad configuration option"; any other probe failure passes it. The proof reads
no `~/.ssh/config` or `/etc/ssh/ssh_config` at all, so nothing there can vouch
for a key or print text into its stderr; `lablink ssh`/`exec` still use your
config, behind the same pinned options. `HostKeyAlgorithms` is set first to exactly the key types pinned
for the device, read from LabLink's own known_hosts file, so a config's
algorithm list or a host certificate cannot steer the exchange to an unpinned
type; with no entry for the device the proof does not run. `ProxyUseFdpass=no`
keeps a config from disabling `ProxyCommand=-`.)

The decision is made from the bytes **LabLink's own ssh process sends**, not
from anything printed. OpenSSH sends its `SSH_MSG_NEWKEYS` message only after
the host key the server presented matched the pinned entry and the server's
signature over the key exchange, which covers ssh's fresh random key, verified
with it. Only the private key can produce that signature, so a host that
replays a public key can never make ssh send `NEWKEYS`. LabLink reads the
unencrypted packet framing of ssh's side of the first key exchange, and closes
the connection the moment `NEWKEYS` appears: no authentication is attempted
and no key, password or agent is ever offered. The server's bytes are passed
to ssh but never parsed. The device becomes *verified*; only then does LabLink
learn its MAC address and run login and service checks.

What ssh prints (stderr, `LogLevel=INFO`) is only used to explain a proof that
did not succeed, and never when it shows any sign of server text (a
disconnect, a closed connection, a negotiation error).

| Result of the proof | Device |
|---|---|
| ssh sent `NEWKEYS` | verified |
| ssh rejected the key: a different key of a pinned type, or a bad signature with the pinned one | **mismatch** (security stop) |
| the host offered no key of a pinned type | unverified, retried (the scan comparison catches contradicting keys) |
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
- The proof shows that whoever answers at the address can reach the private
  key; a machine that only relays bytes to the real device passes it. SSH
  stays secure through such a relay (it sees only ciphertext), but tools you
  give the address to without LabLink's pin options do not get that
  protection.
- OpenSSH 9.8+ servers penalise source addresses that connect without
  authenticating (`PerSourcePenalties`), which host-key scans and the proof
  do by design. In normal operation LabLink stays far below the threshold;
  if a device's sshd ever refuses the LabLink host after a burst of
  re-checks, add that host to the device's `PerSourcePenaltyExemptList`.
