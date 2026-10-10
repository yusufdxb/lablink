# Remote access (optional, Tailscale)

`lablink ssh <device>` can reach a device from another network: it uses the
LAN when the device answers there and falls back to the device's Tailscale
address otherwise. On both paths OpenSSH must see the **same pinned host
key**, so a different machine is never accepted, whichever network you are
on.

Tailscale is optional. Devices without a `remote:` block behave exactly as
before, and LabLink works without Tailscale installed.

## What LabLink does and does not do

| LabLink does | LabLink never does |
|---|---|
| run `tailscale status --json` (read-only) when a remote path is needed | install, start, log in or configure Tailscale |
| connect with the system OpenSSH client to the device's tailnet address | use Tailscale SSH, subnet routes, exit nodes or port forwarding |
| check TCP reachability with a bounded timeout, then the offered host keys against the pins | treat a ping, an open port, Tailscale's "online" flag or a peer name as proof of identity |
| write a per-device known_hosts file holding only pinned keys | change the daemon's pins, the user's `~/.ssh/known_hosts` or `~/.ssh/config` |
| refuse on any host-key, tailnet or node disagreement | fall back to another path after an identity disagreement |

Tailscale provides private reachability only. Authentication stays with
OpenSSH (your SSH keys, or a password typed into OpenSSH after the host key
was verified); LabLink stores no passwords, auth keys or tokens.

## How a path is chosen

```text
lablink ssh mewtwo
  daemon running?
    yes: daemon says the device is online on the LAN at this site  -> LAN (unchanged path)
         daemon says MISMATCH                                       -> refuse (exit 6), no fallback
         daemon says offline / site AWAY / no address, and remote: is configured -> Tailscale
    no (macOS, or lablinkd stopped), and remote: is configured:
         each LAN hint (expected_ips, hostnames): TCP 1.5 s, then host keys  -> LAN
         then Tailscale
  Tailscale:
    tailscale status --json (5 s): must be Running, in the configured tailnet,
    with the configured node (node_id) owning the configured address
    -> the node's Tailscale IP: TCP 5 s, then host keys -> Tailscale
```

A candidate is selected only after `ssh-keyscan` returns a key whose
fingerprint is in the device's `host_key_fingerprints`. LabLink then runs
`ssh` with `HostKeyAlias=lablink.<site>.<name>`, `StrictHostKeyChecking=yes`
and a known_hosts file holding only those keys, so OpenSSH itself proves the
server holds the private key. The pre-check gives a clear error; the ssh
options are the enforcement (an impostor that appears between the two is
still refused by OpenSSH).

`--transport lan|tailscale|auto` (on `ssh`, `exec`, `remote status`) forces a
path; `auto` is the default.

## Configuration

```yaml
devices:                       # or inside a site's devices:
  - name: mewtwo
    usernames: [yusuf]
    expected_ips: [192.168.1.20]          # optional LAN hint (a DHCP reservation)
    hostnames: [mewtwo.local]             # optional LAN hint (mDNS)
    host_key_fingerprints:                # REQUIRED for remote access
      - "SHA256:gSZcGRbEb9CPdJyzWES7dOsB2KkkmWw+RZE+NXEHJoQ"
    remote:
      tailscale:
        address: mewtwo.tail1234.ts.net   # MagicDNS name, or a Tailscale IP
        tailnet: tail1234.ts.net          # the tailnet's MagicDNS suffix
        node_id: nAbC123CNTRL             # optional, recommended: Tailscale stable node ID
```

Validation (`lablink check-config`) requires `host_key_fingerprints`,
`ssh: true` and no `via:`; the address must be a Tailscale IP or a name inside
`tailnet`; `node_id` and the address are unique within a site; any value that
looks like a Tailscale auth key (`tskey-...`) is rejected.

Several sites (for example `careslab` and `robotics-club`) may each have a
device of the same name in different tailnets. A bare name that exists at
several sites is refused as ambiguous (exit 8); use `site/name`. LabLink never
connects while the local client is in a different tailnet than the device's.

## Enrolling mewtwo (Ubuntu 22.04, stays on at home)

Every step that changes the system is yours to run. LabLink only reads.

1. Check what is there (read-only):

   ```sh
   lablink remote setup
   ```

   It prints the SSH host key fingerprints (read from `/etc/ssh/*.pub`),
   whether an SSH server listens, Tailscale's state, and a config snippet.

2. Install Tailscale from its official apt repository (commands from
   https://pkgs.tailscale.com/stable/, Ubuntu 22.04):

   ```sh
   sudo mkdir -p --mode=0755 /usr/share/keyrings
   curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
   curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list
   sudo apt-get update && sudo apt-get install tailscale
   ```

3. Log in, with no extra features:

   ```sh
   sudo tailscale up
   ```

   Do not add `--ssh`, `--advertise-routes`, `--advertise-exit-node` or
   `--accept-routes`; LabLink needs none of them. Open the printed URL and
   log in yourself.

4. In the Tailscale admin console: optionally disable key expiry for mewtwo
   (it is unattended; an expired key shows up as `tailscale_peer_expired`),
   and restrict port 22 to your own devices with a tailnet policy, for example:

   ```hujson
   {
     "hosts": { "mewtwo": "100.x.y.z" },
     "acls": [
       { "action": "accept", "src": ["you@example.com"], "proto": "tcp", "dst": ["mewtwo:22"] },
     ],
   }
   ```

   (Replace the address with mewtwo's Tailscale IP and add rules for whatever
   else your tailnet needs: rules deny by default.)

5. SSH hardening (recommended, yours to decide): confirm key login works from
   the client first, then set `PasswordAuthentication no` in an
   `/etc/ssh/sshd_config.d/*.conf` file and `sudo systemctl reload ssh`.
   Never forward port 22 on your router.

6. Run `lablink remote setup` again: the snippet now has the real `address`,
   `tailnet` and `node_id`. Compare the fingerprints with
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on mewtwo's own console.

## Setting up the MacBook (client)

The LabLink daemon is Linux-only; on macOS the `lablink` CLI works without it
for devices with a `remote:` block (`ssh`, `exec`, `remote status`).

1. Install Tailscale from https://tailscale.com/download/mac and log in from
   the app. LabLink finds the CLI on `PATH` or inside
   `/Applications/Tailscale.app/Contents/MacOS/Tailscale`; if it finds none,
   it still connects to a configured Tailscale IP or resolvable MagicDNS name,
   but cannot check the tailnet and node (it says so; the host key is still
   verified).
2. Build the CLI (needs Rust from https://rustup.rs; macOS builds are
   **not yet tested**):

   ```sh
   git clone <your LabLink repo> && cd lablink
   cargo build --release -p lablink-cli
   install -m 0755 target/release/lablink ~/.local/bin/
   ```

3. Put mewtwo's snippet from step 6 into `~/.config/lablink/config.yaml`
   under `devices:`. Then:

   ```sh
   lablink check-config
   lablink remote status mewtwo     # every path, with reasons; no login
   lablink ssh mewtwo               # LAN at home, Tailscale elsewhere
   ```

4. If mewtwo only accepts keys, install your Mac's public key first while on
   the LAN, or with a one-time password login: `lablink ssh mewtwo` then
   append your key to `~/.ssh/authorized_keys` on mewtwo.

## Errors

| `error.code` | Exit | Meaning |
|---|---|---|
| `host_key_mismatch` | 6 | an endpoint offered keys that are not pinned: SECURITY STOP, no fallback |
| `tailnet_mismatch` | 7 | the local Tailscale client is in another tailnet |
| `tailscale_peer_mismatch` | 7 | the address belongs to another node than `node_id` (or to several) |
| `tailscale_unauthenticated` | 5 | the local Tailscale is not logged in (or awaits admin approval) |
| `tailscale_stopped` / `tailscale_not_ready` | 5 | Tailscale is installed but not connected |
| `tailscale_missing` / `tailscale_error` | 5 | no CLI / unusable answer (LabLink then tries the configured address) |
| `tailscale_peer_not_found` | 5 | the device is not visible in your tailnet (not enrolled, removed, not shared, or hidden by policy) |
| `tailscale_peer_expired` | 5 | the device's Tailscale key expired |
| `dns_failure` | 5 | a configured name did not resolve |
| `timeout` / `unreachable` | 5 | no answer / no route |
| `ssh_refused` | 5 | reachable, but nothing listens on the SSH port |
| `no_ssh_host_key` | 5 | the port answered without an SSH host key |

The message lists every path tried (`lan 192.168.1.20: no answer; tailscale
mewtwo.tail1234.ts.net (100.64.0.2): ...`). Once ssh runs, authentication
failures are OpenSSH's own (exit 255; `exec --json` classifies them in
`ssh_error`).

## Limits

- Real cross-network operation (a MacBook on another network reaching mewtwo
  through a live tailnet) has **not** been tested yet; the tests use real
  OpenSSH on loopback addresses and a scripted `tailscale` CLI.
- macOS: the CLI has not been built or run on macOS yet.
- The daemon does not monitor devices over Tailscale (no background VPN
  traffic); `lablink status` shows a remote-only device as GRAY/AWAY.
- Remote access is not available for devices behind a gateway (`via:`).
- If the key pinned in the daemon (`lablink trust --replace`) changes, update
  `host_key_fingerprints` too; the remote path refuses until they agree.
- Without the Tailscale CLI the tailnet and node are not checked (the host
  key still is).
