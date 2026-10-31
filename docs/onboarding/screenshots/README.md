# Actual GUI screenshots

Captured from the development binary under Xvfb. The IPC/site data are disposable fixtures; authentication uses a temporary localhost OpenSSH server and key. These are rendered GUI screenshots, not design mockups. No production device or real password appears.

| Screen | Image |
| --- | --- |
| Discovered device | [01-discovered.png](01-discovered.png) |
| Site and SSH username | [02-details.png](02-details.png) |
| Independent identity confirmation | [03-identity.png](03-identity.png) |
| Authentication and generation consent | [04-authentication.png](04-authentication.png) |
| Successful key test, friendly name prompt | [05-name.png](05-name.png) |
| Connected and stable site-qualified reference | [06-connected.png](06-connected.png) |
| Verified/online device at Home; Lab away | [07-device.png](07-device.png) |

Reproduce after building the CLI/GUI:

```bash
xvfb-run -a -s '-screen 0 1280x900x24' dbus-run-session -- python3 scripts/capture-onboarding-gui.py
```

The script only types usernames, key paths and friendly names into GUI widgets. It does not type into, read from, or record the authentication terminal. It cleans up its disposable server, agent and GUI on completion.
