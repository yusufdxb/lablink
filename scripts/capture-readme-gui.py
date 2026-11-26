#!/usr/bin/env python3
"""Screenshot the real GUI for the README and docs against a disposable fake
daemon (Unix socket) under Xvfb. Fixture data only: sites site-alpha and
site-beta, devices jetson-a, gpu-workstation and go2-robot on 10.9.0.0/24,
synthetic MACs and fingerprints, user `ops`. No lab device, no real scan.

The Health and Files views run through the real code paths: a fixture `ssh`
program (the resolve answer names it) prints canned doctor sections or serves
a throttled local sftp-server rooted in a throwaway directory, so both panes
list fixture files and one transfer stays in the queue while the shot is taken.

Run (after `cargo build --locked -p lablink-gui -p lablink-cli`):
  xvfb-run -a -s '-screen 0 1280x900x24' dbus-run-session -- \
    python3 scripts/capture-readme-gui.py [out_dir] [shot ...]
Shots: devices-site site-selector sites settings-appearance files-workspace
health (default: all, into docs/screenshots; health runs last because it adds
the expected-off device). Requires Pillow and
xdotool. CLICKS="name@x,y;..." adds ad-hoc shots (see capture-discovery-gui.py).
The shot `hero` alone saves the whole screen instead, for a capture inside a
desktop session where the window frame shows. The README's devices-site.png
is that capture, cropped to the window, taken in GNOME Shell 42.9 (Ubuntu
22.04) running as a nested Wayland compositor:
  Xvfb :5 -screen 0 1600x1000x24 &
  DISPLAY=:5 XDG_CURRENT_DESKTOP=ubuntu:GNOME MUTTER_DEBUG_DUMMY_MODE_SPECS=1600x1000 \
    dbus-run-session -- sh -c 'gnome-shell --nested --wayland --no-x11 \
    --wayland-display lablink-wl & sleep 8; WAYLAND_DISPLAY=lablink-wl \
    python3 scripts/capture-readme-gui.py /tmp/hero hero'
then crop hero.png to the window.
"""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
from PIL import ImageGrab

HERE = Path(__file__).resolve().parent
src = (HERE / "capture-onboarding-gui.py").read_text().split("\ndef action(")[0]
mod = type(sys)("capture")
mod.__file__ = str(HERE / "capture-onboarding-gui.py")
exec(compile(src, mod.__file__, "exec"), mod.__dict__)
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else mod.ROOT / "docs/screenshots"
WANT = sys.argv[2:] or ["devices-site", "site-selector", "sites",
                        "settings-appearance", "files-workspace", "health"]
OUT.mkdir(parents=True, exist_ok=True)

FILES_PROTOCOL_VERSION = 1
FP = {"jetson-a": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "gpu-workstation": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "go2-robot": "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}
DEVICES = [  # name, ip, mac, profile, state
    ("jetson-a", "10.9.0.11", "02:00:00:00:00:11", "jetson", "up"),
    ("gpu-workstation", "10.9.0.12", "02:00:00:00:00:12", "gpu_workstation", "up"),
    ("go2-robot", "10.9.0.13", "02:00:00:00:00:13", "generic_linux", "off"),
]

# Fixture `ssh`: sftp mode serves the throwaway remote tree, throttled so the
# queued upload is still running when the screenshot is taken; exec mode prints
# canned doctor sections for whichever checks the script asks for.
FAKE_SSH = r'''#!/usr/bin/env python3
import os, re, subprocess, sys, threading, time
args = sys.argv[1:]
if args and args[-1] == "sftp":
    root = os.environ["FIXTURE_REMOTE_ROOT"]
    os.chdir(root)
    p = subprocess.Popen(["/usr/lib/openssh/sftp-server"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, env=dict(os.environ, HOME=root))
    rate = float(os.environ.get("FIXTURE_RATE", "3e6"))
    def pump(src, dst):
        while True:
            b = src.read1(65536) if hasattr(src, "read1") else src.read(65536)
            if not b:
                break
            time.sleep(len(b) / rate)
            dst.write(b); dst.flush()
        try: dst.close()
        except Exception: pass
    threading.Thread(target=pump, args=(sys.stdin.buffer, p.stdin), daemon=True).start()
    pump(p.stdout, sys.stdout.buffer)
    sys.exit(0)
CANNED = {
    "disk": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme0n1p1 490000000 205800000 284200000 42% /",
    "jetson_gpu": "# R36 (release), REVISION: 4.3, GCID: 0, BOARD: generic, EABI: aarch64\ngpu_node=yes",
    "nvidia_gpu": "NVIDIA RTX A4000, 3, 41, 812, 16376",
    "thermal": "cpu-thermal 47000\ngpu-thermal 45500",
    "ros2": "humble setup=yes ros2=yes",
}
text = args[-1]
out = ["LC_ALL=C"]
for m in re.finditer(r"echo @@lablink:(\d+):(\w+)@@", text):
    out += [m.group(0)[5:], CANNED.get(m.group(2), ""), "@@rc:0@@"]
out.append("@@lablink:end@@")
print("\n".join(out))
'''


class ReadmeFixture(mod.GuiFixture):
    def __init__(self):
        super().__init__()
        self.show_off = False  # the expected-off device only appears for Health
        self.remote_root = self.dir / "remote-tree"; self.remote_root.mkdir()
        self.ssh = self.bin / "fixture-ssh"
        self.ssh.write_text(FAKE_SSH)
        self.ssh.chmod(0o755)
        self.env["FIXTURE_REMOTE_ROOT"] = str(self.remote_root)
        self.populate()
        mod.fixtures.write(self.dir / "config.yaml", self.config())
        self.resolve.update(ssh_binary=str(self.ssh), username="ops", identity="verified")

    def populate(self):
        """Local pane = the fixture HOME (a throwaway directory), remote = remote/."""
        h, r = self.home, self.remote_root
        for d in ("projects", "datasets", "calibration"):
            (h / d).mkdir()
        for d in ("logs", "maps", "models"):
            (r / d).mkdir(parents=True)
        (h / "notes.txt").write_text("fixture notes\n")
        (h / "calibration.yaml").write_text("camera: {fx: 600.0, fy: 600.0}\n")
        (h / "run-0412.log").write_text("fixture log\n" * 400)
        (h / "bench-capture.bag").write_bytes(b"")
        with open(h / "bench-capture.bag", "wb") as fh:
            fh.truncate(150 * 1024 * 1024)  # sparse, so it costs no disk
        (r / "config.yaml").write_text("fixture: true\n")
        (r / "deploy.sh").write_text("#!/bin/sh\necho fixture\n")
        (r / "readme.txt").write_text("fixture remote readme\n")
        (r / "logs" / "boot.log").write_text("fixture\n")

    def config(self):
        out = ["sites:"]
        out += ["  - id: site-alpha", "    name: Site Alpha", "    networks:",
                "      - {name: bench-lan, cidr: 10.9.0.0/24, active_scan: false}", "    devices:"]
        for n, ip, mac, profile, state in DEVICES:
            out += [f"      - name: {n}", f"        profile: {profile}", "        usernames: [ops]"]
            if state == "off":
                out += ["        availability: on_demand"]
        out += ["  - id: site-beta", "    name: Site Beta", "    networks:",
                "      - {name: annex-lan, cidr: 10.9.1.0/24, active_scan: false}"]
        return "\n".join(out) + "\n"

    def dev(self, n, ip, mac, profile, state):
        up = state == "up"
        caps = ["network", "ssh"] + (["gpu"] if profile != "generic_linux" else []) \
            + (["jetson"] if profile == "jetson" else [])
        return dict(
            name=n, id=f"site-alpha/{n}", site="site-alpha", site_name="Site Alpha", site_state="active",
            color="green" if up else "gray", ip=ip if up else None,
            discovery="located" if up else "searching", network="online" if up else "offline",
            ssh_port="open" if up else "unknown", ssh_auth="ok" if up else "unknown",
            identity="verified", latency_ms=2 if up else None, last_seen_ms=900 if up else 3600000,
            username="ops", interface="eth0", network_name="bench-lan", monitoring=True,
            reasons=[] if up else ["no answer yet"], services=[], profile=profile,
            capabilities=caps, label=None)

    def shown(self):
        return [d for d in DEVICES if self.show_off or d[4] == "up"]

    def sites(self):
        n = len(self.shown())
        ev = [dict(strength="strong", kind="subnet", detail="attached to 10.9.0.0/24"),
              dict(strength="medium", kind="gateway", detail="gateway 10.9.0.1 seen")]
        a = dict(id="site-alpha", name="Site Alpha", state="active", confidence="high", selected_by="auto",
                 auto_detect=True, evidence=ev, scan="active scan is off for these networks",
                 networks=[dict(name="bench-lan", cidr="10.9.0.0/24", active_scan=False, attached=True)],
                 devices=dict(total=n, green=2, yellow=0, red=0, gray=n - 2))
        b = dict(id="site-beta", name="Site Beta", state="away", confidence="none", selected_by="auto",
                 auto_detect=True, evidence=[],
                 networks=[dict(name="annex-lan", cidr="10.9.1.0/24", active_scan=False, attached=False)],
                 devices=dict(total=0, green=0, yellow=0, red=0, gray=0))
        return [a, b]

    def response(self, req):
        m = req["method"]
        if m == "ping":
            r = super().response(req)
            r["files_protocol_version"] = FILES_PROTOCOL_VERSION
            return r
        if m == "status":
            return dict(schema_version=1, daemon=dict(version=mod.VERSION, pid=os.getpid(), uptime_s=1),
                        devices=[self.dev(*d) for d in self.shown()], sites=self.sites(), site_mode=dict(mode="auto"))
        if m == "sites":
            return dict(schema_version=1, mode=dict(mode="auto"), sites=self.sites(),
                        signals=dict(attached=["eth0 10.9.0.2/24"], gateways=["10.9.0.1"], ssids=[]))
        if m in ("resolve", "resolve_files"):
            n = req["params"]["device"].split("/")[-1]
            d = next((x for x in DEVICES if x[0] == n), DEVICES[0])
            if d[4] == "off":
                self.calls[-1]["note"] = "unreachable"
                raise Unreachable()
            return dict(self.resolve, name=n, id=f"site-alpha/{n}", ip=d[1], ssh_host=n,
                        host_key_alias=f"lablink.site-alpha.{n}", site_name="Site Alpha")
        if m == "discovered":
            return dict(discovered=[])
        if m == "history":
            return dict(events=[])
        return super().response(req)


class Unreachable(Exception):
    pass


def serve(self):
    while not self.stop:
        try:
            conn, _ = self.listener.accept()
        except mod.fixtures.socket.timeout:
            continue
        except OSError:
            break
        with conn:
            f = conn.makefile("rwb")
            try:
                req = json.loads(f.readline())
                self.calls.append(req)
                try:
                    body = dict(ok=True, result=self.response(req))
                except Unreachable:
                    body = dict(ok=False, error=dict(code="unreachable", message="no answer (fixture)"))
                f.write((json.dumps(body) + "\n").encode())
                f.flush()
            except (BrokenPipeError, OSError):
                pass


ReadmeFixture.serve = serve


def x(*args, wait=0.3):
    subprocess.run(["xdotool", *map(str, args)], check=True)
    time.sleep(wait)


def click(px, py, wait=0.4):
    x("mousemove", px, py, "click", 1, wait=wait)


def shot(name, wait=1.0, crop_h=None):
    time.sleep(wait)
    g = dict(kv.split("=", 1) for kv in subprocess.check_output(
        ["xdotool", "getwindowgeometry", "--shell", w], text=True).split())
    X, Y, W, H = (int(g[k]) for k in ("X", "Y", "WIDTH", "HEIGHT"))
    ImageGrab.grab(bbox=(X, Y, X + W, Y + (crop_h or H)), xdisplay=os.environ["DISPLAY"]).save(OUT / f"{name}.png")
    print(OUT / f"{name}.png", flush=True)


def esc():
    x("key", "Escape")


# Sidebar and widget coordinates of the ~1120x850 window at the origin.
NAV = dict(devices=(60, 104), discovered=(60, 150))
POS = dict(
    nav_files=(60, 196), nav_health=(60, 242), nav_sites=(60, 288), nav_settings=(60, 334),
    selector=(291, 17), run_all=(438, 70), open_files=(216, 307),
)
POS.update(json.loads(os.environ.get("POS", "{}")))

f = ReadmeFixture()
if WANT == ["hero"]:
    # A desktop-session capture with the window frame: run inside a desktop
    # (for example GNOME Shell nested in Xvfb, WAYLAND_DISPLAY set). No window
    # lookup (Wayland has none for xdotool): Escape closes the overview, then
    # the whole screen of DISPLAY is saved as hero.png.
    try:
        gui = subprocess.Popen([str(mod.ROOT / "target/debug/lablink-gui")], env=f.env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(10)
        subprocess.run(["xdotool", "key", "Escape"], check=False)
        time.sleep(3)
        ImageGrab.grab(xdisplay=os.environ["DISPLAY"]).save(OUT / "hero.png")
        print(OUT / "hero.png", flush=True)
    finally:
        gui.terminate()
        gui.wait(timeout=5)
        f.close()
    sys.exit(0)
try:
    gui = subprocess.Popen([str(mod.ROOT / "target/debug/lablink-gui")], env=f.env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mod.fixtures.wait_for(lambda: subprocess.run(["xdotool", "search", "--name", "^LabLink$"],
                                                 stdout=subprocess.DEVNULL).returncode == 0)
    w = subprocess.check_output(["xdotool", "search", "--name", "^LabLink$"], text=True).splitlines()[0]
    x("windowmove", w, 0, 0)
    x("windowfocus", w)
    time.sleep(3)
    for step in os.environ.get("CLICKS", "").split(";"):
        if not step.strip():
            continue
        name, xy = step.split("@")
        if xy == "wait":
            time.sleep(float(name))
        elif xy == "type":
            x("type", "--clearmodifiers", name)
        elif xy == "key":
            x("key", name)
        else:
            click(*map(int, xy.split(",")))
            shot(name)
    if "devices-site" in WANT:
        click(*NAV["devices"])
        shot("devices-site")
    if "site-selector" in WANT:
        click(*POS["selector"])
        shot("site-selector")
        esc()
    if "sites" in WANT:
        click(*POS["nav_sites"])
        shot("sites")
    if "settings-appearance" in WANT:
        click(*POS["nav_settings"])
        # Cropped above the line that prints the (throwaway) config path.
        shot("settings-appearance", crop_h=520)
    if "files-workspace" in WANT:
        click(*NAV["devices"])
        click(*POS["open_files"])
        time.sleep(4)
        # Drag the large file from the local pane onto the remote pane: an
        # upload that the throttled fixture sftp keeps running during the shot.
        x("mousemove", 230, 620)
        x("mousedown", 1)
        for px, py in ((300, 610), (500, 580), (700, 540), (880, 500)):
            x("mousemove", px, py, wait=0.15)
        x("mouseup", 1)
        time.sleep(0.5)
        x("mousemove", 880, 760)  # park the pointer on empty space
        shot("files-workspace", wait=6.0)
    if "health" in WANT:
        f.show_off = True  # the next 2 s status poll adds go2-robot (on_demand, unreachable)
        time.sleep(3)
        click(*POS["nav_health"])
        click(*POS["run_all"])
        try:
            mod.fixtures.wait_for(lambda: sum(c["method"] == "resolve" for c in f.calls) >= 2)
        except AssertionError:
            shot("debug-health"); print([(c["method"], c.get("params")) for c in f.calls][-12:], flush=True); raise
        time.sleep(3)
        for row_y in (265, 225, 185):  # expand bottom-up so rows do not shift
            click(161, row_y, wait=0.3)
        shot("health")
    print("methods:", sorted({c["method"] for c in f.calls}), flush=True)
finally:
    if "gui" in locals():
        gui.terminate()
        gui.wait(timeout=5)
    f.close()
