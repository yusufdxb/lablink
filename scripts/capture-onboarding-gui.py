#!/usr/bin/env python3
"""Exercise the actual development GUI against disposable localhost fixtures.
No production daemon/config, lab device, password or terminal keystroke capture.
Run: xvfb-run -a -s '-screen 0 1280x900x24' dbus-run-session -- \
  python3 scripts/capture-onboarding-gui.py
Requires Pillow and xdotool. Saves actual screenshots under docs/onboarding.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
import time
from PIL import ImageGrab

spec = importlib.util.spec_from_file_location("terminal_fixtures", Path(__file__).with_name("test-onboarding-terminal.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/onboarding/screenshots"
OUT.mkdir(parents=True, exist_ok=True)


class GuiFixture(fixtures.Fixture):
    def __init__(self):
        self.device = None
        self.confirmed = False
        super().__init__()
        authorized = self.real_server()
        with authorized.open("a") as f:
            f.write(self.key.with_suffix(".pub").read_text())
        self.env.update(LABLINK_CONFIG=str(self.dir / "config.yaml"),
                        LABLINK_STATE_DIR=str(self.dir / "state"))
        fixtures.write(self.dir / "config.yaml", "sites:\n  - id: carebear\n    name: Carebear\n  - id: cares-lab\n    name: CARES Lab\n")

    def sites(self):
        return [dict(id=i, name=n, state=s, confidence="high" if s == "active" else "none",
                     selected_by="auto", auto_detect=True, evidence=[], networks=[], devices=dict(total=0, green=0, yellow=0, red=0, gray=0))
                for i, n, s in [("carebear", "Carebear", "active"), ("cares-lab", "CARES Lab", "away")]]

    def host_record(self):
        return dict(ip="127.0.0.1", site="carebear", mac=None, hostname="Local test fixture", network_name="Disposable localhost",
                    interface="lo", sources=["test fixture"], ssh_port="open", fingerprints=[],
                    matched_device=self.device["id"] if self.device else None, note="No lab hardware", first_seen_ms_ago=0, last_seen_ms_ago=0)

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.listener.accept()
            except fixtures.socket.timeout:
                continue
            except OSError:
                break
            with conn:
                f = conn.makefile("rwb")
                try:
                    req = json.loads(f.readline())
                    self.calls.append(req)
                    result = self.response(req)
                    f.write((json.dumps(dict(ok=True, result=result)) + "\n").encode())
                    f.flush()
                except (BrokenPipeError, OSError):
                    pass

    def response(self, req):
        method, p = req["method"], req.get("params", {})
        if method == "ping":
            return dict(protocol_version=1, version="0.3.0 · local test fixture", pid=os.getpid(), uptime_s=1)
        if method == "status":
            return dict(schema_version=1, daemon=dict(version="0.3.0", pid=os.getpid(), uptime_s=1),
                        devices=[self.device] if self.device else [], sites=self.sites(), site_mode=dict(mode="auto"))
        if method == "sites":
            return dict(schema_version=1, mode=dict(mode="auto"), sites=self.sites(), signals=dict(attached=[], gateways=[], ssids=[]))
        if method == "discovered":
            return dict(discovered=[self.host_record()])
        if method == "adopt":
            self.device = dict(name=p["name"], id=f"carebear/{p['name']}", site="carebear", site_name="Carebear", site_state="active",
                               color="yellow", ip="127.0.0.1", discovery="located", network="online", ssh_port="open", ssh_auth="unknown",
                               identity="unverified", latency_ms=1, last_seen_ms=1, username=p["username"], interface="lo", network_name="Fixture",
                               monitoring=True, reasons=[], services=[])
            self.resolve.update(id=self.device["id"], name=p["name"], ssh_host=p["name"], username=p["username"])
            return self.device
        if method == "trust":
            self.confirmed = bool(p.get("confirm")) or self.confirmed
            k = dict(key_type="ssh-ed25519", fingerprint=self.plan["fingerprints"][0], source="test fixture")
            return dict(schema_version=1, device=p["device"], ip="127.0.0.1", action="pinned" if p.get("confirm") else "preview",
                        scanned=[k], pinned_before=[], pinned_now=[k] if self.confirmed else [])
        if method == "resolve":
            return self.resolve
        if method == "set":
            c = p["changes"]
            if self.device:
                if c.get("username"):
                    self.device["username"] = c["username"]
                if c.get("identity_file"):
                    self.device.update(identity="verified", ssh_auth="ok", color="green")
                if c.get("label"):
                    self.device["label"] = c["label"]
            return self.device or {}
        return {}


def action(*args):
    subprocess.run(["xdotool", *map(str, args)], check=True)
    time.sleep(0.25)


def click(x, y):
    action("mousemove", x, y, "click", 1)


def shot(name):
    time.sleep(0.8)
    ImageGrab.grab(xdisplay=os.environ["DISPLAY"]).save(OUT / name)
    print(OUT / name, flush=True)


f = GuiFixture()
try:
    # Exercise the user's default entry point as well as the GUI workflow.
    gui = subprocess.Popen([str(ROOT / "target/debug/lablink")], env=f.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    fixtures.wait_for(lambda: subprocess.run(["xdotool", "search", "--name", "^LabLink$"], stdout=subprocess.DEVNULL).returncode == 0)
    window = subprocess.check_output(["xdotool", "search", "--name", "^LabLink$"], text=True).splitlines()[0]
    action("windowmove", window, 40, 40)
    action("windowfocus", window)
    time.sleep(2)
    click(459, 55)  # Discovered tab
    shot("01-discovered.png")
    # Coordinates below are maintained against the actual 900x700 GUI.
    click(670, 148)  # Select the discovered localhost fixture
    shot("02-details.png")
    click(260, 377)
    action("type", "--clearmodifiers", f.plan["username"])
    click(189, 416)
    fixtures.wait_for(lambda: any(r["method"] == "trust" for r in f.calls))
    shot("03-identity.png")
    # The fingerprint comes independently from the fixture's local
    # ssh-keygen result, rather than the daemon's displayed claim.
    click(165, 405)
    click(250, 426)
    fixtures.wait_for(lambda: f.confirmed)
    shot("04-authentication.png")
    click(165, 330)  # Existing key
    click(300, 351)  # Advanced key chooser
    click(260, 390)
    action("type", "--clearmodifiers", str(f.key))
    click(240, 433)
    fixtures.wait_for(lambda: f.device and f.device["identity"] == "verified", seconds=60)
    time.sleep(1)
    action("windowfocus", window)
    shot("05-name.png")
    click(260, 315)
    action("type", "--clearmodifiers", "Home test workstation")
    click(193, 337)
    fixtures.wait_for(lambda: f.device.get("label") == "Home test workstation")
    shot("06-connected.png")
    click(184, 317)  # Done
    click(380, 54)   # Devices tab
    shot("07-device.png")
    assert f.device["site"] == "carebear"
    assert f.device["identity"] == "verified"
    assert f.device["ssh_auth"] == "ok"
    assert all(r.get("params", {}).get("device", "carebear/").startswith("carebear/")
               for r in f.calls if r["method"] in ("trust", "resolve", "set"))
    print("GUI flow passed; screenshots use isolated fixture data.", flush=True)

finally:
    if 'gui' in locals():
        gui.terminate()
        gui.wait(timeout=5)
    f.close()
