#!/usr/bin/env python3
"""Screenshot the real GUI's header, Discovered tab and scan confirmation
against a disposable fake daemon. Fixture data only: no lab device, no real
scan (the fixture answers the discover request itself).
Run: xvfb-run -a -s '-screen 0 1280x900x24' dbus-run-session -- \
  python3 scripts/capture-discovery-gui.py [out_dir]
"""
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
sys.dont_write_bytecode = True
from PIL import ImageGrab

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("capture", HERE / "capture-onboarding-gui.py")
src = (HERE / "capture-onboarding-gui.py").read_text().split("\ndef action(")[0]
mod = type(sys)("capture")
mod.__file__ = str(HERE / "capture-onboarding-gui.py")
exec(compile(src, mod.__file__, "exec"), mod.__dict__)
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else mod.ROOT / "docs/screenshots"
OUT.mkdir(parents=True, exist_ok=True)


class DiscoveryFixture(mod.GuiFixture):
    def sites(self):
        s = super().sites()
        s[0]["networks"] = [dict(name="Bench LAN", cidr="192.168.77.0/24", active_scan=False, attached=True)]
        return s

    def hosts(self):
        base = self.host_record()
        quiet = dict(base, ip="192.168.77.23", hostname=None, mac="48:b0:2d:00:00:23", ssh_port="filtered",
                     sources=["neighbor table"], note=None, interface="eth0", network_name="Bench LAN")
        gone = dict(base, ip="192.168.77.40", hostname="old-bench-pc", mac=None, ssh_port="unknown",
                    sources=["neighbor table"], note=None, last_seen_ms_ago=40 * 60 * 1000, interface="eth0",
                    network_name="Bench LAN")
        return [base, quiet, gone]

    def response(self, req):
        if req["method"] == "discovered":
            return dict(discovered=self.hosts())
        if req["method"] == "discover":
            cidr = req.get("params", {}).get("scan_cidr")
            stages = [dict(stage="neighbor_table", result="ok", detail="3 neighbors", duration_ms=4)]
            if cidr:
                time.sleep(3)
                stages.append(dict(stage="active_scan:one_time", result="ok",
                                   detail=f"{cidr}: 254 addresses probed, 3 responsive", duration_ms=3000))
            else:
                stages.append(dict(stage="active_scan", result="skipped",
                                   detail="no network has active_scan: true", duration_ms=0))
            return dict(schema_version=1, stages=stages, probed_hosts=254 if cidr else 0,
                        responsive_hosts=3, devices=[], discovered=self.hosts())
        return super().response(req)


def x(*args):
    subprocess.run(["xdotool", *map(str, args)], check=True)
    time.sleep(0.3)


def shot(name):
    time.sleep(1.0)
    ImageGrab.grab(xdisplay=os.environ["DISPLAY"]).save(OUT / name)
    print(OUT / name, flush=True)


f = mod.GuiFixture() if os.environ.get("FIXTURE") == "onboarding" else DiscoveryFixture()
print("username:", f.plan["username"], "key:", f.key, flush=True)
try:
    gui = subprocess.Popen([str(mod.ROOT / "target/debug/lablink-gui")], env=f.env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    mod.fixtures.wait_for(lambda: subprocess.run(["xdotool", "search", "--name", "^LabLink$"],
                                                 stdout=subprocess.DEVNULL).returncode == 0)
    w = subprocess.check_output(["xdotool", "search", "--name", "^LabLink$"], text=True).splitlines()[0]
    x("windowmove", w, 0, 0)
    x("windowfocus", w)
    time.sleep(2)
    shot("header.png")
    for step in os.environ.get("CLICKS", "").split(";"):
        if not step.strip():
            continue
        name, xy = step.split("@")
        if xy == "wait":
            time.sleep(float(name))
            continue
        if xy == "type":
            x("type", "--clearmodifiers", name)
            continue
        cx, cy = xy.split(",")
        x("mousemove", cx, cy, "click", 1)
        shot(f"{name}.png")
    print("methods:", sorted({c["method"] for c in f.calls}),
          "scan requests:", [c.get("params", {}).get("scan_cidr") for c in f.calls if c["method"] == "discover"], flush=True)
finally:
    if "gui" in locals():
        gui.terminate()
        gui.wait(timeout=5)
    f.close()
