#!/usr/bin/env python3
"""Check installer documentation and the selected official GitHub assets.

Default: download and verify the real .deb and tarball. --offline checks only
repository consistency; --published additionally verifies the public script URL.
No package is executed or installed.
"""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_URL = "https://raw.githubusercontent.com/yusufdxb/lablink/main/scripts/install-linux.sh"
INSTALL_COMMAND = f'bash -c \'installer=$(curl -fsSL {SCRIPT_URL}) && bash <<< "$installer"\''
RELEASE_ROOT = "https://github.com/yusufdxb/lablink/releases/download"


def require(condition, explanation):
    if not condition:
        raise ValueError(explanation)


def target_version(source):
    matches = re.findall(r"^\s*readonly RELEASE_VERSION='([0-9]+\.[0-9]+\.[0-9]+)'$", source, re.M)
    require(len(matches) == 1, "Installer must define exactly one RELEASE_VERSION")
    return matches[0]


def check_docs(version):
    source = (ROOT / "scripts/install-linux.sh").read_text()
    require('readonly RELEASE_URL="' + RELEASE_ROOT + '/v${RELEASE_VERSION}"' in source,
            "Installer release URL must point to the official selected tag")
    require('readonly PACKAGE="lablink_${RELEASE_VERSION}_amd64.deb"' in source,
            "Installer package name differs from the release workflow")
    require("/releases/latest" not in source, "Do not rely on latest for prereleases")
    names = {f"lablink_{version}_amd64.deb", f"lablink-{version}-x86_64-linux.tar.gz"}
    for path in ("README.md", "docs/INSTALL.md", "docs/RELEASING.md"):
        text = (ROOT / path).read_text()
        if path != "docs/RELEASING.md":
            require(f"```bash\n{INSTALL_COMMAND}\n```" in text,
                    f"{path} must contain the exact public command in a bash code block")
            require("lablink init" in text, f"{path} must explain onboarding")
            for release in ("20.04", "22.04", "24.04"):
                require(release in text, f"{path} omits Ubuntu {release} support")
            require("x86_64" in text and "ARM64" in text, f"{path} must describe architecture support")
        mentioned = re.findall(r"lablink_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb|lablink-[0-9]+\.[0-9]+\.[0-9]+-x86_64-linux\.tar\.gz", text)
        require(set(mentioned) <= names, f"{path} has outdated release filenames: {set(mentioned) - names}")
        for url in re.findall(r"https://github\.com/yusufdxb/lablink/releases/download/[^\s`\)]+", text):
            require(url == f"{RELEASE_ROOT}/v{version}" or url.startswith(f"{RELEASE_ROOT}/v{version}/"), f"{path} has an outdated release URL: {url}")
        references = re.findall(
            r"(?:releases/tag/v|--source-ref refs/tags/v)([0-9]+\.[0-9]+\.[0-9]+)", text)
        require(all(reference == version for reference in references),
                f"{path} has an outdated release tag or provenance reference")
    readme = (ROOT / "README.md").read_text()
    require("## Quick Install" in readme[:1500], "README Quick Install must appear near the beginning")
    sections = re.findall(r"^## (.+)$", readme, re.M)
    require(sections and sections[0] == "Quick Install", "README Quick Install must precede detailed sections")
    require(readme.index(INSTALL_COMMAND) < readme.index("```bash\nlablink init\n```"),
            "README must show installation before onboarding")
    install_doc = (ROOT / "docs/INSTALL.md").read_text()
    for name in names:
        require(name in install_doc, f"docs/INSTALL.md must document the real {name} asset")
    print(f"PASS documentation and installer target v{version}")


def download(url, destination):
    subprocess.run([
        "curl", "--disable", "--fail", "--show-error", "--silent", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "20",
        "--max-time", "300", "--retry", "2", "--output", str(destination), url,
    ], check=True)


def selected_checksum(manifest, name):
    matches = []
    for line in manifest.splitlines():
        fields = line.split()
        if len(fields) >= 2 and re.sub(r"^\./", "", fields[1].lstrip("*")) == name:
            require(len(fields) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]),
                    f"Malformed SHA256SUMS entry for {name}")
            matches.append(fields[0].lower())
    require(len(matches) == 1, f"SHA256SUMS must contain exactly one checksum for {name}")
    return matches[0]


def check_assets(version, published):
    with tempfile.TemporaryDirectory(prefix="lablink-release-check-") as directory:
        directory = Path(directory)
        base = f"{RELEASE_ROOT}/v{version}"
        download(f"{base}/SHA256SUMS", directory / "SHA256SUMS")
        manifest = (directory / "SHA256SUMS").read_text()
        for name in (f"lablink_{version}_amd64.deb", f"lablink-{version}-x86_64-linux.tar.gz"):
            expected = selected_checksum(manifest, name)
            destination = directory / name
            download(f"{base}/{name}", destination)
            actual = hashlib.sha256(destination.read_bytes()).hexdigest()
            require(actual == expected, f"Checksum mismatch for {name}")
            print(f"PASS official release download and SHA-256: {name}")
        if published:
            destination = directory / "install-linux.sh"
            download(SCRIPT_URL, destination)
            source = destination.read_text()
            require(target_version(source) == version, "Published installer target differs from this checkout")
            require(source == (ROOT / "scripts/install-linux.sh").read_text(),
                    "Published installer differs from this checkout")
            subprocess.run(["bash", "-n", str(destination)], check=True)
            print("PASS published installer URL and content (execution is tested separately in Ubuntu containers)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="check repository consistency only")
    parser.add_argument("--published", action="store_true", help="also check the public main installer URL")
    args = parser.parse_args()
    require(not (args.offline and args.published), "--published requires network access; omit --offline")
    version = target_version((ROOT / "scripts/install-linux.sh").read_text())
    check_docs(version)
    if not args.offline:
        check_assets(version, args.published)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Installer release check failed: {error}", file=sys.stderr)
        sys.exit(1)
