#!/usr/bin/env python3
"""Check CHANGELOG.md against docs/COMPATIBILITY.md.

Before 1.0, a release whose CHANGELOG section has a "### Behaviour changes"
heading must bump the minor version (0.4.x -> 0.5.0), never only the patch.
Releases that broke the rule before it existed are listed in
KNOWN_EXCEPTIONS and stay listed; never add a new one.

Usage: check-compat.py [CHANGELOG.md] | --self-test
"""
import re
import sys
from pathlib import Path

KNOWN_EXCEPTIONS = {
    # Shipped `ssh --` placement and `exec` stdin changes in a patch release,
    # before this policy existed.
    "0.4.4",
}

HEADING = re.compile(r"^## \[(\d+)\.(\d+)\.(\d+)(?:[-+~][^\]]*)?\]", re.M)


def releases(text):
    """[(version tuple, version string, section text)], newest first."""
    marks = list(HEADING.finditer(text))
    out = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[m.end():end]
        body = body.split("\n## [", 1)[0]
        version = tuple(int(g) for g in m.groups())
        out.append((version, ".".join(m.groups()), body))
    return out


def problems(text, exceptions=KNOWN_EXCEPTIONS):
    found = []
    rel = releases(text)
    for (ver, name, body), older in zip(rel, rel[1:] + [None]):
        if not re.search(r"^### Behaviour changes\s*$", body, re.M):
            continue
        if name in exceptions:
            continue
        major, minor, _ = ver
        if older is None:
            continue
        o_major, o_minor, _ = older[0]
        breaking_bump = major > o_major if major >= 1 else (major > o_major or minor > o_minor)
        if not breaking_bump:
            found.append(
                f"{name} has a 'Behaviour changes' section but only bumps the patch "
                f"version after {older[1]}; see docs/COMPATIBILITY.md (bump the minor "
                f"version before 1.0, the major version after)."
            )
    return found


def self_test():
    ok = "## [0.5.0]\n### Behaviour changes\n- x\n## [0.4.9]\n### Fixed\n"
    assert problems(ok) == [], problems(ok)
    bad = "## [0.4.10] - d\n### Behaviour changes\n- x\n## [0.4.9]\n### Fixed\n"
    assert len(problems(bad)) == 1, problems(bad)
    assert problems(bad, {"0.4.10"}) == []
    post1 = "## [1.1.0]\n### Behaviour changes\n- x\n## [1.0.3]\n"
    assert len(problems(post1)) == 1
    assert problems("## [2.0.0]\n### Behaviour changes\n## [1.9.0]\n") == []
    assert problems("## [Unreleased]\n### Behaviour changes\n## [0.4.4]\n") == []
    print("check-compat self-test: ok")


def main(argv):
    if argv[1:] == ["--self-test"]:
        self_test()
        return 0
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    found = problems(path.read_text())
    for p in found:
        print(f"check-compat: {p}", file=sys.stderr)
    if not found:
        print(f"check-compat: {path.name}: ok ({len(releases(path.read_text()))} releases)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
