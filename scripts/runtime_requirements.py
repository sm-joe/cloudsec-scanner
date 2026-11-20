"""Turn an installed environment inventory into exact audit requirements."""
import json
import re
import sys
from pathlib import Path


def requirements(document):
    if not isinstance(document, list) or not document:
        raise ValueError("missing installed package inventory")
    selected = {}
    for entry in document:
        if not isinstance(entry, dict):
            raise ValueError("invalid package record")
        name, version = entry.get("name"), entry.get("version")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError("invalid package name")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_-]*", version):
            raise ValueError("invalid installed version")
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized == "cloudsec-scanner":
            continue
        if normalized in selected:
            raise ValueError("duplicate installed distribution")
        selected[normalized] = version
    if not selected:
        raise ValueError("no runtime dependency inventory")
    return [f"{name}=={selected[name]}" for name in sorted(selected)]


if __name__ == "__main__":
    print("\n".join(requirements(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))))
