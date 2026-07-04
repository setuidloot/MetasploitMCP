#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM (``sbom.json``) from ``poetry.lock``.

Offline and deterministic: reads the locked dependency graph and emits a
Software Bill of Materials with pinned versions, PyPI PURLs, and dependency
scope (``required`` for runtime / ``optional`` for dev-only). Regenerate after
any dependency change with::

    poetry run python scripts/generate_sbom.py

The project version is read from ``pyproject.toml`` so the SBOM's root component
stays in sync with releases.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:  # stdlib on 3.11+, backport otherwise
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "poetry.lock"
PYPROJECT_PATH = ROOT / "pyproject.toml"
OUTPUT_PATH = ROOT / "sbom.json"


def _load_toml(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _bom_ref(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower()}@{version}"


def build_sbom() -> dict:
    project = _load_toml(PYPROJECT_PATH)["tool"]["poetry"]
    lock = _load_toml(LOCK_PATH)

    root_name = project["name"]
    root_version = project["version"]

    components = []
    dependencies = []
    root_deps = []

    for pkg in sorted(lock.get("package", []), key=lambda p: p["name"].lower()):
        name = pkg["name"]
        version = pkg["version"]
        groups = pkg.get("groups", ["main"])
        # Runtime deps are "required"; dev/test-only deps are "optional".
        scope = "required" if "main" in groups else "optional"
        purl = _bom_ref(name, version)

        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "scope": scope,
            "properties": [
                {"name": "poetry:groups", "value": ",".join(groups)},
            ],
        }
        description = pkg.get("description")
        if description:
            component["description"] = description
        components.append(component)
        root_deps.append(purl)

    dependencies.append(
        {"ref": _bom_ref(root_name, root_version), "dependsOn": sorted(root_deps)}
    )

    # Deterministic serial number derived from the locked content so re-running
    # on an unchanged lock yields an identical SBOM (no wall-clock timestamp).
    digest = hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
    serial = f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": _bom_ref(root_name, root_version),
                "name": root_name,
                "version": root_version,
                "description": project.get("description", ""),
                "purl": _bom_ref(root_name, root_version),
                "licenses": [{"license": {"id": project.get("license", "Apache-2.0")}}],
            },
            "tools": [{"name": "generate_sbom.py", "vendor": "MetasploitMCP"}],
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    sbom = build_sbom()
    OUTPUT_PATH.write_text(json.dumps(sbom, indent=2) + "\n")
    print(
        f"Wrote {OUTPUT_PATH.relative_to(ROOT)} "
        f"({len(sbom['components'])} components) from poetry.lock"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
