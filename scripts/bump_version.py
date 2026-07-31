#!/usr/bin/env python3
"""Bump semantic versions in pyproject.toml."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

VERSION_LINE_RE = re.compile(r'^(version\s*=\s*")(\d+)\.(\d+)\.(\d+)(")\s*$', re.MULTILINE)


def bump_semver(version: str, part: str) -> str:
    """Return a bumped semantic version string."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(
            f"Invalid semantic version '{version}'. Expected format MAJOR.MINOR.PATCH."
        )

    major, minor, patch = (int(group) for group in match.groups())
    if part == "major":
        major += 1
        minor = 0
        patch = 0
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "patch":
        patch += 1
    else:
        raise ValueError(f"Unsupported bump part '{part}'. Use one of: major, minor, patch.")

    return f"{major}.{minor}.{patch}"


def read_current_version(pyproject_path: Path) -> str:
    """Read current version from pyproject.toml."""
    content = pyproject_path.read_text(encoding="utf-8")
    match = VERSION_LINE_RE.search(content)
    if not match:
        raise ValueError(f"Could not find version line in {pyproject_path}")
    return ".".join(match.groups()[1:4])


def bump_pyproject_version(pyproject_path: Path, part: str) -> str:
    """Bump pyproject.toml version and return the new version."""
    content = pyproject_path.read_text(encoding="utf-8")
    match = VERSION_LINE_RE.search(content)
    if not match:
        raise ValueError(f"Could not find version line in {pyproject_path}")

    current_version = ".".join(match.groups()[1:4])
    new_version = bump_semver(current_version, part)
    replacement = f"{match.group(1)}{new_version}{match.group(5)}"
    updated_content = VERSION_LINE_RE.sub(replacement, content, count=1)
    pyproject_path.write_text(updated_content, encoding="utf-8")
    return new_version


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Bump pyproject semantic version.")
    parser.add_argument(
        "--file",
        default="pyproject.toml",
        help="Path to pyproject.toml (default: pyproject.toml)",
    )
    parser.add_argument(
        "--part",
        choices=["major", "minor", "patch"],
        default="patch",
        help="Version segment to bump (default: patch)",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entry point."""
    args = parse_args()
    pyproject_path = Path(args.file).resolve()
    new_version = bump_pyproject_version(pyproject_path, args.part)
    print(new_version)


if __name__ == "__main__":
    main()
