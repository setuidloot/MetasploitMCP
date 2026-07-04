"""Tests for semantic version bump utility."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.bump_version import bump_pyproject_version, bump_semver, read_current_version


@pytest.mark.unit
def test_bump_semver_patch() -> None:
    assert bump_semver("2.0.0", "patch") == "2.0.1"


@pytest.mark.unit
def test_bump_semver_minor() -> None:
    assert bump_semver("2.0.9", "minor") == "2.1.0"


@pytest.mark.unit
def test_bump_semver_major() -> None:
    assert bump_semver("2.9.9", "major") == "3.0.0"


@pytest.mark.unit
def test_bump_semver_invalid_version_raises() -> None:
    with pytest.raises(ValueError, match="Invalid semantic version"):
        bump_semver("2.0", "patch")


@pytest.mark.unit
def test_bump_semver_invalid_part_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported bump part"):
        bump_semver("2.0.0", "build")


@pytest.mark.unit
def test_bump_pyproject_version_updates_file(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "\n".join(
            [
                "[tool.poetry]",
                'name = "metasploit-mcp"',
                'version = "2.0.0"',
            ]
        ),
        encoding="utf-8",
    )

    bumped_version = bump_pyproject_version(pyproject, "patch")

    assert bumped_version == "2.0.1"
    assert read_current_version(pyproject) == "2.0.1"
    assert 'version = "2.0.1"' in pyproject.read_text(encoding="utf-8")


@pytest.mark.unit
def test_bump_pyproject_version_missing_version_line_raises(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.poetry]\nname = "metasploit-mcp"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Could not find version line"):
        bump_pyproject_version(pyproject, "patch")
