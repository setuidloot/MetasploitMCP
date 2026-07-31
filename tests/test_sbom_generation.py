"""Tests for the CycloneDX SBOM generator and its ``--check`` freshness mode."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.generate_sbom import OUTPUT_PATH, build_sbom, main, serialize


@pytest.mark.unit
def test_build_sbom_is_deterministic() -> None:
    """Two consecutive builds from the same lock produce identical output."""
    assert serialize(build_sbom()) == serialize(build_sbom())


@pytest.mark.unit
def test_build_sbom_has_expected_shape() -> None:
    sbom = build_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "metasploit-mcp"
    assert sbom["components"], "expected at least one component from poetry.lock"


@pytest.mark.unit
def test_committed_sbom_is_up_to_date() -> None:
    """The committed sbom.json must match a fresh generation (guards against drift)."""
    committed = OUTPUT_PATH.read_text()
    assert committed == serialize(build_sbom()), "sbom.json is stale; run `make sbom`"


@pytest.mark.unit
def test_check_mode_passes_when_in_sync() -> None:
    assert main(["--check"]) == 0


@pytest.mark.unit
def test_check_mode_fails_when_stale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--check returns non-zero when the on-disk SBOM differs from a fresh build."""
    stale = tmp_path / "sbom.json"
    stale.write_text('{"bomFormat": "CycloneDX", "components": []}\n')
    monkeypatch.setattr("scripts.generate_sbom.OUTPUT_PATH", stale)
    assert main(["--check"]) == 1


@pytest.mark.unit
def test_generate_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "sbom.json"
    monkeypatch.setattr("scripts.generate_sbom.OUTPUT_PATH", out)
    assert main([]) == 0
    assert out.exists()
    assert out.read_text() == serialize(build_sbom())
