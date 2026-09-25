"""Repository-level quality contracts for release/documentation hygiene."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
README_ZH = ROOT / "README.zh-CN.md"
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"


def _project_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml must declare a project version"
    return match.group(1)


def test_required_repository_files_are_present():
    required = [
        "LICENSE",
        "README.md",
        "README.zh-CN.md",
        "CHANGELOG.md",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        "docs/demo.mp4",
        "docs/images/example-output.png",
    ]
    missing = [name for name in required if not (ROOT / name).exists()]
    assert missing == []


def test_readmes_link_license_release_history_and_downloads():
    for path in (README, README_ZH):
        text = path.read_text(encoding="utf-8")
        assert "README.md" in text
        assert "README.zh-CN.md" in text
        assert "CHANGELOG.md" in text
        assert "LICENSE" in text
        assert "https://github.com/zhuhroscar-tech/reboot-safety-check/releases" in text
        assert "docs/demo.mp4" in text
        assert "docs/images/example-output.png" in text


def test_changelog_tracks_current_and_recent_releases():
    text = CHANGELOG.read_text(encoding="utf-8")
    current = _project_version()
    for version in (current, "0.3.1", "0.3.0", "0.2.9", "0.2.8", "0.2.7"):
        assert f"## v{version}" in text
    assert "No runtime behavior changes" in text


def test_ci_builds_release_artifacts_and_checksums():
    ci_text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert 'tags: ["v*"]' in ci_text
    assert "python -m build" in ci_text
    assert "dist/reboot-safety-check.pyz" in ci_text
    assert "sha256sum * > SHA256SUMS.txt" in ci_text
    assert "actions/upload-artifact@v4" in ci_text


def test_package_metadata_links_changelog():
    text = PYPROJECT.read_text(encoding="utf-8")
    assert "Changelog" in text
    assert "CHANGELOG.md" in text


def test_codeql_workflow_is_enabled():
    text = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    assert "github/codeql-action/init" in text
    assert "github/codeql-action/analyze" in text
